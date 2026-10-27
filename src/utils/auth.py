"""网易云登录 / Cookie 获取

设计要点（修复 refresh_cookie 拿不到 cookie 的问题）：
1. 不再依赖 pyncm 的 `LoginViaCellphone`。它内部用 WriteLoginInfo 把业务错误
   塞进 session 后返回 `{"code": 200}`，真实错误码（密码错误 / 风控验证）会被吞掉，
   上层只能看到"未获取到 MUSIC_U"，无法定位。
2. 直接调用加密装饰器拿原始 JSON，错误码 / 原始 message 全部透出。
3. 双通道：eapi 失败自动回退 weapi。
4. 网络错误（SSL EOF / 超时 / 连接重置）单独重试，机房 IP 到网易的 TLS 抖动很常见。
5. cookie 用遍历 cookie jar 的方式取，避免 requests 的 CookieConflictError
   （同名 cookie 多 path 时 `jar.get()` 会直接抛异常）。
6. 登录成功后必须再打一次 /api/nuser/account/get 校验，确认 MUSIC_U 是真登录态
   而不是风控下发的空壳 cookie，避免把无效 cookie 写进 Secrets。
"""

import hashlib
import os
import random
import re
import time
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

from ..utils.logger import Logger

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

try:
    from pyncm import CreateNewSession, SetCurrentSession
    from pyncm.apis import EapiCryptoRequest, WeapiCryptoRequest

    PYNCM_AVAILABLE = True
except ImportError:  # pragma: no cover
    PYNCM_AVAILABLE = False


DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
ACCOUNT_URL = "https://music.163.com/api/nuser/account/get"
PARTNER_TASK_URL = "https://interface.music.163.com/api/music/partner/daily/task/get"

# GitHub Actions runner 在海外机房，网易的风控会按 IP 判定：
# - 460 "Cheating"（pyncm 官方文档就写明海外用户需要加 X-Real-IP）
# - 8821 需要行为验证（滑块/点选，CI 里无法完成）
# 带一个国内 IP 头是最常用的绕过方式；不合规时可用 NETEASE_REAL_IP=off 关掉。
DEFAULT_REAL_IP = "118.88.88.88"

# 业务错误码 -> 人话。网易云登录失败时码很杂，这里只覆盖常见几种。
LOGIN_CODE_HINTS = {
    501: "账号不存在",
    502: "账号或密码错误。如果你用的是 secrets.NETEASE_MD5_PASSWORD，确认填的是 32 位 md5（不是明文）",
    503: "请求过于频繁，已被限流，稍后重试",
    509: "账号被限制登录",
    460: "IP 被判定为异常（海外/机房 IP），尝试带上 X-Real-IP 头或换国内网络",
    8815: "需要行为验证，通常由异地 IP / 机房 IP 触发",
    8816: "账号存在风险，网易要求二次验证",
    8821: "需要行为验证码（滑块/点选）。CI 里无法完成：请确认已启用 X-Real-IP，仍失败就手动更新 cookie 或改用 self-hosted runner",
    8822: "需要手机短信验证码",
}

# 可重试码：限流 / 服务端错误 / 未知网络层失败
RETRYABLE_CODES = {None, 0, 500, 502, 503, 504, 400}


class LoginError(Exception):
    """带网易业务码的登录异常"""

    def __init__(self, message: str, code: Any = None, channel: str = ""):
        self.code = code
        self.channel = channel
        hint = LOGIN_CODE_HINTS.get(code)
        super().__init__(f"{message}" + (f" | 提示: {hint}" if hint else ""))

    @property
    def retryable(self) -> bool:
        return self.code in RETRYABLE_CODES


class LoginResult(NamedTuple):
    ok: bool
    cookies: Optional[Dict[str, str]]
    profile: Optional[Dict[str, Any]]
    reason: str
    channel: str = ""


class AuthService:
    def __init__(
        self,
        logger: Logger,
        timeout: int = 20,
        retries: int = 3,
        real_ip: Optional[str] = None,
        device_id: Optional[str] = None,
    ):
        self.logger = logger
        self.timeout = timeout
        self.retries = max(1, retries)

        # 抗风控头：默认启用（GitHub Actions 是海外机房 IP）
        env_real_ip = os.environ.get("NETEASE_REAL_IP", "").strip()
        if real_ip is not None:
            self.real_ip = real_ip.strip()
        elif env_real_ip.lower() in ("off", "none", "0", "false"):
            self.real_ip = ""
        elif env_real_ip:
            self.real_ip = env_real_ip
        else:
            self.real_ip = DEFAULT_REAL_IP

        # 注意：不要随便换 deviceId。实测新设备指纹 + 新 IP 会直接触发 8821 行为验证。
        # 只有拿到"以前登录成功过"的设备 ID 时才通过 NETEASE_DEVICE_ID 指定。
        self.device_id = (device_id or os.environ.get("NETEASE_DEVICE_ID") or "").strip()

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _hash_password(password: str) -> str:
        return hashlib.md5(password.encode()).hexdigest()

    @staticmethod
    def _mask(value: Optional[str]) -> str:
        if not value:
            return "<empty>"
        return f"{value[:6]}…(len={len(value)})"

    def _normalize_md5(self, password: Optional[str], md5_password: Optional[str]) -> str:
        """统一拿到 32 位 md5。

        常见事故：把明文密码填进了 NETEASE_MD5_PASSWORD。这里不再静默失败，
        而是识别出来后按明文处理并告警，避免整条链路挂掉。
        """
        if md5_password:
            candidate = md5_password.strip()
            if re.fullmatch(r"[0-9a-fA-F]{32}", candidate):
                self.logger.debug("使用提供的 MD5 密码登录")
                return candidate.lower()
            self.logger.warning(
                "NETEASE_MD5_PASSWORD 不是 32 位 MD5（看起来是明文），已自动按明文加密。"
                "建议改成 secrets.NETEASE_PASSWORD，避免误解。"
            )
            return self._hash_password(candidate)

        if password:
            self.logger.debug("使用明文密码（转换为 MD5）登录")
            return self._hash_password(password.strip())

        raise LoginError("未提供密码：NETEASE_PASSWORD / NETEASE_MD5_PASSWORD 都为空")

    @staticmethod
    def _extract_cookies(session) -> Dict[str, str]:
        """遍历 cookie jar 取 MUSIC_U / __csrf

        不用 jar.get()：同名 cookie 存在多个 path 时 requests 会抛 CookieConflictError。
        """
        picked: Dict[str, str] = {}
        try:
            jar = session.cookies
        except Exception:
            return picked

        for cookie in jar:
            if cookie.name not in ("MUSIC_U", "__csrf"):
                continue
            if not cookie.value:
                continue
            # 后写入的覆盖先写入的（网易通常最后一条才是有效值）
            picked[cookie.name] = cookie.value
        return picked

    def _sleep(self, attempt: int) -> None:
        delay = min(2 * (2 ** attempt), 12) + random.uniform(0, 1.5)
        self.logger.debug(f"第 {attempt + 1} 次重试前等待 {delay:.1f}s")
        time.sleep(delay)

    # ------------------------------------------------------------------ login
    def _build_session(self, real_ip: str = ""):
        session = CreateNewSession()
        if real_ip:
            # pyncm 文档里写明：海外 IP 会遇到 460 Cheating / 风控，加这个头可解决
            session.headers["X-Real-IP"] = real_ip
            session.headers["X-Forwarded-For"] = real_ip
        if self.device_id:
            session.deviceId = self.device_id

        # pyncm 自己不带 timeout，网络抖动时会挂几分钟（实测 100s+）。
        # 这里给所有请求兜一个超时，让重试逻辑能真正生效。
        original_request = session.request
        timeout = self.timeout

        def request_with_timeout(method, url, *args, **kwargs):
            kwargs.setdefault("timeout", timeout)
            return original_request(method, url, *args, **kwargs)

        session.request = request_with_timeout
        SetCurrentSession(session)
        return session

    def _login_via_channel(
        self, channel: str, decorator, path: str, phone: str, md5_password: str, real_ip: str = ""
    ) -> Tuple[Dict[str, str], Dict[str, Any]]:
        """走单个通道登录一次，失败抛 LoginError / requests 异常"""
        session = self._build_session(real_ip)

        payload = {
            "type": "1",
            "phone": str(phone),
            "remember": "true",
            "countrycode": "86",
            "checkToken": "",
            "password": md5_password,
        }

        raw = decorator(lambda: (path, payload))(session=session)

        tag = f"{channel}{'/real-ip' if real_ip else '/direct'}"
        if not isinstance(raw, dict):
            raise LoginError(f"{tag} 返回非 JSON 响应: {str(raw)[:200]}", channel=channel)

        code = raw.get("code")
        msg = raw.get("msg") or raw.get("message") or ""
        if code != 200:
            raise LoginError(f"{tag} 登录被拒: code={code} msg={msg}", code=code, channel=channel)

        cookies = self._extract_cookies(session)
        if not cookies.get("MUSIC_U"):
            # 200 但没有 MUSIC_U —— 风控下的"静默失败"，是最难查的一种
            raise LoginError(
                f"{tag} 返回 200 但未下发 MUSIC_U（风控/设备校验拦截，"
                f"常见于机房 IP）; 同期下发的 cookie: {sorted(cookies)}",
                code=code,
                channel=channel,
            )

        return cookies, {"raw_code": code, "msg": msg, "tag": tag}

    def login(
        self, phone: str, password: Optional[str] = None, md5_password: Optional[str] = None
    ) -> Tuple[bool, Optional[Dict[str, str]]]:
        """兼容旧签名：返回 (成功, Cookie字典)"""
        result = self.login_and_verify(phone, password=password, md5_password=md5_password)
        if not result.ok:
            self.logger.error(f"登录失败: {result.reason}")
            return False, None
        return True, result.cookies

    def login_and_verify(
        self, phone: str, password: Optional[str] = None, md5_password: Optional[str] = None
    ) -> LoginResult:
        """登录 + 校验，返回结构化结果（失败原因可直接进邮件/日志）"""
        if not PYNCM_AVAILABLE:
            return LoginResult(False, None, None, "pyncm 未安装，请执行 pip install pyncm")

        if not phone:
            return LoginResult(False, None, None, "未提供手机号")

        try:
            md5_pwd = self._normalize_md5(password, md5_password)
        except LoginError as exc:
            return LoginResult(False, None, None, str(exc))

        channels = [
            ("eapi", EapiCryptoRequest, "/eapi/w/login/cellphone"),
            ("weapi", WeapiCryptoRequest, "/weapi/w/login/cellphone"),
        ]
        # 每个通道先带 X-Real-IP 试，再直连试（头本身可疑时直连反而可能过）
        ip_variants: List[str] = []
        for ip in (self.real_ip, ""):
            if ip not in ip_variants:
                ip_variants.append(ip)

        if self.real_ip:
            self.logger.info(f"抗风控: 登录请求将携带 X-Real-IP={self.real_ip}")
        else:
            self.logger.info("抗风控: 未启用 X-Real-IP（NETEASE_REAL_IP=off）")

        errors: List[str] = []
        risk_controlled = False

        for channel, decorator, path in channels:
            for real_ip in ip_variants:
                tag = f"{channel}{'/real-ip' if real_ip else '/direct'}"
                self.logger.info(
                    f"尝试登录: 账号 {phone[:3]}****{phone[-4:]} 通道 {tag}"
                )

                for attempt in range(self.retries):
                    try:
                        cookies, meta = self._login_via_channel(
                            channel, decorator, path, phone, md5_pwd, real_ip
                        )
                    except LoginError as exc:
                        errors.append(str(exc))
                        self.logger.error(f"[{tag}] 登录失败: {exc}")
                        if exc.code in (8821, 8815, 8816, 460):
                            risk_controlled = True
                        if exc.retryable and attempt < self.retries - 1:
                            self._sleep(attempt)
                            continue
                        break  # 凭据/风控类错误：换通道或换 IP 方案才对
                    except Exception as exc:  # 网络层：SSL EOF / 超时 / 连接重置
                        errors.append(f"[{tag}] 网络异常: {type(exc).__name__}: {exc}")
                        self.logger.warning(
                            f"[{tag}] 网络异常（{type(exc).__name__}），"
                            f"{attempt + 1}/{self.retries}: {exc}"
                        )
                        if attempt < self.retries - 1:
                            self._sleep(attempt)
                            continue
                        break
                    else:
                        music_u = cookies.get("MUSIC_U", "")
                        csrf = cookies.get("__csrf", "")
                        self.logger.info(f"[{tag}] 拿到 MUSIC_U: {self._mask(music_u)}")
                        if not csrf:
                            self.logger.warning(f"[{tag}] 未拿到 __csrf，稍后用旧值兜底")

                        ok, profile, vreason = self.verify_cookie(music_u, csrf)
                        if not ok:
                            errors.append(f"[{tag}] {vreason}")
                            self.logger.error(f"[{tag}] cookie 校验未通过: {vreason}")
                            break

                        self.logger.info(
                            f"[{tag}] cookie 校验通过: {profile.get('nickname')} "
                            f"(userId={profile.get('userId')})"
                        )
                        return LoginResult(
                            True,
                            {"Cookie_MUSIC_U": music_u, "Cookie___csrf": csrf},
                            profile,
                            "登录成功",
                            tag,
                        )

        reason = " | ".join(dict.fromkeys(errors)) or "登录失败原因未知"
        if risk_controlled:
            reason += (
                " | 判定: 登录被网易风控拦截（机房/海外 IP）。"
                "可尝试 NETEASE_REAL_IP 指定国内 IP，或改用 self-hosted runner / 手动更新 cookie"
            )
        return LoginResult(False, None, None, reason)

    # ----------------------------------------------------------------- verify
    def verify_cookie(
        self, music_u: str, csrf: str = "", retries: Optional[int] = None
    ) -> Tuple[bool, Dict[str, Any], str]:
        """用 MUSIC_U 打一次账号信息接口，确认是真登录态"""
        if requests is None:
            return False, {}, "requests 未安装"
        if not music_u:
            return False, {}, "MUSIC_U 为空"

        attempts = retries if retries is not None else 2
        last_error = ""
        headers = {"User-Agent": DEFAULT_UA, "Referer": "https://music.163.com/"}
        if self.real_ip:
            headers["X-Real-IP"] = self.real_ip

        for attempt in range(max(1, attempts)):
            try:
                resp = requests.get(
                    ACCOUNT_URL,
                    headers=headers,
                    cookies={"MUSIC_U": music_u, "__csrf": csrf},
                    timeout=self.timeout,
                )
                data = resp.json()
            except Exception as exc:
                last_error = f"校验请求失败: {type(exc).__name__}: {exc}"
                if attempt < attempts - 1:
                    self._sleep(attempt)
                continue

            code = data.get("code")
            profile = data.get("profile") or {}
            if code == 200 and profile.get("userId"):
                return True, profile, "Cookie 有效"

            detail = data.get("msg") or data.get("message") or ""
            last_error = f"账号接口返回 code={code} {detail}".strip()
            # 明确的无登录态，不必再重试
            if code in (301, 401, -462):
                break
            if attempt < attempts - 1:
                self._sleep(attempt)

        return False, {}, last_error or "Cookie 校验失败"

    def check_partner_access(self, music_u: str, csrf: str = "") -> Tuple[bool, str]:
        """检查音乐合伙人接口是否可访问（非致命，仅用于日志定位）"""
        if requests is None:
            return False, "requests 未安装"
        try:
            headers = {"User-Agent": DEFAULT_UA, "Referer": "https://music.163.com/"}
            if self.real_ip:
                headers["X-Real-IP"] = self.real_ip
            resp = requests.get(
                PARTNER_TASK_URL,
                headers=headers,
                cookies={"MUSIC_U": music_u, "__csrf": csrf},
                timeout=self.timeout,
            )
            data = resp.json()
        except Exception as exc:
            return False, f"合伙人接口请求失败: {type(exc).__name__}: {exc}"

        if data.get("code") == 200:
            payload = data.get("data") or {}
            return True, (
                f"合伙人任务可访问: {payload.get('completedCount', '?')}/{payload.get('count', '?')}"
            )
        return False, f"合伙人接口返回 code={data.get('code')} msg={data.get('msg') or ''}"
