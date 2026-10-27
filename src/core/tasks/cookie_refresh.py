import os
from typing import Dict, NamedTuple, Optional

from ...utils.auth import AuthService, LoginResult
from ...utils.github import GitHubService
from ...utils.logger import Logger
from ...utils.notification import NotificationService


class RefreshOutcome(NamedTuple):
    ok: bool
    status: str          # refreshed / kept / failed
    reason: str
    profile: Optional[Dict] = None


class CookieRefreshTask:
    """Cookie 刷新任务

    流程：登录 -> 校验新 cookie -> 写 Secrets
    - 登录失败但旧 cookie 仍有效时，不覆盖、不报红，只发告警（避免每周误报）
    - 登录成功但新 cookie 校验不通过时，绝不写 Secrets（原来会写进一个假 cookie）
    """

    def __init__(
        self,
        logger: Logger,
        notifier: Optional[NotificationService] = None,
        dry_run: bool = False,
    ):
        self.logger = logger
        self.notifier = notifier
        self.dry_run = dry_run
        self.auth_service = AuthService(logger)
        self.github_service = GitHubService(logger)
        self.last_outcome: Optional[RefreshOutcome] = None

    # --------------------------------------------------------------- helpers
    def _notify(self, subject: str, content: str) -> None:
        if not self.notifier:
            return
        try:
            self.notifier.send_notification(subject, content)
        except Exception as exc:
            self.logger.error(f"发送通知失败: {exc}")

    def _existing_cookies(self) -> Dict[str, str]:
        return {
            "MUSIC_U": os.environ.get("MUSIC_U", ""),
            "CSRF": os.environ.get("CSRF", ""),
        }

    def _finish(self, outcome: RefreshOutcome) -> RefreshOutcome:
        self.last_outcome = outcome
        self.logger.info(f"刷新结果: status={outcome.status} reason={outcome.reason}")
        return outcome

    # ---------------------------------------------------------------- execute
    def execute(self) -> bool:
        return self.run().ok

    def run(self) -> RefreshOutcome:
        self.logger.info("开始执行Cookie刷新任务")

        phone = (os.environ.get("NETEASE_PHONE") or "").strip()
        password = os.environ.get("NETEASE_PASSWORD") or None
        md5_password = os.environ.get("NETEASE_MD5_PASSWORD") or None

        if not phone:
            reason = "未设置手机号，请检查 secret NETEASE_PHONE"
            self.logger.error(reason)
            self._notify("网易云音乐合伙人 - 自动登录失败", reason)
            return RefreshOutcome(False, "failed", reason)

        if not password and not md5_password:
            reason = "未设置密码，请检查 secret NETEASE_PASSWORD 或 NETEASE_MD5_PASSWORD"
            self.logger.error(reason)
            self._notify("网易云音乐合伙人 - 自动登录失败", reason)
            return RefreshOutcome(False, "failed", reason)

        existing = self._existing_cookies()

        # 1) 登录 + 校验
        result: LoginResult = self.auth_service.login_and_verify(
            phone=phone, password=password, md5_password=md5_password
        )

        if not result.ok or not result.cookies:
            return self._handle_login_failure(result.reason, existing)

        new_music_u = result.cookies.get("Cookie_MUSIC_U", "")
        new_csrf = result.cookies.get("Cookie___csrf", "") or existing.get("CSRF", "")

        if not new_music_u:
            return self._handle_login_failure("登录返回的 MUSIC_U 为空", existing)

        # 2) 和旧值比对，避免无意义的重复写入
        if new_music_u == existing.get("MUSIC_U"):
            self.logger.info("新 cookie 与现有 secret 一致，跳过写入")
            self._notify(
                "网易云音乐合伙人 - Cookie校验通过",
                f"登录成功，cookie 与现有 secret 一致，无需更新。\n账号: {result.profile.get('nickname') if result.profile else '?'}",
            )
            return self._finish(RefreshOutcome(True, "kept", "cookie 未变化", result.profile))

        if self.dry_run:
            self.logger.warning("dry-run 模式：已拿到并校验成功的新 cookie，但不写入 Secrets")
            return self._finish(
                RefreshOutcome(True, "refreshed", "dry-run，未写入 Secrets", result.profile)
            )

        # 3) 写 Secrets
        self.logger.info("开始更新 GitHub Secrets ...")
        updated = self.github_service.update_cookies(
            {"MUSIC_U": new_music_u, "CSRF": new_csrf}
        )

        if updated:
            nickname = (result.profile or {}).get("nickname", "?")
            userId = (result.profile or {}).get("userId", "?")
            self._notify(
                "网易云音乐合伙人 - Cookie更新成功",
                f"已获取并通过校验的新 Cookie 写入 Secrets。\n"
                f"账号: {nickname} (userId={userId})\n通道: {result.channel}\n"
                f"MUSIC_U: {new_music_u[:6]}…(len={len(new_music_u)})",
            )
            return self._finish(RefreshOutcome(True, "refreshed", "Secrets 已更新", result.profile))

        reason = "登录与校验都通过，但写入 GitHub Secrets 失败（检查 GH_TOKEN 权限）"
        self.logger.error(reason)
        self._notify("网易云音乐合伙人 - Cookie更新失败", reason)
        return self._finish(RefreshOutcome(False, "failed", reason, result.profile))

    # ------------------------------------------------------- failure handling
    def _handle_login_failure(self, reason: str, existing: Dict[str, str]) -> RefreshOutcome:
        self.logger.error(f"自动登录失败: {reason}")

        # 旧 cookie 还活着就别惊动用户，也别把 workflow 刷红
        old_music_u = existing.get("MUSIC_U", "")
        if old_music_u:
            ok, profile, vreason = self.auth_service.verify_cookie(
                old_music_u, existing.get("CSRF", "")
            )
            if ok:
                msg = (
                    f"本次自动登录失败，但现有 MUSIC_U 仍然有效，已沿用旧 Cookie。\n"
                    f"账号: {profile.get('nickname')} (userId={profile.get('userId')})\n"
                    f"失败原因: {reason}"
                )
                self.logger.warning(msg)
                self._notify("网易云音乐合伙人 - 自动登录失败（旧Cookie仍有效）", msg)
                return self._finish(
                    RefreshOutcome(True, "kept", f"沿用旧 cookie；登录失败原因: {reason}", profile)
                )
            self.logger.error(f"旧 cookie 也已失效: {vreason}")

        self._notify(
            "网易云音乐合伙人 - 自动登录失败",
            f"自动登录失败，且没有可用的旧 Cookie，请手动更新 secrets.MUSIC_U / CSRF。\n"
            f"失败原因: {reason}",
        )
        return self._finish(RefreshOutcome(False, "failed", reason))
