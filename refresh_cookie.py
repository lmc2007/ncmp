"""Cookie 自动刷新入口

用法：
    python refresh_cookie.py              # 正常刷新：登录 -> 校验 -> 写 Secrets
    python refresh_cookie.py --dry-run    # 只登录+校验，不写 Secrets
    python refresh_cookie.py --diagnose   # 环境自检 + 各通道逐个试，输出诊断信息

退出码：0 = 成功（含"沿用旧 cookie"），1 = 失败。失败必须让 Actions 变红，
否则界面一片绿、实际每周都没刷新。
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.core.tasks.cookie_refresh import CookieRefreshTask  # noqa: E402
from src.utils.config import Config  # noqa: E402
from src.utils.logger import Logger  # noqa: E402
from src.utils.notification import NotificationService  # noqa: E402

CONFIG_KEY_MAP = {
    "NETEASE_PHONE": "netease_phone",
    "NETEASE_PASSWORD": "netease_password",
    "NETEASE_MD5_PASSWORD": "netease_md5_password",
    "GH_TOKEN": "gh_token",
    "GH_REPO": "gh_repo",
}


def load_local_config(logger: Logger) -> Config:
    """本地运行时用 config/setting.json 补环境变量；失败了也不拦路"""
    try:
        config = Config()
    except Exception as exc:
        logger.warning(f"读取本地配置失败（将只使用环境变量）: {exc}")
        return _EmptyConfig()

    for env_key, cfg_key in CONFIG_KEY_MAP.items():
        value = config.get(cfg_key)
        if value and not os.environ.get(env_key):
            os.environ[env_key] = str(value)
            logger.debug(f"从本地配置注入 {env_key}")
    return config


class _EmptyConfig:
    """兜底空配置：没有 config/setting.json 时也要能只靠环境变量跑完"""

    def get(self, key, default=None):
        return default


def print_env_summary(logger: Logger) -> None:
    def mask(value: str) -> str:
        if not value:
            return "<未设置>"
        return f"{value[:6]}…(len={len(value)})"

    phone = os.environ.get("NETEASE_PHONE", "")
    logger.info("---- 环境自检 ----")
    logger.info(f"NETEASE_PHONE        : {phone[:3] + '****' + phone[-4:] if len(phone) >= 7 else '<未设置>'}")
    logger.info(f"NETEASE_PASSWORD     : {'<已设置>' if os.environ.get('NETEASE_PASSWORD') else '<未设置>'}")
    logger.info(f"NETEASE_MD5_PASSWORD : {mask(os.environ.get('NETEASE_MD5_PASSWORD', ''))}")
    logger.info(f"GH_TOKEN             : {'<已设置>' if os.environ.get('GH_TOKEN') else '<未设置>'}")
    logger.info(f"GH_REPO              : {os.environ.get('GH_REPO', '<未设置>')}")
    logger.info(f"NETEASE_REAL_IP      : {os.environ.get('NETEASE_REAL_IP') or '<默认 118.88.88.88>'}")
    logger.info(f"NETEASE_DEVICE_ID    : {os.environ.get('NETEASE_DEVICE_ID') or '<默认 pyncm!>'}")
    logger.info(f"MUSIC_U (现有 secret): {mask(os.environ.get('MUSIC_U', ''))}")
    logger.info(f"CSRF   (现有 secret) : {mask(os.environ.get('CSRF', ''))}")
    logger.info(f"Python               : {sys.version.split()[0]}")
    logger.info("------------------")


def run_diagnose(logger: Logger) -> int:
    """逐项自检，定位到底卡在哪一步"""
    print_env_summary(logger)

    from src.utils.auth import AuthService, PYNCM_AVAILABLE

    if not PYNCM_AVAILABLE:
        logger.error("pyncm 未安装，先执行: pip install -r requirements.txt")
        return 1

    auth = AuthService(logger)

    logger.info("---- 现有 Cookie 是否仍有效 ----")
    old_music_u = os.environ.get("MUSIC_U", "")
    if old_music_u:
        ok, profile, reason = auth.verify_cookie(old_music_u, os.environ.get("CSRF", ""))
        logger.info(f"现有 cookie: {'有效' if ok else '无效'} | {reason}")
        if ok:
            logger.info(f"账号: {profile.get('nickname')} (userId={profile.get('userId')})")
            okp, preason = auth.check_partner_access(old_music_u, os.environ.get("CSRF", ""))
            logger.info(f"合伙人权限: {'可访问' if okp else '不可访问'} | {preason}")
    else:
        logger.warning("没有现成的 MUSIC_U，跳过校验")

    logger.info("---- 尝试重新登录 ----")
    result = auth.login_and_verify(
        phone=os.environ.get("NETEASE_PHONE", ""),
        password=os.environ.get("NETEASE_PASSWORD") or None,
        md5_password=os.environ.get("NETEASE_MD5_PASSWORD") or None,
    )
    if result.ok:
        logger.info(f"登录成功（通道 {result.channel}）")
        logger.info(f"账号: {(result.profile or {}).get('nickname')} "
                    f"(userId={(result.profile or {}).get('userId')})")
        okp, preason = auth.check_partner_access(
            result.cookies.get("Cookie_MUSIC_U", ""), result.cookies.get("Cookie___csrf", "")
        )
        logger.info(f"合伙人权限: {'可访问' if okp else '不可访问'} | {preason}")
        return 0

    logger.error(f"登录失败: {result.reason}")
    logger.error("常见原因见上方提示；机房 IP 触发风控(8821/8816)时，只能手动更新 cookie 或改用自建 runner")
    return 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="网易云音乐合伙人 Cookie 自动刷新")
    parser.add_argument("--dry-run", action="store_true", help="只登录校验，不写 Secrets")
    parser.add_argument("--diagnose", action="store_true", help="环境自检与逐通道登录诊断")
    parser.add_argument("--retries", type=int, default=3, help="登录重试次数（默认 3）")
    args = parser.parse_args(argv)

    logger = Logger()
    config = load_local_config(logger)

    try:
        if args.diagnose:
            return run_diagnose(logger)

        notifier = NotificationService(config, logger)
        task = CookieRefreshTask(logger, notifier, dry_run=args.dry_run)
        task.auth_service.retries = max(1, args.retries)

        outcome = task.run()
        if outcome.ok:
            logger.info(f"✅ Cookie刷新成功 ({outcome.status}): {outcome.reason}")
            return 0

        logger.error(f"❌ Cookie刷新失败: {outcome.reason}")
        return 1

    except Exception as exc:
        error_message = f"Cookie刷新程序异常: {type(exc).__name__}: {exc}"
        logger.error(error_message)
        try:
            notifier = NotificationService(config, logger)
            notifier.send_notification("网易云音乐合伙人 - Cookie刷新异常", error_message)
        except Exception as notify_error:
            logger.error(f"发送异常通知时出错: {notify_error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
