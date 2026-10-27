"""Cookie 刷新链路的离线单测（不联网、不需要真实账号）

跑法：
    python tests/test_refresh_cookie.py
    python -m pytest tests/test_refresh_cookie.py -q
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.tasks.cookie_refresh import CookieRefreshTask  # noqa: E402
from src.utils.auth import AuthService, LoginError, LoginResult  # noqa: E402
from src.utils.github import GitHubService  # noqa: E402
from src.utils.logger import Logger  # noqa: E402

logger = Logger(log_level=50)  # 静音


class _FakeJarCookie:
    def __init__(self, name, value):
        self.name = name
        self.value = value


class _FakeSession:
    def __init__(self, cookies):
        self.cookies = cookies


# ---------------------------------------------------------------- AuthService
def test_extract_cookies_handles_duplicates():
    """同名 cookie 多 path 时不能抛 CookieConflictError"""
    jar = [
        _FakeJarCookie("MUSIC_A_T", "a1"),
        _FakeJarCookie("MUSIC_A_T", "a2"),
        _FakeJarCookie("MUSIC_U", "old"),
        _FakeJarCookie("MUSIC_U", "new"),
        _FakeJarCookie("__csrf", "csrf"),
    ]
    got = AuthService._extract_cookies(_FakeSession(jar))
    assert got["MUSIC_U"] == "new", got
    assert got["__csrf"] == "csrf", got
    assert "MUSIC_A_T" not in got


def test_normalize_md5_accepts_md5():
    svc = AuthService(logger)
    assert svc._normalize_md5(None, "b" * 32) == "b" * 32


def test_normalize_md5_detects_plaintext_in_md5_field():
    """把明文填进 NETEASE_MD5_PASSWORD 时自动按明文处理，而不是发出去被拒"""
    import hashlib

    svc = AuthService(logger)
    assert svc._normalize_md5(None, "plaintext-pwd") == hashlib.md5(b"plaintext-pwd").hexdigest()


def test_normalize_md5_requires_something():
    svc = AuthService(logger)
    try:
        svc._normalize_md5(None, None)
    except LoginError as exc:
        assert "未提供密码" in str(exc)
    else:
        raise AssertionError("空密码应当抛 LoginError")


def test_login_error_exposes_code_hint():
    exc = LoginError("x", code=8821)
    assert exc.code == 8821
    assert "行为验证码" in str(exc)


def test_login_returns_failure_reason_instead_of_silent_none():
    """所有通道都失败时，必须带回真实错误码，而不是只说"未获取到 MUSIC_U"""
    svc = AuthService(logger, retries=1)

    def boom(*a, **k):
        raise LoginError("eapi/real-ip 登录被拒: code=8821 msg=", code=8821)

    svc._login_via_channel = boom  # type: ignore
    res = svc.login_and_verify("13800000000", password="x")
    assert res.ok is False
    assert "8821" in res.reason, res.reason


def test_login_success_path():
    svc = AuthService(logger, retries=1)
    svc._login_via_channel = lambda *a, **k: (  # type: ignore
        {"MUSIC_U": "u" * 64, "__csrf": "c" * 32},
        {"tag": "fake"},
    )
    svc.verify_cookie = lambda *a, **k: (True, {"nickname": "tester", "userId": 1}, "ok")  # type: ignore
    res = svc.login_and_verify("13800000000", password="x")
    assert res.ok and res.cookies["Cookie_MUSIC_U"] == "u" * 64


# ---------------------------------------------------------------- GitHubService
def test_github_rejects_empty_secret():
    """空值绝不能写进 Secrets（会清掉已有的有效 cookie）"""
    svc = GitHubService(logger, token="t", repo="o/r")
    assert svc.update_secret("MUSIC_U", "") is False
    assert svc.update_secret("MUSIC_U", "   ") is False


def test_github_check_ready_reports_missing_token():
    svc = GitHubService(logger, token="", repo="o/r")
    ok, reason = svc.check_ready()
    assert ok is False and "GH_TOKEN" in reason


def test_github_requires_owner_repo():
    svc = GitHubService(logger, token="t", repo="bad-repo")
    ok, reason = svc.check_ready()
    assert ok is False and "GH_REPO" in reason


# ------------------------------------------------------------------- Task 层
class _RecordingGitHub:
    def __init__(self):
        self.calls = []

    def update_cookies(self, cookies):
        self.calls.append(cookies)
        return True

    def check_ready(self):
        return True, "ok"


class _NullAuth:
    def __init__(self, result):
        self.result = result

    def login_and_verify(self, **kwargs):
        return self.result

    def verify_cookie(self, *a, **k):
        return False, {}, "invalid"


def test_task_keeps_old_cookie_when_login_fails_but_old_is_valid():
    task = CookieRefreshTask(logger)
    task.auth_service = _NullAuth(LoginResult(False, None, None, "8821 风控"))
    task.auth_service.verify_cookie = lambda *a, **k: (True, {"nickname": "n", "userId": 1}, "ok")  # type: ignore
    task.github_service = _RecordingGitHub()

    os.environ.update({"NETEASE_PHONE": "13800000000", "NETEASE_PASSWORD": "x", "MUSIC_U": "old"})
    outcome = task.run()
    assert outcome.ok is True and outcome.status == "kept", outcome
    assert task.github_service.calls == [], "旧 cookie 仍有效时不应写 Secrets"


def test_task_fails_cleanly_when_login_and_old_cookie_both_bad():
    task = CookieRefreshTask(logger)
    task.auth_service = _NullAuth(LoginResult(False, None, None, "8821 风控"))
    task.github_service = _RecordingGitHub()

    os.environ.update({"NETEASE_PHONE": "13800000000", "NETEASE_PASSWORD": "x", "MUSIC_U": ""})
    outcome = task.run()
    assert outcome.ok is False and "8821" in outcome.reason
    assert task.github_service.calls == []


def test_task_writes_new_cookie_when_login_ok():
    task = CookieRefreshTask(logger)
    task.auth_service = _NullAuth(
        LoginResult(
            True,
            {"Cookie_MUSIC_U": "new-mu", "Cookie___csrf": "new-csrf"},
            {"nickname": "n", "userId": 1},
            "ok",
        )
    )
    gh = _RecordingGitHub()
    task.github_service = gh

    os.environ.update({"NETEASE_PHONE": "13800000000", "NETEASE_PASSWORD": "x", "MUSIC_U": "old"})
    outcome = task.run()
    assert outcome.ok is True and outcome.status == "refreshed", outcome
    assert gh.calls == [{"MUSIC_U": "new-mu", "CSRF": "new-csrf"}]


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in tests:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"FAIL {fn.__name__}: {type(exc).__name__}: {exc}")
        else:
            print(f"ok   {fn.__name__}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
