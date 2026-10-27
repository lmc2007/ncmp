import base64
import os
import time
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

import nacl.encoding
import nacl.public
import requests

from ..utils.logger import Logger


class GitHubService:
    """更新仓库 Actions Secrets

    修复点：
    - 不再在 __init__ 里 raise（之前 GH_TOKEN 缺失会让任务构造直接炸，
      连"哪一步失败"都看不出来）。
    - 拒绝写入空值（原来 cookie 取不到时会用 "" 把已有 Secret 清空，等于自毁）。
    - 403/404 给出 scope 提示（public_repo 无法写 secrets 是高频坑）。
    - 5xx 重试；公钥只取一次。
    """

    def __init__(self, logger: Logger, token: Optional[str] = None, repo: Optional[str] = None):
        self.logger = logger
        self.api_base = "https://api.github.com"
        self.token = token or os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        self.repo_full = repo or os.environ.get("GH_REPO") or os.environ.get("GITHUB_REPOSITORY")

        self.repo_owner, self.repo_name = "", ""
        if self.repo_full and "/" in self.repo_full:
            self.repo_owner, self.repo_name = self.repo_full.split("/", 1)

        self.headers = {
            "Authorization": f"token {self.token}" if self.token else "",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self._public_key: Optional[Dict] = None

    # ------------------------------------------------------------- preflight
    def check_ready(self) -> Tuple[bool, str]:
        """执行前自检，给出可执行的修复建议"""
        if not self.token:
            return False, "GH_TOKEN 未设置（需要带 secrets 写权限的 PAT）"
        if not self.repo_owner or not self.repo_name:
            return False, f"GH_REPO 无效: {self.repo_full!r}（应为 owner/repo）"
        return True, "ok"

    def _url(self, suffix: str) -> str:
        return f"{self.api_base}/repos/{self.repo_owner}/{self.repo_name}{suffix}"

    def _explain(self, response: requests.Response) -> str:
        if response.status_code == 401:
            return "Token 无效或已过期，请重新生成 GH_TOKEN"
        if response.status_code == 403:
            return (
                "Token 权限不足。classic PAT 需要 repo（公开仓库仅 public_repo 不够），"
                "fine-grained PAT 需要对目标仓库勾选 Secrets: Read and write"
            )
        if response.status_code == 404:
            return "仓库不存在或 Token 无权访问（检查 GH_REPO 与 Token 的仓库范围）"
        return response.text[:300]

    # ------------------------------------------------------------ public key
    def get_public_key(self) -> Optional[Dict]:
        if self._public_key:
            return self._public_key

        for attempt in range(3):
            try:
                response = requests.get(
                    self._url("/actions/secrets/public-key"),
                    headers=self.headers,
                    timeout=20,
                )
            except Exception as exc:
                self.logger.warning(f"获取公钥网络异常({attempt + 1}/3): {exc}")
                time.sleep(2 * (attempt + 1))
                continue

            if response.status_code == 200:
                self._public_key = response.json()
                return self._public_key

            if response.status_code in (401, 403, 404):
                self.logger.error(
                    f"获取公钥失败: {response.status_code} - {self._explain(response)}"
                )
                return None

            self.logger.warning(
                f"获取公钥失败({attempt + 1}/3): {response.status_code} - {response.text[:200]}"
            )
            time.sleep(2 * (attempt + 1))

        return None

    # --------------------------------------------------------------- encrypt
    def encrypt_secret(self, public_key: str, secret_value: str) -> str:
        public_key_bytes = base64.b64decode(public_key)
        box = nacl.public.SealedBox(nacl.public.PublicKey(public_key_bytes))
        encrypted = box.encrypt(secret_value.encode("utf-8"))
        return base64.b64encode(encrypted).decode("utf-8")

    # ---------------------------------------------------------------- update
    def update_secret(self, secret_name: str, secret_value: str) -> bool:
        ready, reason = self.check_ready()
        if not ready:
            self.logger.error(f"无法更新 secret '{secret_name}': {reason}")
            return False

        if not secret_value or not str(secret_value).strip():
            # 关键保护：绝不用空值覆盖已有 Secret
            self.logger.error(f"拒绝把空值写入 secret '{secret_name}'（避免清掉已有的有效值）")
            return False

        key_data = self.get_public_key()
        if not key_data:
            return False

        try:
            encrypted_value = self.encrypt_secret(key_data["key"], str(secret_value).strip())
        except Exception as exc:
            self.logger.error(f"加密 secret '{secret_name}' 失败: {exc}")
            return False

        payload = {"encrypted_value": encrypted_value, "key_id": key_data["key_id"]}

        for attempt in range(3):
            try:
                response = requests.put(
                    self._url(f"/actions/secrets/{secret_name}"),
                    headers=self.headers,
                    json=payload,
                    timeout=20,
                )
            except Exception as exc:
                self.logger.warning(f"更新 secret '{secret_name}' 网络异常({attempt + 1}/3): {exc}")
                time.sleep(2 * (attempt + 1))
                continue

            if response.status_code in (201, 204):
                self.logger.info(f"成功更新 secret: {secret_name}")
                return True

            if response.status_code >= 500 and attempt < 2:
                self.logger.warning(
                    f"更新 secret '{secret_name}' 服务端错误 {response.status_code}，重试中"
                )
                time.sleep(2 * (attempt + 1))
                continue

            self.logger.error(
                f"更新 secret '{secret_name}' 失败: {response.status_code} - {self._explain(response)}"
            )
            return False

        return False

    def verify_secret_updated(self, secret_name: str, since_ts: float) -> bool:
        """回读 Secret 的 updated_at，确认远端真的写进去了（失败不算致命）"""
        try:
            response = requests.get(
                self._url(f"/actions/secrets/{secret_name}"), headers=self.headers, timeout=20
            )
            if response.status_code != 200:
                self.logger.debug(f"回读 secret '{secret_name}' 失败: {response.status_code}")
                return False

            updated_at = response.json().get("updated_at", "")
            if not updated_at:
                return False

            ts = datetime.strptime(updated_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            fresh = ts.timestamp() >= since_ts - 120  # 容忍 2 分钟时差
            self.logger.info(
                f"secret '{secret_name}' 远端更新时间: {updated_at} "
                f"({'已生效' if fresh else '未变化'})"
            )
            return fresh
        except Exception as exc:
            self.logger.debug(f"回读 secret '{secret_name}' 异常: {exc}")
            return False

    def update_cookies(self, cookies: Dict[str, str]) -> bool:
        ready, reason = self.check_ready()
        if not ready:
            self.logger.error(f"跳过 Secrets 更新: {reason}")
            return False

        started = time.time()
        results = {}
        for key, value in cookies.items():
            results[key] = self.update_secret(key, value)

        if all(results.values()):
            for key in results:
                self.verify_secret_updated(key, started)
            return True

        failed = [k for k, v in results.items() if not v]
        self.logger.error(f"以下 secret 更新失败: {', '.join(failed)}")
        return False
