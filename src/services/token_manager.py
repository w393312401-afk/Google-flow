"""Token manager for Flow2API with AT auto-refresh"""

import asyncio
import hashlib
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, List
from ..core.database import Database
from ..core.config import config
from ..core.models import Token, Project
from ..core.logger import debug_logger
from ..core.monitoring import record_token_refresh
from ..core.account_audit import audit_account_operation
from ..core.account_operation_context import account_error_reason, account_operation_source, operation_source
from .flow_client import FlowClient
from .proxy_manager import ProxyManager
from ..core.account_admission import AccountAdmission, AccountAdmissionBusy


class TokenManager:
    """Token lifecycle manager with AT auto-refresh"""

    def __init__(self, db: Database, flow_client: FlowClient):
        self.db = db
        self.flow_client = flow_client
        self._refresh_lock_guard = asyncio.Lock()
        self._project_lock_guard = asyncio.Lock()
        self._refresh_locks: dict[int, asyncio.Lock] = {}
        self._validation_lock_guard = asyncio.Lock()
        self._validation_locks: dict[int, asyncio.Lock] = {}
        self._project_locks: dict[int, asyncio.Lock] = {}
        self._refresh_futures: dict[int, asyncio.Task] = {}
        self._at_validation_cache: dict[int, float] = {}
        self._at_validation_routes: dict[int, str] = {}
        self._at_validation_identities: dict[int, str] = {}
        self._last_at_refresh_error: dict[int, str] = {}
        self._last_st_refresh_error: dict[int, str] = {}
        self._last_validation_error: dict[int, str] = {}
        self._last_health_diagnostic: dict[int, tuple[str, str, str]] = {}
        self._validation_retry_after: dict[int, tuple[str, float, str]] = {}
        self._protocol_retry_after: dict[int, tuple[str, float, str]] = {}
        self._protocol_refresher_task: Optional[asyncio.Task] = None
        self._credential_recovery = None
        db_path = getattr(db, "db_path", None)
        self.account_admission = AccountAdmission(db_path) if isinstance(db_path, (str, bytes)) else None

    async def recover_credentials(self, token_id: int) -> Dict[str, Any]:
        """Manually recover a fixed AdsPower account through its login host."""
        if self._credential_recovery is None:
            from .credential_recovery import CredentialRecovery

            self._credential_recovery = CredentialRecovery(self)
        return await self._credential_recovery.recover(token_id)

    async def _audit(self, token_id, operation, status, reason="", *,
                     stage="result", details=None, token=None, source="system"):
        await audit_account_operation(
            self.db, token_id, operation=operation, status=status, reason=reason,
            stage=stage, source=operation_source(source), details=details, token=token,
        )

    async def _get_token_lock(
        self,
        lock_map: dict[int, asyncio.Lock],
        guard: asyncio.Lock,
        token_id: int,
    ) -> asyncio.Lock:
        """按 token 维度获取锁，避免不同 token 之间串行阻塞。"""
        async with guard:
            lock = lock_map.get(token_id)
            if lock is None:
                lock = asyncio.Lock()
                lock_map[token_id] = lock
            return lock

    def _get_project_pool_size(self) -> int:
        """读取当前生效的单 Token 项目池大小配置。"""
        try:
            return max(1, min(50, int(config.personal_project_pool_size or 4)))
        except Exception:
            return 4

    def _sort_projects(self, projects: List[Project]) -> List[Project]:
        """Sort projects in a stable order for round-robin selection."""
        return sorted(
            projects, key=lambda project: (project.id or 0, project.project_id)
        )

    def _normalize_project_name_base(self, project_name: Optional[str] = None) -> str:
        """Normalize a project base name for pooled creation."""
        raw_name = (project_name or "").strip()
        if raw_name:
            parts = raw_name.rsplit(" ", 1)
            if len(parts) == 2 and parts[1].startswith("P") and parts[1][1:].isdigit():
                return parts[0]
            return raw_name
        return datetime.now().strftime("%b %d - %H:%M")

    def _build_project_name(
        self, pool_index: int, base_name: Optional[str] = None
    ) -> str:
        """Build a project name for the pool."""
        normalized_base = self._normalize_project_name_base(base_name)
        return f"{normalized_base} P{pool_index}"

    def _normalize_protocol_mode(self, value: Optional[str]) -> str:
        mode = (value or "session").strip().lower()
        return "protocol" if mode == "protocol" else "session"

    def _normalize_refresh_interval(self, value: Optional[int]) -> int:
        try:
            return max(1, int(value if value is not None else 120))
        except Exception:
            return 120

    def _parse_at_expires(self, value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except Exception:
            return None

    def _as_utc(self, value: Optional[datetime]) -> Optional[datetime]:
        if not value:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def _normalize_token_proxy_url(self, proxy_url: Optional[str]) -> str:
        raw = (proxy_url or "").strip()
        if not raw:
            return ""
        proxy_manager = getattr(self.flow_client, "proxy_manager", None)
        if proxy_manager and hasattr(proxy_manager, "normalize_proxy_url"):
            normalized = proxy_manager.normalize_proxy_url(raw)
            return normalized or ""
        return raw

    def _clear_at_validation_cache(self, token_id: int) -> None:
        self._at_validation_cache.pop(int(token_id), None)
        self._at_validation_routes.pop(int(token_id), None)
        self._at_validation_identities.pop(int(token_id), None)

    def _mark_at_valid(
        self, token_id: int, ttl_seconds: int = 300, *, proxy_url=None,
        token: Optional[Token] = None,
    ) -> None:
        self._validation_retry_after.pop(int(token_id), None)
        self._last_validation_error.pop(int(token_id), None)
        self._last_health_diagnostic.pop(int(token_id), None)
        self._at_validation_cache[int(token_id)] = time.monotonic() + max(
            30, int(ttl_seconds or 300)
        )
        self._at_validation_routes[int(token_id)] = str(proxy_url or "").strip()
        if token is not None:
            self._at_validation_identities[int(token_id)] = self.health_identity(token)
        else:
            self._at_validation_identities.pop(int(token_id), None)

    def _has_recent_at_validation(
        self, token_id: int, *, proxy_url=None, token: Optional[Token] = None,
    ) -> bool:
        if self._at_validation_routes.get(int(token_id), "") != str(proxy_url or "").strip():
            return False
        identity = self._at_validation_identities.get(int(token_id))
        if token is not None and identity is not None and identity != self.health_identity(token):
            self._clear_at_validation_cache(token_id)
            return False
        expires_at = float(self._at_validation_cache.get(int(token_id), 0.0) or 0.0)
        if expires_at <= time.monotonic():
            self._clear_at_validation_cache(token_id)
            return False
        return True

    @staticmethod
    def health_identity(token: Token) -> str:
        """Identify credentials and routes without retaining their plaintext."""
        fields = (
            "st", "at", "google_cookies", "proxy_url", "captcha_proxy_url",
            "extension_route_key", "protocol_mode",
        )
        payload = "\0".join(str(getattr(token, field, "") or "") for field in fields)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def account_identity(token: Token) -> str:
        """Identify credentials alone; exit rotation moves the route under them."""
        fields = ("st", "at", "google_cookies", "extension_route_key", "protocol_mode")
        payload = "\0".join(str(getattr(token, field, "") or "") for field in fields)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def get_validation_cooldown_reason(self, token: Token) -> Optional[str]:
        """Return a current temporary failure; changed credentials retry at once."""
        retry = self._validation_retry_after.get(int(token.id))
        if retry is None:
            return None
        if retry[0] != self.health_identity(token) or retry[1] <= time.monotonic():
            self._validation_retry_after.pop(int(token.id), None)
            return None
        return retry[2]

    def _is_transient_network_failure(self, reason: Optional[str]) -> bool:
        """判断刷新失败原因是否为网络/代理类瞬时错误。"""
        text = str(reason or "").strip()
        if not text:
            return False
        lowered = text.lower()
        try:
            if self.flow_client._is_proxy_connection_error(Exception(text)):
                return True
        except Exception:
            pass
        try:
            if self.flow_client._is_retryable_network_error(lowered):
                return True
        except Exception:
            pass
        transient_keywords = (
            "timed out",
            "timeout",
            "connection",
            "curl: (",
            "proxy",
            "network",
            "ssl",
            "tls",
            "eof",
            "getaddrinfo",
            "name or service not known",
            "temporarily unavailable",
            "502",
            "503",
            "504",
        )
        return any(keyword in lowered for keyword in transient_keywords)

    def _is_authentication_failure(self, reason: Any) -> bool:
        """Only explicit credential rejection warrants recovery or disabling.

        In particular, the frontend labels some HTTP 403 responses as login
        failures even when they are traffic controls. That wording is not proof
        that the stored credentials have expired.
        """
        return self._authentication_evidence(reason) != "none"

    def _authentication_evidence(self, reason: Any) -> str:
        """Keep the existing auth rules while distinguishing their evidence."""
        status = getattr(reason, "status_code", None)
        if status is None:
            status = getattr(getattr(reason, "response", None), "status_code", None)
        if str(status) == "401":
            return "http_401"
        text = str(reason or "")
        if re.search(r"\bUNAUTHENTICATED\b", text, re.IGNORECASE):
            return "unauthenticated"
        if re.search(
            r"\b(?:HTTP(?:\s+Error)?|status(?:_code)?|code)[\s:=\"']+401\b",
            text,
            re.IGNORECASE,
        ):
            return "http_401"
        if "Google Cookies 不完整，缺少" in text:
            return "missing_cookie"
        if "页面已跳转到 Google 登录" in text:
            return "login_redirect"
        return "none"

    def _safe_health_error(self, stage: str, error: Any) -> str:
        """Keep diagnostic categories/codes, never response bodies or cookies."""
        text = str(error or "")
        status = re.search(
            r"\b(?:HTTP(?:\s+Error)?|status(?:_code)?|code)[\s:=\"']+([45]\d{2})\b",
            text,
            re.IGNORECASE,
        )
        if self._is_authentication_failure(error):
            detail = "credentials rejected (UNAUTHENTICATED)"
        elif "PUBLIC_ERROR_UNUSUAL_ACTIVITY" in text:
            traffic_code = (
                "PUBLIC_ERROR_UNUSUAL_ACTIVITY_TOO_MUCH_TRAFFIC"
                if "PUBLIC_ERROR_UNUSUAL_ACTIVITY_TOO_MUCH_TRAFFIC" in text
                else "PUBLIC_ERROR_UNUSUAL_ACTIVITY"
            )
            detail = f"upstream traffic restriction ({traffic_code})"
        elif status:
            detail = f"upstream unavailable (HTTP {status.group(1)})"
        elif "metadata" in text.lower():
            detail = "frontend bootstrap metadata unavailable"
        elif self._is_transient_network_failure(text):
            detail = "network or proxy unavailable"
        else:
            detail = "upstream validation unavailable (unclassified error)"
        return f"{stage}: {detail}"

    def _health_diagnostic(self, stage: str, error: Any) -> tuple[str, str, str]:
        if stage not in {"AT_CHECK", "AT_VERIFY", "AT_REFRESH", "ST_REFRESH", "PROTOCOL_REFRESH"}:
            stage = "TOKEN_VALIDATION"
        reason = self._safe_health_error(stage, error).partition(": ")[2]
        return stage, self._authentication_evidence(error), reason

    def _log_health_diagnostic(self, diagnostic: tuple[str, str, str], decision: str) -> None:
        # These values are fixed categories only. Keep this small audit trail
        # even when verbose request/response debugging is disabled.
        stage, evidence, reason = diagnostic
        debug_logger.logger.warning(
            "[TOKEN_HEALTH] %s stage=%s auth_evidence=%s reason=%s decision=%s",
            debug_logger._format_timestamp(), stage, evidence, reason, decision,
        )

    async def _persist_health(self, token_id: int, reason: Optional[str]) -> None:
        """持久化最近一次校验失败原因（成功则清除）；诊断写入失败不得影响主流程。"""
        try:
            if reason:
                await self.db.set_token_health(token_id, reason)
            else:
                await self.db.clear_token_health(token_id)
        except Exception as persist_error:
            debug_logger.log_error(
                f"[TOKEN_HEALTH] Token {token_id}: 健康状态写入失败: {type(persist_error).__name__}"
            )

    async def _record_at_failure(
        self, token_id: int, reason: str, *, error: Any = None,
        token: Optional[Token] = None,
    ) -> None:
        self._clear_at_validation_cache(token_id)
        self._last_at_refresh_error[token_id] = reason
        self._last_validation_error[token_id] = reason
        await self._persist_health(token_id, reason)
        diagnostic = self._health_diagnostic(
            reason.partition(":")[0], error if error is not None else reason
        )
        self._last_health_diagnostic[token_id] = diagnostic
        await self._audit(
            token_id, "health_check", "failed", account_error_reason(reason),
            stage=diagnostic[0], token=token,
            details={"auth_evidence": diagnostic[1], "decision": "unavailable"},
        )
        # Traffic controls and browser/network availability do not prove bad
        # credentials. Keep the account enabled but stop each queued request
        # from repeating the same failed validation for unchanged credentials.
        if not self._is_authentication_failure(error if error is not None else reason):
            token = token or await self.db.get_token(token_id)
            if token is not None:
                cooldown = 300 if "PUBLIC_ERROR_UNUSUAL_ACTIVITY" in reason else 60
                self._validation_retry_after[token_id] = (
                    self.health_identity(token), time.monotonic() + cooldown, reason,
                )
                await self._audit(
                    token_id, "health_check", "cooldown", "validation_backoff",
                    stage=diagnostic[0], token=token,
                    details={"cooldown_seconds": cooldown, "retry_reason": account_error_reason(reason)},
                )
        else:
            self._validation_retry_after.pop(token_id, None)
        self._log_health_diagnostic(diagnostic, "unavailable")

    def get_last_validation_error(self, token_id: int) -> Optional[str]:
        """Return a safe health failure for scheduling errors and request logs."""
        return self._last_validation_error.get(int(token_id))

    async def _flow_call_with_proxy(self, proxy_url: Optional[str], call):
        """Scope one account's HTTP call without changing global proxy settings."""
        previous_fingerprint = self.flow_client.get_request_fingerprint()
        proxy_url = (proxy_url or "").strip()
        next_fingerprint = dict(previous_fingerprint or {})
        if proxy_url:
            next_fingerprint["proxy_url"] = proxy_url
        else:
            # An account with no override uses the global proxy, never an
            # inherited override from another account in a nested call.
            next_fingerprint.pop("proxy_url", None)
        self.flow_client._set_request_fingerprint(next_fingerprint)
        try:
            return await call()
        finally:
            self.flow_client._set_request_fingerprint(previous_fingerprint)

    async def _flow_call_for_token(self, token: Token, call):
        return await self._flow_call_with_proxy(getattr(token, "proxy_url", ""), call)

    async def _st_to_at_for_token(self, token: Token, st: str) -> Dict[str, Any]:
        return await self._flow_call_for_token(
            token,
            lambda: self.flow_client.st_to_at(
                st,
                google_cookies=token.google_cookies,
                token_id=token.id,
            ),
        )

    async def _get_credits_for_token(self, token: Token, at: str) -> Dict[str, Any]:
        return await self._flow_call_for_token(
            token,
            lambda: self.flow_client.get_credits(
                at,
                google_cookies=token.google_cookies,
                token_id=token.id,
            ),
        )

    async def get_personal_warmup_project_ids(
        self,
        tokens: Optional[List[Token]] = None,
        limit: Optional[int] = None,
    ) -> List[str]:
        """返回 personal 模式启动时建议预热的项目 ID 列表。"""
        token_list = tokens if tokens is not None else await self.get_all_tokens()
        pool_size = self._get_project_pool_size()
        warmup_ids: List[str] = []
        seen_projects: set[str] = set()

        try:
            warmup_limit = None if limit is None else max(1, int(limit))
        except Exception:
            warmup_limit = None

        for token in token_list:
            if not token or not token.is_active:
                continue

            candidate_ids: List[str] = []
            current_project_id = str(token.current_project_id or "").strip()
            if current_project_id:
                candidate_ids.append(current_project_id)

            projects = [
                project
                for project in await self.db.get_projects_by_token(token.id)
                if project.is_active
            ]
            for project in self._sort_projects(projects):
                project_id = str(project.project_id or "").strip()
                if project_id and project_id not in candidate_ids:
                    candidate_ids.append(project_id)

            for project_id in candidate_ids[:pool_size]:
                if project_id in seen_projects:
                    continue
                seen_projects.add(project_id)
                warmup_ids.append(project_id)
                if warmup_limit is not None and len(warmup_ids) >= warmup_limit:
                    return warmup_ids

        return warmup_ids

    async def _create_project_for_token(
        self, token: Token, pool_index: int, base_name: Optional[str] = None,
        *, audit_failure: bool = True,
    ) -> Project:
        """Create a new pooled project for a token and persist it."""
        try:
            project_name = self._build_project_name(pool_index, base_name)
            project_id = await self._flow_call_for_token(
                token, lambda: self.flow_client.create_project(
                    token.st, project_name, google_cookies=token.google_cookies,
                ),
            )
            debug_logger.log_info(
                f"[PROJECT] Created pooled project for token {token.id}: {project_name} ({project_id})"
            )
            project = Project(
                project_id=project_id,
                token_id=token.id,
                project_name=project_name,
            )
            project.id = await self.db.add_project(project)
        except Exception as error:
            if audit_failure:
                await self._audit(
                    token.id, "project", "failed", "project_creation_failed", stage="project", token=token,
                    details={"retry_reason": account_error_reason(error)},
                )
            raise
        await self._audit(token.id, "project", "success", "project_created", stage="project", token=token)
        return project

    def _select_next_project(self, token: Token, projects: List[Project]) -> Project:
        """Select the next project from the pool in round-robin order."""
        ordered_projects = self._sort_projects(projects)
        if not ordered_projects:
            raise ValueError("No available projects for token")

        if len(ordered_projects) == 1:
            return ordered_projects[0]

        if token.current_project_id:
            for index, project in enumerate(ordered_projects):
                if project.project_id == token.current_project_id:
                    return ordered_projects[(index + 1) % len(ordered_projects)]

        return ordered_projects[0]

    # ========== Token CRUD ==========

    async def get_all_tokens(self) -> List[Token]:
        """Get all tokens"""
        return await self.db.get_all_tokens()

    async def get_active_tokens(self) -> List[Token]:
        """Get all active tokens"""
        return await self.db.get_active_tokens()

    async def get_token(self, token_id: int) -> Optional[Token]:
        """Get token by ID"""
        return await self.db.get_token(token_id)

    async def delete_token(self, token_id: int):
        """Delete token"""
        token = await self.db.get_token(token_id)
        project_ids: List[str] = []
        if token:
            current_project_id = str(token.current_project_id or "").strip()
            if current_project_id:
                project_ids.append(current_project_id)

        for project in await self.db.get_projects_by_token(token_id):
            project_id = str(project.project_id or "").strip()
            if project_id and project_id not in project_ids:
                project_ids.append(project_id)

        await self.db.delete_token(token_id)
        await self._audit(token_id, "delete", "success", "account_deleted", token=token)

        refresh_task = self._refresh_futures.pop(token_id, None)
        if refresh_task and not refresh_task.done():
            refresh_task.cancel()
            try:
                await refresh_task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
        self._refresh_locks.pop(token_id, None)
        self._validation_locks.pop(token_id, None)
        self._project_locks.pop(token_id, None)
        self._last_validation_error.pop(token_id, None)
        self._last_health_diagnostic.pop(token_id, None)
        self._last_at_refresh_error.pop(token_id, None)
        self._last_st_refresh_error.pop(token_id, None)
        self._protocol_retry_after.pop(token_id, None)
        self._validation_retry_after.pop(token_id, None)
        self._clear_at_validation_cache(token_id)

        if config.captcha_method == "personal" and project_ids:
            try:
                from .browser_captcha_personal import BrowserCaptchaService

                service = await BrowserCaptchaService.get_instance(self.db)
                for project_id in project_ids:
                    await service.stop_resident_mode(project_id)
            except Exception as e:
                debug_logger.log_warning(
                    f"[DELETE_TOKEN] 清理 personal 浏览器状态失败: {e}"
                )

    async def enable_token(self, token_id: int, *, reason: str = "manual_enable"):
        """Enable a token and reset error count"""
        # Enable the token
        await self.db.update_token(
            token_id, is_active=True, ban_reason=None, banned_at=None
        )
        # Reset error count when enabling (only reset total error_count, keep today_error_count)
        await self.db.reset_error_count(token_id)
        self._validation_retry_after.pop(token_id, None)
        self._clear_at_validation_cache(token_id)
        await self._audit(token_id, "enable", "enabled", reason, stage="account_state")

    async def disable_token(self, token_id: int, *, reason: str = "manual_disable", details=None):
        """Disable a token"""
        await self.db.update_token(token_id, is_active=False)
        await self._audit(token_id, "disable", "disabled", reason, stage="account_state", details=details)

    # ========== Token添加 (支持Project创建) ==========

    async def add_token(
        self,
        st: str,
        project_id: Optional[str] = None,
        project_name: Optional[str] = None,
        remark: Optional[str] = None,
        image_enabled: bool = True,
        video_enabled: bool = True,
        image_concurrency: int = -1,
        video_concurrency: int = -1,
        captcha_proxy_url: Optional[str] = None,
        extension_route_key: Optional[str] = None,
        protocol_mode: str = "session",
        google_cookies: Optional[str] = None,
        login_account: Optional[str] = None,
        login_password: Optional[str] = None,
        proxy_url: Optional[str] = None,
        auto_refresh_enabled: bool = True,
        refresh_interval_minutes: int = 120,
        is_active: bool = True,
        adspower_serial: Optional[int] = None,
    ) -> Token:
        """Add a new token and prepare its pooled projects."""
        proxy_url = self._normalize_token_proxy_url(proxy_url)
        if not st and google_cookies:
            cookie_hash = hashlib.sha256(google_cookies.encode("utf-8")).hexdigest()[
                :32
            ]
            st = f"frontend-{cookie_hash}"
        existing_token = await self.db.get_token_by_st(st) if st else None
        if existing_token:
            raise ValueError(f"Token 已存在：{existing_token.email}")

        debug_logger.log_info(f"[ADD_TOKEN] Converting ST to AT...")
        try:
            result = await self._flow_call_with_proxy(
                proxy_url, lambda: self.flow_client.st_to_at(st, google_cookies=google_cookies),
            )
            at = result["access_token"]
            expires = result.get("expires")
            user_info = result.get("user", {})
            email = user_info.get("email", "") or str(login_account or "").strip()
            if not email and google_cookies:
                account_hash = hashlib.sha256(
                    google_cookies.encode("utf-8")
                ).hexdigest()[:16]
                email = f"account-{account_hash}@flow.local"
            existing_identity = await self.db.get_token_by_email(email) if email else None
            if existing_identity:
                raise ValueError(f"账号已存在: {email}")
            name = user_info.get("name", email.split("@")[0] if email else "")
            at_expires = None
            if expires:
                try:
                    at_expires = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                except Exception:
                    pass
        except ValueError:
            raise
        except Exception as e:
            raise ValueError(f"Google Cookie 验证失败：{str(e)}")

        try:
            credits_result = await self._flow_call_with_proxy(
                proxy_url, lambda: self.flow_client.get_credits(at, google_cookies=google_cookies),
            )
            credits = credits_result.get("credits", 0)
            user_paygate_tier = credits_result.get("userPaygateTier")
        except Exception:
            credits = 0
            user_paygate_tier = None

        base_project_name = self._normalize_project_name_base(project_name)
        project_pool_size = self._get_project_pool_size()
        pooled_projects: List[Project] = []

        if project_id:
            first_project_name = self._build_project_name(1, base_project_name)
            debug_logger.log_info(
                f"[ADD_TOKEN] Using provided project_id as pooled project #1: {project_id}"
            )
            pooled_projects.append(
                Project(
                project_id=project_id,
                token_id=0,
                project_name=first_project_name,
                    tool_name="PINHOLE",
                )
            )
        else:
            try:
                first_project_name = self._build_project_name(1, base_project_name)
                first_project_id = await self._flow_call_with_proxy(
                    proxy_url, lambda: self.flow_client.create_project(
                        st, first_project_name, google_cookies=google_cookies,
                    ),
                )
                debug_logger.log_info(
                    f"[ADD_TOKEN] Created pooled project #1: {first_project_name} (ID: {first_project_id})"
                )
                pooled_projects.append(
                    Project(
                    project_id=first_project_id,
                    token_id=0,
                    project_name=first_project_name,
                        tool_name="PINHOLE",
                    )
                )
            except Exception as e:
                await self._audit(
                    None, "project", "failed", "project_creation_failed", stage="project",
                    token={"email": email, "adspower_serial": adspower_serial},
                    details={"retry_reason": account_error_reason(e)},
                )
                raise ValueError(f"创建项目失败：{str(e)}")

        token = Token(
            st=st,
            at=at,
            at_expires=at_expires,
            email=email,
            name=name,
            remark=remark,
            is_active=bool(is_active),
            credits=credits,
            user_paygate_tier=user_paygate_tier,
            current_project_id=pooled_projects[0].project_id,
            current_project_name=pooled_projects[0].project_name,
            image_enabled=image_enabled,
            video_enabled=video_enabled,
            image_concurrency=image_concurrency,
            video_concurrency=video_concurrency,
            captcha_proxy_url=captcha_proxy_url,
            extension_route_key=extension_route_key,
            protocol_mode=self._normalize_protocol_mode(protocol_mode),
            google_cookies=(google_cookies or "").strip(),
            login_account=(login_account or "").strip(),
            login_password=login_password or "",
            proxy_url=proxy_url,
            auto_refresh_enabled=bool(auto_refresh_enabled),
            refresh_interval_minutes=self._normalize_refresh_interval(
                refresh_interval_minutes
            ),
            adspower_serial=adspower_serial or None,
        )

        token_id = await self.db.add_token(token)
        token.id = token_id

        pooled_projects[0].token_id = token_id
        pooled_projects[0].id = await self.db.add_project(pooled_projects[0])

        while len(pooled_projects) < project_pool_size:
            new_project = await self._create_project_for_token(
                token, len(pooled_projects) + 1, base_project_name
            )
            pooled_projects.append(new_project)

        debug_logger.log_info(
            f"[ADD_TOKEN] Token added successfully (ID: {token_id}, Email: {email}, pooled_projects={len(pooled_projects)})"
        )
        await self._audit(
            token_id, "create", "success", "account_created", token=token,
            details={"credits": token.credits, "is_active": token.is_active, "pool_size": len(pooled_projects)},
        )
        return token

    async def update_token(
        self,
        token_id: int,
        st: Optional[str] = None,
        at: Optional[str] = None,
        at_expires: Optional[datetime] = None,
        email: Optional[str] = None,
        project_id: Optional[str] = None,
        project_name: Optional[str] = None,
        remark: Optional[str] = None,
        image_enabled: Optional[bool] = None,
        video_enabled: Optional[bool] = None,
        image_concurrency: Optional[int] = None,
        video_concurrency: Optional[int] = None,
        captcha_proxy_url: Optional[str] = None,
        extension_route_key: Optional[str] = None,
        protocol_mode: Optional[str] = None,
        google_cookies: Optional[str] = None,
        login_account: Optional[str] = None,
        login_password: Optional[str] = None,
        proxy_url: Optional[str] = None,
        auto_refresh_enabled: Optional[bool] = None,
        refresh_interval_minutes: Optional[int] = None,
        auto_enable_on_update: bool = True,
        adspower_serial: Optional[int] = None,
    ):
        """Update token (支持修改project_id和project_name)

        当用户编辑保存token时，如果token未过期，自动清空429禁用状态
        """
        update_fields = {}
        credential_updated = any(value is not None for value in (st, at, at_expires))

        if st is not None:
            update_fields["st"] = st
        if at is not None:
            update_fields["at"] = at
        if at_expires is not None:
            update_fields["at_expires"] = at_expires
        if email is not None:
            normalized_email = email.strip().lower()
            existing_identity = await self.db.get_token_by_email(normalized_email)
            if existing_identity and existing_identity.id != token_id:
                raise ValueError(f"账号已存在: {normalized_email}")
            update_fields["email"] = normalized_email
        if project_id is not None:
            update_fields["current_project_id"] = project_id
        if project_name is not None:
            update_fields["current_project_name"] = project_name
        if remark is not None:
            update_fields["remark"] = remark
        if image_enabled is not None:
            update_fields["image_enabled"] = image_enabled
        if video_enabled is not None:
            update_fields["video_enabled"] = video_enabled
        if image_concurrency is not None:
            update_fields["image_concurrency"] = image_concurrency
        if video_concurrency is not None:
            update_fields["video_concurrency"] = video_concurrency
        if captcha_proxy_url is not None:
            update_fields["captcha_proxy_url"] = captcha_proxy_url
        if extension_route_key is not None:
            update_fields["extension_route_key"] = extension_route_key
        if protocol_mode is not None:
            update_fields["protocol_mode"] = self._normalize_protocol_mode(
                protocol_mode
            )
        if google_cookies is not None:
            update_fields["google_cookies"] = google_cookies.strip()
        if login_account is not None:
            update_fields["login_account"] = login_account.strip()
        if login_password is not None:
            update_fields["login_password"] = login_password
        if proxy_url is not None:
            update_fields["proxy_url"] = self._normalize_token_proxy_url(proxy_url)
        if auto_refresh_enabled is not None:
            update_fields["auto_refresh_enabled"] = bool(auto_refresh_enabled)
        if refresh_interval_minutes is not None:
            update_fields["refresh_interval_minutes"] = (
                self._normalize_refresh_interval(refresh_interval_minutes)
            )
        if adspower_serial is not None:
            # 0 表示清除序号
            update_fields["adspower_serial"] = adspower_serial or None

        # 检查token是否因429被禁用，如果是且未过期，则清空429状态
        token = await self.db.get_token(token_id)
        if auto_enable_on_update and credential_updated and token and not token.is_active:
            debug_logger.log_info(
                f"[UPDATE_TOKEN] Token {token_id} 已更新凭证，自动恢复为启用状态"
            )
            update_fields["is_active"] = True
            update_fields["ban_reason"] = None
            update_fields["banned_at"] = None

        if auto_enable_on_update and token and token.ban_reason == "429_rate_limit":
            # 检查token是否过期
            is_expired = False
            if token.at_expires:
                now = datetime.now(timezone.utc)
                if token.at_expires.tzinfo is None:
                    at_expires_aware = token.at_expires.replace(tzinfo=timezone.utc)
                else:
                    at_expires_aware = token.at_expires
                is_expired = at_expires_aware <= now

            # 如果未过期，清空429禁用状态
            if not is_expired:
                debug_logger.log_info(
                    f"[UPDATE_TOKEN] Token {token_id} 编辑保存，清空429禁用状态"
                )
                update_fields["ban_reason"] = None
                update_fields["banned_at"] = None

        if update_fields:
            if credential_updated or any(value is not None for value in (
                google_cookies, proxy_url, captcha_proxy_url, extension_route_key,
            )):
                self._clear_at_validation_cache(token_id)
                self._validation_retry_after.pop(token_id, None)
            await self.db.update_token(token_id, **update_fields)
            await self._audit(
                token_id, "update", "success",
                "credentials_updated" if credential_updated else "account_updated",
                stage="credentials" if credential_updated else "settings",
                details={"field_count": len(update_fields), "credential_changed": credential_updated},
            )
            if update_fields.get("is_active") is True and token and not token.is_active:
                await self._audit(
                    token_id, "enable", "enabled", "credentials_updated", stage="account_state",
                )
            if credential_updated:
                # 凭证刚被更新，旧的失败原因不再适用
                await self._persist_health(token_id, None)

    # ========== AT自动刷新逻辑 (核心) ==========

    def _should_refresh_at(self, token: Token) -> bool:
        """根据当前 token 快照判断是否需要刷新 AT。"""
        if not token.at:
            debug_logger.log_info(f"[AT_CHECK] Token {token.id}: AT不存在,需要刷新")
            return True

        if not token.at_expires:
            debug_logger.log_info(
                f"[AT_CHECK] Token {token.id}: AT过期时间未知,尝试刷新"
            )
            return True

        now = datetime.now(timezone.utc)
        if token.at_expires.tzinfo is None:
            at_expires_aware = token.at_expires.replace(tzinfo=timezone.utc)
        else:
            at_expires_aware = token.at_expires

        time_until_expiry = at_expires_aware - now
        # Current Flow authenticates with Google cookies and returns a 55-minute
        # frontend placeholder. The legacy one-hour window would refresh it on
        # every selection, even immediately after a successful validation.
        frontend_cookie_token = (
            token.at == FlowClient.FRONTEND_ACCESS_TOKEN
            and bool(str(getattr(token, "google_cookies", "") or "").strip())
        )
        refresh_window_seconds = 300 if frontend_cookie_token else 3600
        if time_until_expiry.total_seconds() < refresh_window_seconds:
            debug_logger.log_info(
                f"[AT_CHECK] Token {token.id}: AT即将过期 "
                f"(剩余 {time_until_expiry.total_seconds():.0f} 秒),需要刷新"
            )
            return True

        return False

    def needs_at_refresh(self, token: Optional[Token]) -> bool:
        """供调度层快速判断当前 token 是否大概率会触发 AT 刷新。"""
        if not token:
            return True
        return self._should_refresh_at(token)

    async def ensure_valid_token(self, token: Optional[Token]) -> Optional[Token]:
        if token is None:
            return None
        if self.account_admission is None:
            return await self._ensure_valid_token_admitted(token)
        try:
            with self.account_admission.generation(token.id):
                return await self._ensure_valid_token_admitted(token)
        except AccountAdmissionBusy:
            return None

    async def _ensure_valid_token_admitted(self, token: Optional[Token]) -> Optional[Token]:
        """确保 token 的 AT 可用，并在必要时返回刷新后的最新对象。"""
        if not token:
            return None

        validation_lock = await self._get_token_lock(
            self._validation_locks, self._validation_lock_guard, token.id,
        )
        async with validation_lock:
            # A waiter must see refreshes performed by the earlier validation.
            latest = await self.db.get_token(token.id)
            if latest is None or not latest.is_active:
                return None
            token = latest
            if self.get_validation_cooldown_reason(token):
                return None
            return await self._ensure_valid_token_inner(token)

    async def _ensure_valid_token_inner(self, token: Token) -> Optional[Token]:
        """Validate one account while its validation lock is held."""

        if not self._should_refresh_at(token):
            if self._has_recent_at_validation(token.id, proxy_url=token.proxy_url, token=token):
                return token
            try:
                credits_result = await self._get_credits_for_token(token, token.at)
                await self.db.update_token(
                    token.id,
                    credits=credits_result.get("credits", 0),
                    user_paygate_tier=credits_result.get("userPaygateTier"),
                )
                await self._persist_health(token.id, None)
                self._last_at_refresh_error.pop(token.id, None)
                self._mark_at_valid(token.id, proxy_url=token.proxy_url, token=token)
                await self._audit(
                    token.id, "health_check", "success", "credentials_validated",
                    stage="AT_CHECK", token=token, details={"credits": credits_result.get("credits", 0)},
                )
                return await self.db.get_token(token.id) or token
            except Exception as e:
                await self._record_at_failure(
                    token.id, self._safe_health_error("AT_CHECK", e), error=e, token=token,
                )
                if not self._is_authentication_failure(e):
                    return None

        if not await self._refresh_at(token.id):
            return None

        return await self.db.get_token(token.id)

    async def is_at_valid(self, token_id: int, token: Optional[Token] = None) -> bool:
        """检查AT是否有效,如果无效或即将过期则自动刷新

        Returns:
            True if AT is valid or refreshed successfully
            False if AT cannot be refreshed
        """
        token_obj = (
            token
            if token and token.id == token_id
            else await self.db.get_token(token_id)
        )
        if not token_obj:
            return False

        valid_token = await self.ensure_valid_token(token_obj)
        return valid_token is not None

    async def _refresh_at_inner(self, token_id: int) -> bool:
        """Perform exactly one real AT refresh attempt."""
        refresh_lock = await self._get_token_lock(
            self._refresh_locks,
            self._refresh_lock_guard,
            token_id,
        )
        async with refresh_lock:
            token = await self.db.get_token(token_id)
            if not token:
                return False

            result = await self._do_refresh_at(token_id, token.st, token)
            if result:
                return True
            if not self._is_authentication_failure(
                self._last_at_refresh_error.get(token_id)
            ):
                return False

            debug_logger.log_info(
                f"[AT_REFRESH] Token {token_id}: first AT refresh failed, trying ST refresh..."
            )
            self._last_st_refresh_error.pop(token_id, None)
            diagnostic = self._last_health_diagnostic.get(token_id)
            if diagnostic:
                self._log_health_diagnostic(diagnostic, "recover")
            await self._audit(
                token_id, "refresh_at", "started", "refresh_started", stage="recovery", token=token,
            )
            new_st = await self._try_refresh_st(token_id, token)
            if new_st:
                debug_logger.log_info(
                    f"[AT_REFRESH] Token {token_id}: ST refreshed, retrying AT refresh..."
                )
                latest_token = await self.db.get_token(token_id) or token
                result = await self._do_refresh_at(token_id, new_st, latest_token)
                if result:
                    return True
            else:
                st_error = self._last_st_refresh_error.get(token_id)
                if st_error and not self._is_authentication_failure(st_error):
                    await self._record_at_failure(token_id, st_error, token=token)
                    return False

            if not self._is_authentication_failure(
                self._last_at_refresh_error.get(token_id)
            ):
                return False

            debug_logger.log_error(
                f"[AT_REFRESH] Token {token_id}: credentials rejected after recovery, disabling token"
            )
            await self.disable_token(token_id, reason="authentication_failed")
            diagnostic = self._last_health_diagnostic.get(token_id)
            if diagnostic:
                self._log_health_diagnostic(diagnostic, "disabled")
            self._clear_at_validation_cache(token_id)
            return False

    async def _refresh_at(self, token_id: int) -> bool:
        """Coalesce concurrent AT refresh calls for the same token."""
        existing_task = self._refresh_futures.get(token_id)
        if existing_task:
            return await existing_task

        async def runner() -> bool:
            try:
                await self._audit(token_id, "refresh_at", "started", "refresh_started", stage="validation")
                refreshed = await self._refresh_at_inner(token_id)
                await self._audit(
                    token_id, "refresh_at", "success" if refreshed else "failed",
                    "credentials_validated" if refreshed else account_error_reason(self._last_at_refresh_error.get(token_id)),
                    stage="result",
                )
                return refreshed
            except Exception as error:
                await self._audit(token_id, "refresh_at", "failed", account_error_reason(error), stage="result")
                raise
            finally:
                current = self._refresh_futures.get(token_id)
                if current is task:
                    self._refresh_futures.pop(token_id, None)

        task = asyncio.create_task(runner())
        self._refresh_futures[token_id] = task
        return await task

    async def _do_refresh_at(
        self, token_id: int, st: str, token: Optional[Token] = None
    ) -> bool:
        """执行 AT 刷新的核心逻辑

        Args:
            token_id: Token ID
            st: Session Token

        Returns:
            True if refresh successful AND AT is valid, False otherwise
        """
        self._clear_at_validation_cache(token_id)
        try:
            debug_logger.log_info(f"[AT_REFRESH] Token {token_id}: 开始刷新AT...")

            # 使用ST转AT
            token = token or await self.db.get_token(token_id)
            result = await (
                self._st_to_at_for_token(token, st)
                if token is not None
                else self.flow_client.st_to_at(st)
            )
            new_at = result["access_token"]
            expires = result.get("expires")

            # 解析过期时间
            new_at_expires = None
            if expires:
                try:
                    new_at_expires = datetime.fromisoformat(
                        expires.replace("Z", "+00:00")
                    )
                except:
                    pass

            # 验证 AT 有效性：通过 get_credits 测试
            try:
                credits_result = await (
                    self._get_credits_for_token(token, new_at)
                    if token is not None
                    else self.flow_client.get_credits(new_at)
                )
                await self.db.update_token(
                    token_id,
                    at=new_at,
                    at_expires=new_at_expires,
                    credits=credits_result.get("credits", 0),
                    user_paygate_tier=credits_result.get("userPaygateTier"),
                )
                await self._persist_health(token_id, None)
                self._mark_at_valid(
                    token_id, proxy_url=token.proxy_url if token else None,
                    token=token.model_copy(update={"at": new_at}) if token else None,
                )
                debug_logger.log_info(
                    f"[AT_REFRESH] Token {token_id}: AT 验证成功（余额: {credits_result.get('credits', 0)}）"
                )
                self._last_at_refresh_error.pop(token_id, None)
                record_token_refresh("at", "success")
                await self._audit(
                    token_id, "refresh_at", "success", "credentials_validated", stage="AT_VERIFY",
                    token=token, details={"credits": credits_result.get("credits", 0)},
                )
                return True
            except Exception as verify_err:
                await self._record_at_failure(
                    token_id, self._safe_health_error("AT_VERIFY", verify_err), error=verify_err, token=token,
                )
                record_token_refresh("at", "failure")
                return False

        except Exception as e:
            await self._record_at_failure(
                token_id, self._safe_health_error("AT_REFRESH", e), error=e, token=token,
            )
            record_token_refresh("at", "failure")
            return False

    async def _try_protocol_refresh_st(
        self, token_id: int, token: Token, *, source: str = "system",
    ) -> Optional[str]:
        if (
            self._normalize_protocol_mode(getattr(token, "protocol_mode", "session"))
            != "protocol"
        ):
            return None
        if not (getattr(token, "google_cookies", "") or "").strip():
            debug_logger.log_info(
                f"[ST_REFRESH] Token {token_id}: 未配置 Google Cookies，跳过协议刷新"
            )
            return None

        # An upstream outage cannot be repaired by repeatedly checking the same
        # cookie. A changed credential/proxy can be tried immediately.
        retry_key = hashlib.sha256(
            f"{token.google_cookies}\0{token.proxy_url}".encode("utf-8")
        ).hexdigest()
        retry = self._protocol_retry_after.get(token_id)
        if retry and retry[0] == retry_key and retry[1] > time.monotonic():
            self._last_st_refresh_error[token_id] = retry[2]
            return None

        try:
            from .protocol_login import protocol_loginer

            proxy_url = (getattr(token, "proxy_url", "") or "").strip()
            if not proxy_url:
                proxy_manager = getattr(self.flow_client, "proxy_manager", None)
                if proxy_manager is not None:
                    try:
                        fallback_proxy = await proxy_manager.get_request_proxy_url()
                        proxy_url = (fallback_proxy or "").strip()
                    except Exception as e:
                        debug_logger.log_warning(
                            f"[ST_REFRESH] Token {token_id}: 获取全局请求代理失败 - {e}"
                        )

            debug_logger.log_info(f"[ST_REFRESH] Token {token_id}: 尝试协议刷新 ST...")
            await self._audit(token_id, "refresh_st", "started", "refresh_started", stage="page_probe", source=source, token=token)
            login_result = await protocol_loginer.login(
                token.google_cookies,
                proxy=proxy_url or None,
                email=(getattr(token, "login_account", "") or token.email or None),
            )
            if login_result.get("success") and login_result.get("session_token"):
                self._protocol_retry_after.pop(token_id, None)
                self._last_st_refresh_error.pop(token_id, None)
                new_st = str(login_result["session_token"]).strip()
                await self.db.update_token(
                    token_id,
                    st=new_st,
                    last_st_refresh_at=datetime.now(timezone.utc),
                    last_st_refresh_result="success",
                )
                debug_logger.log_info(
                    f"[ST_REFRESH] Token {token_id}: 协议刷新 ST 成功"
                )
                record_token_refresh("st", "success")
                await self._audit(
                    token_id, "refresh_st", "success", "frontend_probe_passed", stage="page_probe", token=token,
                    source=source, details={"category": "protocol_probe", "cookie_changed": False},
                )
                return new_st

            error = self._safe_health_error("ST_REFRESH", login_result.get("error"))
            self._log_health_diagnostic(
                self._health_diagnostic("ST_REFRESH", login_result.get("error")), "recovery_failed"
            )
            self._last_st_refresh_error[token_id] = error
            await self._audit(token_id, "refresh_st", "failed", account_error_reason(error), stage="page_probe", source=source, token=token)
            if not self._is_authentication_failure(error):
                self._protocol_retry_after[token_id] = (
                    retry_key, time.monotonic() + 60, error
                )
            await self.db.update_token(
                token_id,
                last_st_refresh_at=datetime.now(timezone.utc),
                last_st_refresh_result=error,
            )
            debug_logger.log_warning(
                f"[ST_REFRESH] Token {token_id}: 协议刷新 ST 失败 - {error}"
            )
            record_token_refresh("st", "failure")
            return None
        except Exception as e:
            error = self._safe_health_error("ST_REFRESH", e)
            self._log_health_diagnostic(self._health_diagnostic("ST_REFRESH", e), "recovery_failed")
            self._last_st_refresh_error[token_id] = error
            await self._audit(token_id, "refresh_st", "failed", account_error_reason(error), stage="page_probe", source=source, token=token)
            if not self._is_authentication_failure(error):
                self._protocol_retry_after[token_id] = (
                    retry_key, time.monotonic() + 60, error
                )
            await self.db.update_token(
                token_id,
                last_st_refresh_at=datetime.now(timezone.utc),
                last_st_refresh_result=error,
            )
            debug_logger.log_error(
                f"[ST_REFRESH] Token {token_id}: {error}"
            )
            record_token_refresh("st", "failure")
            return None

    async def _try_refresh_st(self, token_id: int, token) -> Optional[str]:
        """尝试通过浏览器刷新 Session Token

        使用常驻 tab 获取新的 __Secure-next-auth.session-token

        Args:
            token_id: Token ID
            token: Token 对象

        Returns:
            新的 ST 字符串，如果失败返回 None
        """
        browser_attempt_started = False
        try:
            from ..core.config import config

            protocol_st = await self._try_protocol_refresh_st(token_id, token)
            if protocol_st:
                return protocol_st
            protocol_error = self._last_st_refresh_error.get(token_id)
            if protocol_error and not self._is_authentication_failure(protocol_error):
                return None

            # 仅在 personal 模式下支持 ST 自动刷新
            if config.captcha_method != "personal":
                debug_logger.log_info(
                    f"[ST_REFRESH] 非 personal 模式，跳过 ST 自动刷新"
                )
                return None

            if not token.current_project_id:
                debug_logger.log_warning(
                    f"[ST_REFRESH] Token {token_id} 没有 project_id，无法刷新 ST"
                )
                return None

            debug_logger.log_info(
                f"[ST_REFRESH] Token {token_id}: 尝试通过浏览器刷新 ST..."
            )
            browser_attempt_started = True
            await self._audit(
                token_id, "refresh_st", "started", "refresh_started", stage="ST_REFRESH", token=token,
            )

            from .browser_captcha_personal import BrowserCaptchaService

            service = await BrowserCaptchaService.get_instance(self.db)

            refresh_timeout_seconds = 45.0
            try:
                new_st = await asyncio.wait_for(
                    service.refresh_session_token(token.current_project_id),
                    timeout=refresh_timeout_seconds,
                )
            except asyncio.TimeoutError:
                self._last_st_refresh_error[token_id] = self._safe_health_error(
                    "ST_REFRESH", "browser refresh timeout"
                )
                debug_logger.log_error(
                    f"[ST_REFRESH] Token {token_id}: 刷新 ST 超时 ({refresh_timeout_seconds:.0f}s)"
                )
                record_token_refresh("st", "failure")
                await self._audit(
                    token_id, "refresh_st", "failed", "timeout", stage="ST_REFRESH", token=token,
                )
                return None
            if new_st and new_st != token.st:
                self._last_st_refresh_error.pop(token_id, None)
                # 更新数据库中的 ST
                await self.db.update_token(token_id, st=new_st)
                debug_logger.log_info(f"[ST_REFRESH] Token {token_id}: ST 已自动更新")
                record_token_refresh("st", "success")
                await self._audit(
                    token_id, "refresh_st", "success", "browser_session_refreshed", stage="ST_REFRESH", token=token,
                    details={"credential_changed": True},
                )
                return new_st
            elif new_st == token.st:
                debug_logger.log_warning(
                    f"[ST_REFRESH] Token {token_id}: 获取到的 ST 与原 ST 相同，可能登录已失效"
                )
                record_token_refresh("st", "failure")
                await self._audit(
                    token_id, "refresh_st", "failed", "session_token_unchanged", stage="ST_REFRESH", token=token,
                    details={"credential_changed": False},
                )
                return None
            else:
                self._last_st_refresh_error[token_id] = self._safe_health_error(
                    "ST_REFRESH", "browser returned no session token"
                )
                debug_logger.log_warning(
                    f"[ST_REFRESH] Token {token_id}: 无法获取新 ST"
                )
                record_token_refresh("st", "failure")
                await self._audit(
                    token_id, "refresh_st", "failed", "session_token_unavailable", stage="ST_REFRESH", token=token,
                )
                return None

        except asyncio.CancelledError:
            if browser_attempt_started:
                await self._audit(
                    token_id, "refresh_st", "failed", "operation_cancelled", stage="ST_REFRESH", token=token,
                )
            raise
        except Exception as e:
            reason = self._safe_health_error("ST_REFRESH", e)
            self._last_st_refresh_error[token_id] = reason
            debug_logger.log_error(
                f"[ST_REFRESH] Token {token_id}: {reason}"
            )
            record_token_refresh("st", "failure")
            if browser_attempt_started:
                await self._audit(
                    token_id, "refresh_st", "failed", account_error_reason(reason), stage="ST_REFRESH", token=token,
                )
            return None

    async def _refresh_protocol_token(self, token: Token, now: datetime) -> None:
        token_id = int(token.id)
        refresh_lock = await self._get_token_lock(
            self._refresh_locks,
            self._refresh_lock_guard,
            token_id,
        )
        async with refresh_lock:
            latest = await self.db.get_token(token_id)
            if not latest or not latest.is_active:
                return
            if not latest.auto_refresh_enabled:
                return
            if self._normalize_protocol_mode(latest.protocol_mode) != "protocol":
                return
            if not (latest.google_cookies or "").strip():
                return

            await self._audit(
                token_id, "protocol_refresh", "started", "refresh_started", stage="PROTOCOL_REFRESH",
                source="protocol_refresh", token=latest,
            )
            new_st = await self._try_protocol_refresh_st(token_id, latest, source="protocol_refresh")
            if not new_st:
                await self._audit(
                    token_id, "protocol_refresh", "failed", "protocol_refresh_failed", stage="PROTOCOL_REFRESH",
                    source="protocol_refresh", token=latest,
                    details={"retry_reason": account_error_reason(self._last_st_refresh_error.get(token_id))},
                )
                return

            self._clear_at_validation_cache(token_id)
            try:
                session = await self._st_to_at_for_token(latest, new_st)
                new_at = str(session.get("access_token") or "").strip()
                if not new_at:
                    raise RuntimeError("ST 转 AT 响应缺少 access_token")

                updates: Dict[str, Any] = {
                    "st": new_st,
                    "at": new_at,
                    "at_expires": self._parse_at_expires(session.get("expires")),
                    "last_st_refresh_at": now,
                    "last_st_refresh_result": "success",
                }
                user_info = (
                    session.get("user") if isinstance(session.get("user"), dict) else {}
                )
                if user_info.get("email"):
                    updates["email"] = user_info.get("email")
                if user_info.get("name"):
                    updates["name"] = user_info.get("name")

                credits_result = await self._get_credits_for_token(latest, new_at)
                updates["credits"] = credits_result.get("credits", 0)
                updates["user_paygate_tier"] = credits_result.get("userPaygateTier")

                await self.db.update_token(token_id, **updates)
                await self._audit(
                    token_id, "protocol_refresh", "success", "credentials_validated", stage="PROTOCOL_REFRESH",
                    source="protocol_refresh", details={"credits": updates["credits"]},
                )
                await self._persist_health(token_id, None)
                self._mark_at_valid(
                    token_id, proxy_url=latest.proxy_url,
                    token=latest.model_copy(update={"st": new_st, "at": new_at}),
                )
                self._last_at_refresh_error.pop(token_id, None)
                record_token_refresh("at", "success")
                debug_logger.log_info(
                    f"[PROTOCOL_REFRESH] Token {token_id}: 协议刷新 ST/AT 成功"
                )
            except Exception as e:
                reason = self._safe_health_error("PROTOCOL_REFRESH", e)
                await self._record_at_failure(
                    token_id, reason, error=e,
                    token=latest.model_copy(update={"st": new_st}),
                )
                await self.db.update_token(
                    token_id,
                    st=new_st,
                    last_st_refresh_at=now,
                    last_st_refresh_result=reason,
                )
                await self._audit(
                    token_id, "protocol_refresh", "failed", account_error_reason(reason),
                    stage="PROTOCOL_REFRESH", source="protocol_refresh", token=latest,
                )
                record_token_refresh("at", "failure")
                debug_logger.log_error(
                    f"[PROTOCOL_REFRESH] Token {token_id}: {reason}"
                )

    async def run_protocol_refresh_once(self) -> None:
        """Refresh protocol-mode tokens whose ST refresh interval is due."""
        try:
            refresh_config = await self.db.get_token_refresh_config()
        except Exception as e:
            debug_logger.log_warning(f"[PROTOCOL_REFRESH] 读取刷新配置失败: {e}")
            await self._audit(
                None, "protocol_refresh", "failed", "protocol_refresh_failed", stage="settings",
                source="protocol_refresh", details={"retry_reason": account_error_reason(e)},
            )
            return

        if not refresh_config or not refresh_config.enabled:
            return

        tokens = await self.db.get_active_tokens()
        now = datetime.now(timezone.utc)
        for token in tokens:
            try:
                if not token.auto_refresh_enabled:
                    continue
                if self._normalize_protocol_mode(token.protocol_mode) != "protocol":
                    continue
                if not (token.google_cookies or "").strip():
                    continue

                interval_minutes = (
                    token.refresh_interval_minutes
                    or refresh_config.refresh_interval_minutes
                    or 120
                )
                interval_minutes = self._normalize_refresh_interval(interval_minutes)
                last_refresh = self._as_utc(token.last_st_refresh_at)
                if last_refresh and now - last_refresh < timedelta(
                    minutes=interval_minutes
                ):
                    continue

                context = account_operation_source.set("protocol_refresh")
                try:
                    await self._refresh_protocol_token(token, now)
                finally:
                    account_operation_source.reset(context)
            except Exception as e:
                await self._audit(
                    token.id, "protocol_refresh", "failed", "protocol_refresh_failed", stage="PROTOCOL_REFRESH",
                    source="protocol_refresh", token=token,
                    details={"retry_reason": account_error_reason(e)},
                )
                debug_logger.log_error(
                    f"[PROTOCOL_REFRESH] Token {getattr(token, 'id', '?')}: 后台刷新异常 - {e}"
                )

    async def _protocol_refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(60)
            try:
                await self.run_protocol_refresh_once()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                debug_logger.log_error(f"[PROTOCOL_REFRESH] 后台任务异常 - {e}")

    def start_protocol_refresher(self) -> None:
        if self._protocol_refresher_task and not self._protocol_refresher_task.done():
            return
        self._protocol_refresher_task = asyncio.create_task(
            self._protocol_refresh_loop()
        )

    async def stop_protocol_refresher(self) -> None:
        task = self._protocol_refresher_task
        self._protocol_refresher_task = None
        if not task or task.done():
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception as e:
            debug_logger.log_warning(f"[PROTOCOL_REFRESH] 停止后台任务时出错: {e}")

    async def ensure_project_exists(self, token_id: int) -> str:
        """Ensure a token has a pooled set of projects and return one in round-robin order."""
        project_lock = await self._get_token_lock(
            self._project_locks,
            self._project_lock_guard,
            token_id,
        )
        async with project_lock:
            token = await self.db.get_token(token_id)
            if not token:
                raise ValueError("Token not found")

            try:
                projects = [
                    project
                    for project in await self.db.get_projects_by_token(token_id)
                    if project.is_active
                ]
                projects = self._sort_projects(projects)
            except Exception as error:
                await self._audit(
                    token_id, "project", "failed", "project_creation_failed", stage="project", token=token,
                    details={"retry_reason": account_error_reason(error)},
                )
                raise

            try:
                project_pool_size = self._get_project_pool_size()
                while len(projects) < project_pool_size:
                    new_project = await self._create_project_for_token(
                        token, len(projects) + 1, audit_failure=False,
                    )
                    projects.append(new_project)
                    projects = self._sort_projects(projects)

                selectable_projects = projects[:project_pool_size]
                selected_project = self._select_next_project(token, selectable_projects)
                await self.db.update_token(
                    token_id,
                    current_project_id=selected_project.project_id,
                    current_project_name=selected_project.project_name,
                )
                await self._audit(token_id, "project", "success", "project_selected", stage="project")
                return selected_project.project_id
            except Exception as e:
                await self._audit(
                    token_id, "project", "failed", "project_creation_failed", stage="project", token=token,
                    details={"retry_reason": account_error_reason(e)},
                )
                raise ValueError(f"Failed to prepare project pool: {str(e)}")

    async def record_usage(self, token_id: int, is_video: bool = False):
        """Record token usage"""
        await self.db.update_token(token_id, use_count=1, last_used_at=datetime.now())

        if is_video:
            await self.db.increment_token_stats(token_id, "video")
        else:
            await self.db.increment_token_stats(token_id, "image")

    async def record_error(self, token_id: int):
        """Record token error and auto-disable if threshold reached"""
        await self.db.increment_token_stats(token_id, "error")

        # Check if should auto-disable token (based on consecutive errors)
        stats = await self.db.get_token_stats(token_id)
        admin_config = await self.db.get_admin_config()
        await self._audit(
            token_id, "generation", "failed", "operation_failed", source="generation",
            details={"consecutive_error_count": stats.consecutive_error_count if stats else 0,
                     "threshold": admin_config.error_ban_threshold},
        )

        if stats and stats.consecutive_error_count >= admin_config.error_ban_threshold:
            debug_logger.log_warning(
                f"[TOKEN_BAN] Token {token_id} consecutive error count ({stats.consecutive_error_count}) "
                f"reached threshold ({admin_config.error_ban_threshold}), auto-disabling"
            )
            await self.disable_token(
                token_id, reason="consecutive_errors",
                details={"consecutive_error_count": stats.consecutive_error_count, "threshold": admin_config.error_ban_threshold},
            )

    async def record_success(self, token_id: int):
        """Record successful request (reset consecutive error count)

        This method resets error_count to 0, which is used for auto-disable threshold checking.
        Note: today_error_count and historical statistics are NOT reset.
        """
        await self.db.reset_error_count(token_id)
        await self._audit(token_id, "generation", "success", "completed", source="generation")

    async def ban_token_for_429(self, token_id: int):
        """因429错误立即禁用token

        Args:
            token_id: Token ID
        """
        debug_logger.log_warning(
            f"[429_BAN] 禁用Token {token_id} (原因: 429 Rate Limit)"
        )
        await self.db.update_token(
            token_id,
            is_active=False,
            ban_reason="429_rate_limit",
            banned_at=datetime.now(timezone.utc),
        )
        await self._audit(token_id, "disable", "disabled", "rate_limit", stage="account_state")

    async def auto_unban_429_tokens(self):
        """自动解禁因429被禁用的token

        规则:
        - 距离禁用时间12小时后自动解禁
        - 仅解禁未过期的token
        - 仅解禁因429被禁用的token
        """
        all_tokens = await self.db.get_all_tokens()
        now = datetime.now(timezone.utc)

        for token in all_tokens:
            # 跳过非429禁用的token
            if token.ban_reason != "429_rate_limit":
                continue

            # 跳过未禁用的token
            if token.is_active:
                continue

            # 跳过没有禁用时间的token
            if not token.banned_at:
                continue

            # 检查token是否已过期
            if token.at_expires:
                # 确保时区一致
                if token.at_expires.tzinfo is None:
                    at_expires_aware = token.at_expires.replace(tzinfo=timezone.utc)
                else:
                    at_expires_aware = token.at_expires

                # 如果已过期，跳过
                if at_expires_aware <= now:
                    debug_logger.log_info(
                        f"[AUTO_UNBAN] Token {token.id} 已过期，跳过解禁"
                    )
                    continue

            # 确保banned_at时区一致
            if token.banned_at.tzinfo is None:
                banned_at_aware = token.banned_at.replace(tzinfo=timezone.utc)
            else:
                banned_at_aware = token.banned_at

            # 检查是否已过12小时
            time_since_ban = now - banned_at_aware
            if time_since_ban.total_seconds() >= 12 * 3600:  # 12小时
                debug_logger.log_info(
                    f"[AUTO_UNBAN] 解禁Token {token.id} (禁用时间: {banned_at_aware}, "
                    f"已过 {time_since_ban.total_seconds() / 3600:.1f} 小时)"
                )
                await self.db.update_token(
                    token.id, is_active=True, ban_reason=None, banned_at=None
                )
                # 重置错误计数
                await self.db.reset_error_count(token.id)
                await self._audit(
                    token.id, "enable", "enabled", "cooldown_elapsed", stage="account_state", source="scheduler", token=token,
                )

    # ========== 余额刷新 ==========

    async def refresh_credits(self, token_id: int) -> int:
        """刷新Token余额

        Returns:
            credits

        Raises:
            ValueError: 账号不存在
            RuntimeError: 账号已禁用，或校验/查询失败；消息为安全的失败类别，
                不会把失败伪装成余额 0
        """
        token = await self.db.get_token(token_id)
        if not token:
            raise ValueError("Token不存在")
        if not token.is_active:
            raise RuntimeError("account disabled")

        # 确保AT有效
        valid = await self.ensure_valid_token(token)
        if not valid:
            raise RuntimeError(
                self.get_last_validation_error(token_id) or "account credentials unavailable"
            )

        try:
            result = await self._get_credits_for_token(valid, valid.at)
        except Exception as e:
            reason = self._safe_health_error("AT_CHECK", e)
            debug_logger.log_error(
                f"Failed to refresh credits for token {token_id}: {reason}"
            )
            await self._record_at_failure(token_id, reason, error=e, token=valid)
            raise RuntimeError(reason) from e

        credits = result.get("credits", 0)
        await self.db.update_token(
            token_id,
            credits=credits,
            user_paygate_tier=result.get("userPaygateTier"),
        )
        await self._persist_health(token_id, None)
        await self._audit(
            token_id, "refresh_credits", "success", "balance_refreshed", stage="credits", token=valid,
            details={"credits": credits},
        )
        return credits
