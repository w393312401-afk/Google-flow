"""Manual credential recovery through the existing fixed AdsPower login bridge.

The bridge owns browser admission and login credentials. This service only accepts
the exact live session proved by that bridge, then runs the existing guarded sync.
Private configuration, cookies and upstream exception text never enter responses.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import math
from pathlib import Path
import re
import uuid
from datetime import datetime, timezone

import httpx
from ..core.account_admission import AccountAdmissionBusy


_MESSAGES = {
    "token_not_found": "账号不存在",
    "login_not_configured": "此账号尚未接入 Flow2API 自动登录刷新，请检查账号与 AdsPower 环境的绑定",
    "login_binding_mismatch": "账号与 AdsPower 环境的固定绑定发生变化，请检查绑定后重试",
    "login_proxy_mismatch": "账号代理与固定环境不匹配，请检查代理后重试",
    "generation_busy": "账号生成任务或浏览器操作尚未结束，请等待结束后再刷新凭证",
    "queue_paused": "浏览器任务队列已暂停，请恢复后再刷新凭证",
    "busy_state_unknown": "无法确认浏览器是否空闲，请稍后重试",
    "already_running": "此账号正在刷新凭证，请稍后再试",
    "login_cancelled": "自动登录已取消，请稍后重试",
    "login_timeout": "自动登录超时，请稍后重试",
    "login_host_unavailable": "自动登录服务暂时不可用，请稍后重试",
    "login_credentials_missing": "对应环境未配置完整登录凭证，请补充后重试",
    "login_credentials_blocked": "自动登录暂时受限，请检查对应环境的登录凭证",
    "login_captcha_required": "Google 要求验证码，请在对应 AdsPower 环境完成验证后重试",
    "login_device_confirmation": "Google 要求设备确认，请在对应 AdsPower 环境完成确认后重试",
    "login_identity_unverifiable": "无法确认登录账号，请在对应 AdsPower 环境检查登录状态",
    "login_wrong_password": "Google 登录密码被拒绝，请更新对应环境的登录凭证",
    "login_wrong_totp": "Google 动态验证码被拒绝，请检查对应环境的验证配置",
    "login_wrong_email": "登录账号不符合固定绑定，请检查对应环境的账号",
    "login_challenge_unsupported": "Google 要求额外验证，请在对应 AdsPower 环境完成验证后重试",
    "login_identity_mismatch": "实际登录账号与绑定账号不一致，未保存凭证",
    "login_credits_unverifiable": "无法验证真实账号余额，未保存凭证，请稍后重试",
    "login_browser_unavailable": "对应 AdsPower 环境暂时不可用，请检查浏览器后重试",
    "login_worker_failed": "自动登录未完成，请检查对应 AdsPower 环境后重试",
    "login_internal_error": "自动登录结果无法确认，未保存凭证，请稍后重试",
    "credential_sync_failed": "真实凭证同步未完成，请稍后重试",
}
_BUSY_CODES = {"generation_busy", "queue_paused", "busy_state_unknown", "already_running"}
_UNAVAILABLE_CODES = {
    "login_cancelled", "login_timeout", "login_host_unavailable",
    "login_browser_unavailable", "login_worker_failed", "login_internal_error",
    "credential_sync_failed",
}
_SYNC_CODES = {
    "config_binding_changed": "login_binding_mismatch",
    "token_binding_changed": "login_binding_mismatch",
    "bound_account_missing": "login_binding_mismatch",
    "account_binding_mismatch": "login_binding_mismatch",
    "account_identity_ambiguous": "login_binding_mismatch",
    "profile_identity_ambiguous": "login_binding_mismatch",
    "profile_changed_during_sync": "login_binding_mismatch",
    "account_changed_during_sync": "login_binding_mismatch",
    "account_flags_changed": "login_binding_mismatch",
    "profile_proxy_changed": "login_proxy_mismatch",
    "account_proxy_mismatch": "login_proxy_mismatch",
    "account_proxy_invalid": "login_proxy_mismatch",
    "profile_proxy_invalid": "login_proxy_mismatch",
    "profile_proxy_unknown": "login_proxy_mismatch",
    "google_identity_mismatch": "login_identity_mismatch",
    "google_credit_validation_failed": "login_credits_unverifiable",
    "google_session_requires_attention": "login_identity_unverifiable",
    "flow_busy_check_unavailable": "busy_state_unknown",
    "spark_inventory_incomplete": "busy_state_unknown",
    "spark_task_state_unknown": "busy_state_unknown",
    "spark_lease_inventory_invalid": "busy_state_unknown",
    "profile_inactive": "login_browser_unavailable",
    "profile_cookie_source_invalid": "login_browser_unavailable",
    "identity_validation_unavailable": "login_host_unavailable",
}


class CredentialRecoveryError(Exception):
    """Only a fixed code and a fixed safe message may leave the service."""

    def __init__(self, code):
        self.code = code if isinstance(code, str) and code in _MESSAGES else "login_internal_error"
        self.message = _MESSAGES[self.code]
        self.status_code = (404 if self.code == "token_not_found" else
                            409 if self.code in _BUSY_CODES else
                            503 if self.code in _UNAVAILABLE_CODES else 422)
        super().__init__(self.code)


class CredentialRecovery:
    def __init__(self, manager, *, root=None):
        self.manager = manager
        self.root = Path(root or Path(__file__).resolve().parents[2])
        self._running = {}

    async def recover(self, token_id):
        """Coalesce clicks, including a caller disconnecting mid-login."""
        task = self._running.get(token_id)
        if task is None:
            async def run():
                try:
                    await self.manager._audit(token_id, "auto_login", "started", "login_requested", stage="recovery")
                    result = await self._recover_locked(token_id)
                    await self.manager._audit(token_id, "auto_login", "success", "credentials_validated", stage="result")
                    return result
                except Exception as exc:
                    code = exc.code if isinstance(exc, CredentialRecoveryError) else "login_internal_error"
                    await self.manager._audit(token_id, "auto_login", "failed", code, stage="result")
                    raise CredentialRecoveryError(code) from None
                finally:
                    self._running.pop(token_id, None)

            task = asyncio.create_task(run())
            # Retrieve detached failures if an HTTP caller goes away while the
            # guarded host still owns its lease. The next caller can join it.
            task.add_done_callback(lambda finished: None if finished.cancelled() else finished.exception())
            self._running[token_id] = task
        return await asyncio.shield(task)

    async def _recover_locked(self, token_id):
        # Reserve before validation locks: generation also acquires admission
        # before validating, so the lock order cannot form a wait cycle.
        admission = self.manager.account_admission
        try:
            with admission.maintenance(token_id) as lease:
                return await self._recover_admitted(token_id, lease.capability)
        except AccountAdmissionBusy as exc:
            raise CredentialRecoveryError(exc.reason) from None

    async def _recover_admitted(self, token_id, maintenance_capability):
        validation = await self.manager._get_token_lock(
            self.manager._validation_locks, self.manager._validation_lock_guard, token_id)
        refresh = await self.manager._get_token_lock(
            self.manager._refresh_locks, self.manager._refresh_lock_guard, token_id)
        async with validation:
            async with refresh:
                if await self.manager.get_token(token_id) is None:
                    raise CredentialRecoveryError("token_not_found")
                try:
                    sync, pool = self._load_bridge()
                    path, config = await self._binding(sync, pool, token_id)
                    config_hash = sync.digest(config)
                    async with httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=30) as client:
                        host_gateway = sync.Gateway(config, client, {})
                        host_gateway.maintenance_capability = maintenance_capability
                        proof = await host_gateway.recover_login()
                        self._check_proof(proof, token_id)
                        # The host has released its account lock; take that same
                        # lock before checking the live source and accepting it.
                        with sync.process_lock(path.with_suffix(".lock")):
                            latest_path, latest_config = await self._binding(sync, pool, token_id)
                            if latest_path != path or sync.digest(latest_config) != config_hash:
                                raise CredentialRecoveryError("login_binding_mismatch")
                            state_path = path.with_name(path.stem + ".state.json")
                            state = pool._read_private(state_path)
                            # Manual recovery validates the live source afresh.
                            # Saved caches/backoffs stay on disk untouched.
                            state = {key: value for key, value in state.items() if key not in {
                                "validated_hash", "validated_at", "validated_proxy_hash",
                                "auth_failed_hash", "auth_failed_proxy_hash", "auth_retry_after",
                                "auth_failed_reason", "network_retry_after",
                            }}
                            gateway = self._gateway(sync, config, client, proof, path, config_hash, state)
                            gateway.maintenance_capability = maintenance_capability
                            manual_config = dict(config, disable_below_credits=None)
                            result = await sync.synchronize(
                                manual_config, state, gateway, validator=gateway.validate)
                            if (not isinstance(result, dict) or result.get("token_id") != token_id
                                    or result.get("status") not in {"updated", "unchanged"}):
                                reason = result.get("reason") if isinstance(result, dict) else None
                                raise CredentialRecoveryError(_SYNC_CODES.get(reason, reason))
                            # An unchanged Cookie can still have a rejected AT;
                            # a manual recovery always renews and checks it.
                            if result["status"] == "unchanged":
                                await gateway.write(token_id, {"auto_enable_on_update": False})
                        browser_closed = None
                        if "opened_browser_hash" in proof:
                            try:
                                browser_closed = await gateway.close_recovered_browser(proof, path)
                            except Exception:
                                browser_closed = False
                                await self.manager._audit(token_id, "auto_login", "deferred",
                                    "browser_close_deferred", stage="browser_close")
                    current = await self.manager.get_token(token_id)
                    response = {"success": True, "code": "credentials_recovered", "message": "已自动登录并验证真实凭证",
                            "token": {"id": token_id, "at_expires": current.at_expires.isoformat() if current.at_expires else None,
                                      "credits": current.credits}}
                    if browser_closed is not None:
                        response['browser_closed'] = browser_closed
                    return response
                except CredentialRecoveryError:
                    raise
                except Exception as exc:
                    reason = getattr(exc, "reason", None)
                    raise CredentialRecoveryError(_SYNC_CODES.get(reason, reason) or "credential_sync_failed") from None

    def _load_bridge(self):
        modules = []
        for filename in ("sync_adspower_cookies.py", "sync_adspower_cookie_pool.py"):
            path = self.root / "local" / filename
            if not path.is_file() or path.is_symlink():
                raise CredentialRecoveryError("login_not_configured")
            spec = importlib.util.spec_from_file_location("_credential_recovery_" + uuid.uuid4().hex, path)
            if spec is None or spec.loader is None:
                raise CredentialRecoveryError("login_not_configured")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            modules.append(module)
        return tuple(modules)

    async def _binding(self, sync, pool, token_id):
        try:
            paths = pool._manifest_paths(pool.LOCAL / "adspower-cookie-pool.json")
            records = [(path, sync.validate_config(pool._read_private(path))) for path in paths]
        except Exception:
            raise CredentialRecoveryError("login_not_configured") from None
        for key in ("profile_id", "expected_email", "token_id"):
            values = [config.get(key) for _, config in records]
            if None in values or len(set(values)) != len(values):
                raise CredentialRecoveryError("login_binding_mismatch")
        matches = [(path, config) for path, config in records if config["token_id"] == token_id]
        if len(matches) != 1 or matches[0][1].get("allow_pool_login") is not True:
            raise CredentialRecoveryError("login_not_configured")
        path, config = matches[0]
        configured_db = Path(config.get("flow_db_path", self.root / "data/flow.db")).resolve()
        if configured_db != Path(self.manager.db.db_path).resolve():
            raise CredentialRecoveryError("login_binding_mismatch")
        tokens = [token.model_dump(mode="json") for token in await self.manager.get_all_tokens()]
        target = sync.find_binding(tokens, config, {})
        if target is None or target["id"] != token_id:
            raise CredentialRecoveryError("login_binding_mismatch")
        return path, config

    @staticmethod
    def _check_proof(proof, token_id):
        if not isinstance(proof, dict):
            raise CredentialRecoveryError("login_internal_error")
        if proof.get("status") != "ok" or proof.get("reason") != "login_verified":
            raise CredentialRecoveryError(proof.get("reason"))
        if (type(proof.get("token_id")) is not int or proof["token_id"] != token_id
                or any(not isinstance(proof.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", proof[key])
                       for key in ("verified_cookie_hash", "verified_proxy_hash"))):
            raise CredentialRecoveryError("login_internal_error")
        if ("verified_session_hash" in proof and
                (not isinstance(proof["verified_session_hash"], str) or
                 not re.fullmatch(r"[0-9a-f]{64}", proof["verified_session_hash"]))):
            raise CredentialRecoveryError("login_internal_error")
        if ("opened_browser_hash" in proof and
                (not isinstance(proof["opened_browser_hash"], str) or
                 not re.fullmatch(r"[0-9a-f]{64}", proof["opened_browser_hash"]))):
            raise CredentialRecoveryError("login_internal_error")

    @staticmethod
    def _session_matches(sync, cookies, proof):
        if "verified_session_hash" in proof:
            return sync.auth_session_hash(cookies) == proof["verified_session_hash"]
        return sync.auth_hash(cookies) == proof["verified_cookie_hash"]

    def _gateway(self, sync, config, client, proof, config_path, config_hash, state):
        service = self
        token_id = config["token_id"]

        class LiveGateway(sync.Gateway):
            async def profile(self):
                profile = await super().profile()
                if profile.get("source") != "cdp":
                    raise CredentialRecoveryError("login_browser_unavailable")
                signature = (profile.get("ws"), sync.proxy_identity(profile.get("proxy")))
                previous = getattr(self, "_recovery_source", signature)
                if signature != previous:
                    raise CredentialRecoveryError("login_binding_mismatch")
                self._recovery_source = signature
                return profile

            async def tokens(self):
                return [token.model_dump(mode="json") for token in await service.manager.get_all_tokens()]

            async def validate(self, cookies, expected_email, proxy_url):
                if (expected_email != config["expected_email"]
                        or not service._session_matches(sync, cookies, proof)
                        or sync.validation_proxy_hash(proxy_url) != proof["verified_proxy_hash"]):
                    raise sync.SyncError("account_changed_during_sync")
                return await sync.validate_identity(cookies, expected_email, proxy_url)

            async def write(self, target_id, payload):
                if (target_id != token_id or set(payload) - {"auto_enable_on_update", "google_cookies"}
                        or payload.get("auto_enable_on_update") is not False):
                    raise CredentialRecoveryError("login_binding_mismatch")
                before = await service.manager.get_token(token_id)
                if before is None:
                    raise CredentialRecoveryError("login_binding_mismatch")
                raw_cookies = payload.get("google_cookies", before.google_cookies)
                cookies = json.loads(raw_cookies)
                candidate = before.model_copy(update={"google_cookies": raw_cookies})
                source = await self.profile()
                proxy = sync.validation_proxy_uri(sync.authorized_target_proxy(
                    candidate.model_dump(mode="json"), source["proxy"], config),
                    config.get("remote_dns", False))
                await sync.verified_session(self.validate, cookies, config["expected_email"], proxy)
                # Use the same proven effective route for both requests while
                # leaving the account's empty/global proxy overrides intact.
                routed_candidate = candidate.model_copy(update={"proxy_url": proxy})
                converted = await service.manager._st_to_at_for_token(routed_candidate, candidate.st)
                access_token = converted.get("access_token")
                expires = service.manager._parse_at_expires(converted.get("expires"))
                credits = await service.manager._get_credits_for_token(routed_candidate, access_token)
                balance = credits.get("credits")
                if (not isinstance(access_token, str) or not access_token or expires is None
                        or service.manager._as_utc(expires) <= datetime.now(timezone.utc)
                        or type(balance) not in (int, float) or not math.isfinite(balance)
                        or not 0 <= balance < 10**12):
                    raise CredentialRecoveryError("login_credits_unverifiable")
                # Reject account/source edits during upstream validation before
                # committing any credentials, balance, health or enable flags.
                current = await service.manager.get_token(token_id)
                fields = (*sync.PRESERVED_ACCOUNT_FIELDS, "at", "at_expires")
                if current is None or any(getattr(current, key) != getattr(before, key) for key in fields):
                    raise CredentialRecoveryError("login_binding_mismatch")
                if sync.digest(sync.validate_config(sync.private_json(config_path))) != config_hash:
                    raise CredentialRecoveryError("login_binding_mismatch")
                profile = await self.profile()
                sync.find_binding(await self.tokens(), config, state)
                if (state.get("proxy_hash") not in sync.source_proxy_hashes(profile["proxy"])
                        or not service._session_matches(sync, await self.cookies(profile), proof)
                        or sync.validation_proxy_hash(sync.validation_proxy_uri(
                            sync.authorized_target_proxy(current.model_dump(mode="json"), profile["proxy"], config),
                            config.get("remote_dns", False))) != proof["verified_proxy_hash"]):
                    raise CredentialRecoveryError("login_binding_mismatch")
                busy, flow_active = await self.busy(token_id)
                if busy or flow_active:
                    raise CredentialRecoveryError("generation_busy")
                committed = await service.manager.db.commit_recovered_credentials(
                    before, google_cookies=raw_cookies, at=access_token, at_expires=expires,
                    credits=balance, user_paygate_tier=credits.get("userPaygateTier"))
                if not committed:
                    raise CredentialRecoveryError("login_binding_mismatch")
                service.manager._clear_at_validation_cache(token_id)
                for cache in (service.manager._last_at_refresh_error, service.manager._last_st_refresh_error,
                              service.manager._last_validation_error, service.manager._validation_retry_after,
                              service.manager._protocol_retry_after):
                    cache.pop(token_id, None)

        gateway = LiveGateway(dict(config, allow_saved_cookies=False), client, {})
        gateway._recovery_binding_config = dict(config)
        return gateway
