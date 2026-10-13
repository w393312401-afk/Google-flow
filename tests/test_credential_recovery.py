"""Offline manual recovery tests using the real guarded sync and fake transports."""

import asyncio
import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
import httpx

from src.api import admin
from src.core.models import Token
from src.core.database import Database
from src.services.credential_recovery import CredentialRecovery, CredentialRecoveryError
from src.services.token_manager import TokenManager


ROOT = Path(__file__).resolve().parents[1]
EMAIL = "synthetic@example.test"


def load_local(name):
    spec = importlib.util.spec_from_file_location("manual_recovery_test_" + name, ROOT / "local" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MemoryDatabase:
    def __init__(self, path, token):
        self.db_path = str(path)
        self.rows = {token.id: token.model_copy(deep=True)}
        self.writes = []
        self.health = {token.id: "AT_VERIFY: credentials rejected"}

    async def get_token(self, token_id):
        token = self.rows.get(token_id)
        return token.model_copy(deep=True) if token is not None else None

    async def get_all_tokens(self):
        return [token.model_copy(deep=True) for token in self.rows.values()]

    async def update_token(self, token_id, **fields):
        self.writes.append(copy.deepcopy(fields))
        self.rows[token_id] = self.rows[token_id].model_copy(update=fields)

    async def clear_token_health(self, token_id):
        self.health.pop(token_id, None)

    async def commit_recovered_credentials(self, expected, **fields):
        ignored = {"created_at", "last_used_at", "use_count", "credits", "user_paygate_tier",
                   "last_st_refresh_at", "last_st_refresh_result"}
        current = self.rows.get(expected.id)
        if current is None or any(getattr(current, key) != getattr(expected, key)
                                  for key in Token.model_fields if key not in ignored):
            return False
        await self.update_token(expected.id, **fields)
        await self.clear_token_health(expected.id)
        return True


class CredentialRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.local = self.root / "local"
        self.local.mkdir()
        self.sync = load_local("sync_adspower_cookies")
        self.pool = load_local("sync_adspower_cookie_pool")
        self.pool.LOCAL = self.local
        self.pool.ROOT = self.root
        self.cookies = [{"name": "SID", "value": "SYNTHETIC_FRESH_COOKIE", "domain": ".google.com",
                         "path": "/", "secure": True}]
        old_cookies = [dict(self.cookies[0], value="SYNTHETIC_OLD_COOKIE")]
        self.token = Token(id=7, st="SYNTHETIC_ST", at="SYNTHETIC_OLD_AT", email=EMAIL,
                           login_account=EMAIL, remark="adspower-sync:one", protocol_mode="protocol",
                           google_cookies=json.dumps(old_cookies), is_active=False,
                           image_enabled=False, video_enabled=True, ban_reason="authentication_failed",
                           at_expires=datetime(2020, 1, 1, tzinfo=timezone.utc), credits=12)
        self.db = MemoryDatabase(self.root / "flow.db", self.token)
        self.manager = TokenManager(self.db, SimpleNamespace())
        self.manager._audit = AsyncMock()
        self.manager._st_to_at_for_token = AsyncMock(return_value={
            "access_token": "SYNTHETIC_FRESH_AT", "expires": "2099-01-01T00:00:00Z"})
        self.manager._get_credits_for_token = AsyncMock(return_value={"credits": 89, "userPaygateTier": "Pro"})
        self.service = CredentialRecovery(self.manager, root=self.root)
        self.service._load_bridge = lambda: (self.sync, self.pool)
        self.config_path = self.local / "account.json"
        self.state_path = self.local / "account.state.json"
        self.config = dict(profile_id="one", expected_email=EMAIL, token_id=7,
                           adspower_base="http://127.0.0.1:50325", flow_base="http://127.0.0.1:38000",
                           spark_base="http://127.0.0.1:8085", allow_pool_login=True,
                           flow_db_path=self.db.db_path, disable_below_credits=1000)
        self.sync.save_private(self.config_path, self.config)
        self.sync.save_private(self.local / "adspower-cookie-pool.json", {"config_paths": ["account.json"]})
        self.state = dict(proxy_hash=self.sync.digest(self.sync.proxy_identity("")), token_id=7,
                          validated_at=10**11, auth_retry_after=10**11, network_retry_after=10**11,
                          private_test_marker="PRESERVE_STATE")
        self.sync.save_private(self.state_path, self.state)
        self.proof = dict(status="ok", reason="login_verified", token_id=7,
                          verified_cookie_hash=self.sync.auth_hash(self.cookies),
                          verified_proxy_hash=self.sync.validation_proxy_hash(""))
        self.host = self.enterContext(patch.object(self.sync.Gateway, "recover_login", AsyncMock(return_value=self.proof)))
        self.profile = self.enterContext(patch.object(self.sync.Gateway, "profile", AsyncMock(return_value={
            "source": "cdp", "ws": "ws://127.0.0.1:9222/synthetic", "proxy": ""})))
        self.source_cookies = self.enterContext(patch.object(self.sync.Gateway, "cookies", AsyncMock(return_value=self.cookies)))
        self.busy = self.enterContext(patch.object(self.sync.Gateway, "busy", AsyncMock(return_value=(False, False))))
        self.identity = self.enterContext(patch.object(self.sync, "validate_identity", AsyncMock(return_value={"email": EMAIL, "credits": 89})))

        def reject_network(request):
            raise AssertionError("The offline recovery test attempted real network access")

        original_client = httpx.AsyncClient
        self.enterContext(patch("src.services.credential_recovery.httpx.AsyncClient",
            side_effect=lambda **kwargs: original_client(transport=httpx.MockTransport(reject_network), **kwargs)))

    async def assert_rejected(self, code):
        with self.assertRaises(CredentialRecoveryError) as caught:
            await self.service.recover(7)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(self.db.writes, [])
        self.assertEqual(self.db.health[7], "AT_VERIFY: credentials rejected")
        self.assertNotIn("SYNTHETIC", caught.exception.message)

    async def test_login_then_live_sync_verifies_identity_and_credits_and_preserves_flags(self):
        result = await self.service.recover(7)
        self.host.assert_awaited_once()
        self.assertGreaterEqual(self.identity.await_count, 2)
        self.assertEqual(result, {"success": True, "code": "credentials_recovered",
            "message": "已自动登录并验证真实凭证",
            "token": {"id": 7, "at_expires": "2099-01-01T00:00:00+00:00", "credits": 89}})
        saved = await self.db.get_token(7)
        self.assertEqual(json.loads(saved.google_cookies), self.cookies)
        self.assertEqual(saved.at, "SYNTHETIC_FRESH_AT")
        self.assertEqual((saved.is_active, saved.image_enabled, saved.video_enabled), (False, False, True))
        self.assertEqual(saved.ban_reason, "authentication_failed")
        self.assertNotIn(7, self.db.health)
        self.assertNotIn("SYNTHETIC", json.dumps(result))
        self.assertEqual(self.sync.private_json(self.config_path), self.config)
        self.assertEqual(self.sync.private_json(self.state_path), self.state)

    async def test_recovery_browser_closes_only_after_committed_credentials_while_maintenance_is_held(self):
        self.proof['opened_browser_hash'] = self.sync.digest('ws://127.0.0.1:9222/synthetic')
        stages = []
        commit = self.db.commit_recovered_credentials
        admission = self.manager.account_admission

        async def committed(expected, **fields):
            stages.append('commit_started')
            closed.assert_not_awaited()
            accepted = await commit(expected, **fields)
            self.assertTrue(accepted)
            stages.append('commit_finished')
            return accepted

        async def close(proof, config_path):
            self.assertEqual(stages, ['commit_started', 'commit_finished'])
            self.assertEqual(proof, self.proof)
            self.assertEqual(config_path, self.config_path)
            saved = await self.db.get_token(7)
            self.assertEqual(saved.at, 'SYNTHETIC_FRESH_AT')
            self.assertEqual(json.loads(saved.google_cookies), self.cookies)
            self.assertNotIn(7, self.db.health)
            with self.assertRaises(admission.busy_error) as raised:
                admission.generation(7)
            self.assertEqual(raised.exception.reason, 'generation_busy')
            stages.append('browser_closed')
            return True

        with patch.object(self.db, 'commit_recovered_credentials', side_effect=committed), \
                patch.object(self.sync.Gateway, 'close_recovered_browser', AsyncMock(side_effect=close)) as closed:
            result = await self.service.recover(7)
            closed.assert_awaited_once_with(self.proof, self.config_path)
        self.assertEqual(stages, ['commit_started', 'commit_finished', 'browser_closed'])
        self.assertTrue(result['success'])
        self.assertTrue(result['browser_closed'])
        self.assertNotIn(self.proof['opened_browser_hash'], json.dumps(result))
        with admission.generation(7):
            pass

    async def test_existing_browser_proof_without_opened_hash_keeps_old_result_and_never_closes(self):
        with patch.object(self.sync.Gateway, 'close_recovered_browser', AsyncMock()) as closed:
            result = await self.service.recover(7)
            closed.assert_not_awaited()
        self.assertEqual(set(result), {'success', 'code', 'message', 'token'})
        self.assertTrue(result['success'])
        self.assertEqual(result['code'], 'credentials_recovered')

    async def test_sync_and_commit_failures_never_close_recovery_browser(self):
        self.proof['opened_browser_hash'] = 'd' * 64
        with patch.object(self.sync.Gateway, 'close_recovered_browser', AsyncMock()) as closed:
            with patch.object(self.sync, 'validate_identity', AsyncMock(return_value={'email': 'other@example.test', 'credits': 89})):
                await self.assert_rejected('login_identity_mismatch')
            with patch.object(self.db, 'commit_recovered_credentials', AsyncMock(return_value=False)):
                await self.assert_rejected('login_binding_mismatch')
            with patch.object(self.db, 'commit_recovered_credentials', AsyncMock(side_effect=RuntimeError('SYNTHETIC_DB_FAILURE'))):
                await self.assert_rejected('credential_sync_failed')
            closed.assert_not_awaited()

    async def test_cleanup_false_preserves_already_committed_credential_success(self):
        self.proof['opened_browser_hash'] = 'd' * 64
        with patch.object(self.sync.Gateway, 'close_recovered_browser', AsyncMock(return_value=False)) as closed:
            result = await self.service.recover(7)
            closed.assert_awaited_once_with(self.proof, self.config_path)
        self.assertTrue(result['success'])
        self.assertEqual(result['code'], 'credentials_recovered')
        self.assertIs(result['browser_closed'], False)
        self.assertEqual((await self.db.get_token(7)).at, 'SYNTHETIC_FRESH_AT')
        self.assertEqual(len(self.db.writes), 1)
        self.assertNotIn(7, self.db.health)

    async def test_malformed_opened_browser_proof_is_rejected_before_sync_commit_or_close(self):
        with patch.object(self.sync.Gateway, 'close_recovered_browser', AsyncMock()) as closed:
            for value in (None, 1, [], '', 'SYNTHETIC_WS_SECRET', 'D' * 64, 'd' * 63):
                with self.subTest(value=value):
                    self.proof['opened_browser_hash'] = value
                    await self.assert_rejected('login_internal_error')
            closed.assert_not_awaited()
        self.source_cookies.assert_not_awaited()
        self.manager._st_to_at_for_token.assert_not_awaited()

    async def test_current_cookie_with_future_deadline_still_renews_at_after_real_login(self):
        self.db.rows[7] = self.token.model_copy(update={"google_cookies": json.dumps(self.cookies),
            "at_expires": datetime(2090, 1, 1, tzinfo=timezone.utc)})
        await self.service.recover(7)
        self.host.assert_awaited_once()
        self.manager._st_to_at_for_token.assert_awaited_once()
        self.assertEqual(len(self.db.writes), 1)

    async def test_proven_global_route_is_used_without_saving_account_overrides(self):
        route = "http://global.example.test:8080"
        self.proof["verified_proxy_hash"] = self.sync.validation_proxy_hash(route)
        with patch.object(self.sync, "authorized_target_proxy", return_value=route):
            await self.service.recover(7)
        for request in (self.manager._st_to_at_for_token, self.manager._get_credits_for_token):
            routed_token = request.await_args.args[0]
            self.assertEqual(routed_token.proxy_url, route)
        saved = await self.db.get_token(7)
        self.assertEqual(saved.proxy_url, self.token.proxy_url)
        self.assertEqual(saved.captcha_proxy_url, self.token.captcha_proxy_url)
        self.assertNotIn("proxy_url", self.db.writes[0])

    async def test_effective_global_route_change_during_validation_prevents_commit(self):
        route = "http://global.example.test:8080"
        current_route = route
        self.proof["verified_proxy_hash"] = self.sync.validation_proxy_hash(route)

        async def changed_route(*args):
            nonlocal current_route
            current_route = "http://changed.example.test:8080"
            return {"credits": 89}

        self.manager._get_credits_for_token.side_effect = changed_route
        with patch.object(self.sync, "authorized_target_proxy", side_effect=lambda *args: current_route):
            await self.assert_rejected("login_binding_mismatch")

    async def test_busy_or_challenge_host_results_never_copy_credentials(self):
        for code in ("generation_busy", "login_captcha_required", "login_device_confirmation",
                     "login_credentials_missing", "login_credentials_blocked"):
            with self.subTest(code=code):
                self.host.return_value = {"status": "error", "reason": code, "message": "SYNTHETIC_PASSWORD"}
                await self.assert_rejected(code)
        self.source_cookies.assert_not_awaited()

    async def test_failed_host_and_malformed_proof_are_safe(self):
        self.host.side_effect = RuntimeError("SYNTHETIC_COOKIE SYNTHETIC_PASSWORD SYNTHETIC_PROXY")
        await self.assert_rejected("credential_sync_failed")
        self.host.side_effect = None
        for proof in (dict(self.proof, token_id=8), dict(self.proof, verified_cookie_hash=None),
                      {"status": "error", "reason": "SYNTHETIC_SECRET"}):
            with self.subTest(proof=proof):
                self.host.return_value = proof
                await self.assert_rejected("login_internal_error")

    async def test_no_bound_configuration_or_login_opt_in_never_calls_host(self):
        for config in (dict(self.config, token_id=8), dict(self.config, allow_pool_login=False)):
            self.sync.save_private(self.config_path, config)
            await self.assert_rejected("login_not_configured")
        self.host.assert_not_awaited()

    async def test_binding_and_database_mismatch_prevent_login(self):
        self.db.rows[7] = self.token.model_copy(update={"remark": "adspower-sync:other"})
        await self.assert_rejected("login_binding_mismatch")
        self.db.rows[7] = self.token
        self.sync.save_private(self.config_path, dict(self.config, flow_db_path=str(self.root / "other.db")))
        await self.assert_rejected("login_binding_mismatch")
        self.host.assert_not_awaited()

    async def test_wrong_live_identity_and_invalid_credit_proofs_do_not_save(self):
        for identity, code in (({"email": "other@example.test", "credits": 89}, "login_identity_mismatch"),
                               ({"email": EMAIL, "credits": None}, "login_credits_unverifiable")):
            self.identity.return_value = identity
            await self.assert_rejected(code)

    async def test_source_session_changed_after_host_proof_is_rejected(self):
        self.source_cookies.return_value = [dict(self.cookies[0], value="SYNTHETIC_OTHER_COOKIE")]
        await self.assert_rejected("login_binding_mismatch")

    async def test_sidcc_renewal_after_proof_and_before_commit_saves_fresh_verified_cookie(self):
        original = [*self.cookies, {"name": "SIDCC", "value": "SYNTHETIC_CC_0",
            "domain": ".google.com", "path": "/", "secure": True, "expires": 2000000000}]
        self.proof.update(verified_cookie_hash=self.sync.auth_hash(original),
                          verified_session_hash=self.sync.auth_session_hash(original))
        reads = []

        async def renewing(_):
            current = [*self.cookies, dict(original[-1], value=f"SYNTHETIC_CC_{len(reads)+1}",
                                           expires=2000000001+len(reads))]
            reads.append(current)
            return current

        self.source_cookies.side_effect = renewing
        await self.service.recover(7)
        saved = json.loads((await self.db.get_token(7)).google_cookies)
        self.assertEqual(saved, reads[0])
        self.assertGreaterEqual(len(reads), 2)
        self.assertGreaterEqual(self.identity.await_count, 2)

    async def test_session_hash_proof_cannot_accept_changed_primary_cookie_or_malformed_hash(self):
        self.proof["verified_session_hash"] = self.sync.auth_session_hash(self.cookies)
        self.source_cookies.return_value = [dict(self.cookies[0], value="SYNTHETIC_OTHER_COOKIE")]
        await self.assert_rejected("login_binding_mismatch")
        self.proof["verified_session_hash"] = "SYNTHETIC_NOT_A_HASH"
        await self.assert_rejected("login_internal_error")

    async def test_account_edit_during_credit_validation_is_rejected(self):
        async def edit_account(*args):
            self.db.rows[7] = self.db.rows[7].model_copy(update={"image_enabled": True})
            return {"credits": 89}

        self.manager._get_credits_for_token.side_effect = edit_account
        await self.assert_rejected("login_binding_mismatch")

    async def test_expired_missing_or_malformed_deadline_never_saves_credentials(self):
        for expiry in (None, "", "malformed", "2020-01-01T00:00:00Z", "2020-01-01T00:00:00"):
            with self.subTest(expiry=expiry):
                self.manager._st_to_at_for_token.return_value = {
                    "access_token": "SYNTHETIC_FRESH_AT", "expires": expiry}
                await self.assert_rejected("login_credits_unverifiable")

    async def test_nonfinite_or_invalid_credit_results_never_save_credentials(self):
        for balance in (None, True, -1, float("inf"), float("nan"), 10**12):
            with self.subTest(balance=balance):
                self.manager._get_credits_for_token.return_value = {"credits": balance}
                await self.assert_rejected("login_credits_unverifiable")

    async def test_source_browser_change_during_credit_validation_is_rejected(self):
        self.profile.side_effect = [
            {"source": "cdp", "ws": "ws://127.0.0.1:9222/synthetic", "proxy": ""},
            {"source": "cdp", "ws": "ws://127.0.0.1:9222/synthetic", "proxy": ""},
            {"source": "cdp", "ws": "ws://127.0.0.1:9222/other", "proxy": ""},
        ]
        await self.assert_rejected("login_binding_mismatch")

    async def test_configuration_edit_while_host_logs_in_is_rejected(self):
        async def changed_config():
            self.sync.save_private(self.config_path, dict(self.config, adspower_base="http://127.0.0.1:50326"))
            return self.proof

        self.host.side_effect = changed_config
        await self.assert_rejected("login_binding_mismatch")

    async def test_busy_after_validation_never_commits_credentials(self):
        self.busy.side_effect = [(False, False), (False, False), (True, False)]
        await self.assert_rejected("generation_busy")

    async def test_account_edit_during_last_busy_check_cannot_overwrite_new_credentials(self):
        calls = 0

        async def busy(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 3:
                self.db.rows[7] = self.db.rows[7].model_copy(update={"google_cookies": "SYNTHETIC_MANUAL_EDIT"})
            return False, False

        self.busy.side_effect = busy
        await self.assert_rejected("login_binding_mismatch")
        self.assertEqual((await self.db.get_token(7)).google_cookies, "SYNTHETIC_MANUAL_EDIT")

    async def test_same_account_requests_share_one_login_and_commit(self):
        started = asyncio.Event()
        release = asyncio.Event()

        async def host():
            started.set()
            await release.wait()
            return self.proof

        self.host.side_effect = host
        first = asyncio.create_task(self.service.recover(7))
        await asyncio.wait_for(started.wait(), 2)
        second = asyncio.create_task(self.service.recover(7))
        await asyncio.sleep(0)
        release.set()
        first_result, second_result = await asyncio.gather(first, second)
        self.assertEqual(first_result, second_result)
        self.host.assert_awaited_once()
        self.assertEqual(len(self.db.writes), 1)

    async def test_caller_disconnect_does_not_cancel_host_or_start_duplicate_login(self):
        started = asyncio.Event()
        release = asyncio.Event()

        async def host():
            started.set()
            await release.wait()
            return self.proof

        self.host.side_effect = host
        first = asyncio.create_task(self.service.recover(7))
        await asyncio.wait_for(started.wait(), 2)
        first.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await first
        second = asyncio.create_task(self.service.recover(7))
        await asyncio.sleep(0)
        release.set()
        self.assertTrue((await second)["success"])
        self.host.assert_awaited_once()
        self.assertEqual(len(self.db.writes), 1)
        self.assertEqual(self.service._running, {})

    async def test_failure_can_be_retried_after_configuration_is_fixed(self):
        self.sync.save_private(self.config_path, dict(self.config, allow_pool_login=False))
        await self.assert_rejected("login_not_configured")
        self.sync.save_private(self.config_path, self.config)
        self.assertTrue((await self.service.recover(7))["success"])


class CredentialRecoveryApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.recover = AsyncMock(return_value={"success": True, "code": "credentials_recovered", "token": {"id": 7}})
        self.enterContext(patch.object(admin, "token_manager", SimpleNamespace(recover_credentials=self.recover)))
        self.enterContext(patch.object(admin, "db", None))
        app = FastAPI()
        app.include_router(admin.router)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://offline.test")
        self.addAsyncCleanup(self.client.aclose)
        self.session = "synthetic-recovery-admin"
        self.enterContext(patch.object(admin, "is_admin_session_token_valid", AsyncMock(
            side_effect=lambda candidate: candidate == self.session)))

    async def test_requires_admin_auth_before_any_login(self):
        response = await self.client.post("/api/tokens/7/recover-credentials")
        self.assertEqual(response.status_code, 401)
        self.recover.assert_not_awaited()

    async def test_authenticated_request_and_safe_failure_contract(self):
        self.client.headers["Authorization"] = "Bearer " + self.session
        response = await self.client.post("/api/tokens/7/recover-credentials")
        self.assertEqual(response.status_code, 200)
        self.recover.assert_awaited_once_with(7)
        for code, status in (("generation_busy", 409), ("login_captcha_required", 422),
                             ("login_not_configured", 422), ("login_host_unavailable", 503),
                             ("token_not_found", 404)):
            self.recover.side_effect = CredentialRecoveryError(code)
            response = await self.client.post("/api/tokens/7/recover-credentials")
            self.assertEqual(response.status_code, status)
            detail = response.json()["detail"]
            self.assertEqual(detail["code"], code)
            self.assertFalse(detail["success"])
            self.assertEqual(detail["reason"], code)
            self.assertIsInstance(detail["message"], str)


class CredentialRecoveryCommitTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.db = Database(str(Path(directory.name) / "flow.db"))
        await self.db.init_db()
        token_id = await self.db.add_token(Token(st="SYNTHETIC_ST", email=EMAIL,
            login_account=EMAIL, google_cookies="SYNTHETIC_OLD_COOKIE", is_active=False,
            image_enabled=False, video_enabled=True, proxy_url="http://127.0.0.1:8080"))
        self.before = await self.db.get_token(token_id)
        await self.db.set_token_health(token_id, "AT_VERIFY: credentials rejected")
        self.fields = {"google_cookies": "SYNTHETIC_FRESH_COOKIE", "at": "SYNTHETIC_FRESH_AT",
                       "at_expires": datetime(2099, 1, 1, tzinfo=timezone.utc), "credits": 89,
                       "user_paygate_tier": "Pro"}

    async def test_commit_clears_health_and_preserves_flags_in_one_transaction(self):
        self.assertTrue(await self.db.commit_recovered_credentials(self.before, **self.fields))
        saved = await self.db.get_token(self.before.id)
        self.assertEqual((saved.is_active, saved.image_enabled, saved.video_enabled), (False, False, True))
        self.assertEqual(saved.google_cookies, "SYNTHETIC_FRESH_COOKIE")
        async with self.db._connect() as connection:
            cursor = await connection.execute("SELECT reason FROM token_health WHERE token_id = ?", (self.before.id,))
            self.assertIsNone(await cursor.fetchone())

    async def test_changed_credential_proxy_flags_or_deleted_token_reject_commit(self):
        for field, value in (("google_cookies", "SYNTHETIC_MANUAL_COOKIE"),
                             ("proxy_url", "http://127.0.0.1:8081"), ("image_enabled", True)):
            with self.subTest(field=field):
                await self.db.update_token(self.before.id, **{field: value})
                self.assertFalse(await self.db.commit_recovered_credentials(self.before, **self.fields))
                saved = await self.db.get_token(self.before.id)
                self.assertEqual(getattr(saved, field), value)
                self.assertEqual(saved.at, self.before.at)
                await self.db.update_token(self.before.id, **{field: getattr(self.before, field)})
        await self.db.delete_token(self.before.id)
        self.assertFalse(await self.db.commit_recovered_credentials(self.before, **self.fields))


if __name__ == "__main__":
    unittest.main()
