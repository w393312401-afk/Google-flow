"""Offline recovery integration tests; all files and transports are synthetic."""
import copy
import fcntl
import importlib.util
import json
import math
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import httpx


_SPEC = importlib.util.spec_from_file_location(
    "sync_adspower_cookies_recovery_tests",
    Path(__file__).resolve().parents[1] / "local/sync_adspower_cookies.py")
sync = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sync)
_ASYNC_CLIENT = httpx.AsyncClient
_EMAIL = "owner@example.test"
_COOKIE_HASH = "a" * 64
_PROXY_HASH = "b" * 64


def config(**updates):
    value = dict(profile_id="one", expected_email=_EMAIL, token_id=7,
                 adspower_base="http://127.0.0.1:50325",
                 flow_base="http://127.0.0.1:38000",
                 spark_base="http://127.0.0.1:8085")
    value.update(updates)
    return value


def proof(**updates):
    value = dict(status="ok", reason="login_verified", token_id=7,
                 verified_cookie_hash=_COOKIE_HASH,
                 verified_proxy_hash=_PROXY_HASH)
    value.update(updates)
    return value


def backoff(**updates):
    value = dict(auth_failed_hash=_COOKIE_HASH, observed_hash=_COOKIE_HASH,
                 auth_failed_proxy_hash=_PROXY_HASH, auth_retry_after=5000)
    value.update(updates)
    return value


class RecoveryRunTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.path = self.root / "account.json"
        self.state_path = self.root / "account.state.json"
        (self.root / "local").mkdir()
        sync.save_private(self.root / "local/credentials.json",
                          {"username": "SYNTHETIC_ADMIN", "password": "SYNTHETIC_PASSWORD"})
        self.write_config()
        self.recovery = AsyncMock(return_value=proof())
        self.gateway = type("SyntheticGateway", (), {})()
        self.gateway.recover_login = self.recovery
        self.factory_calls = []

        def factory(conf, client, credentials):
            self.factory_calls.append((copy.deepcopy(conf), copy.deepcopy(credentials)))
            return self.gateway

        self.factory = factory
        self.validator = AsyncMock()
        self.addCleanup(patch.stopall)
        patch.object(sync, "ROOT", self.root).start()
        patch.object(sync.time, "time", return_value=1000).start()

        def reject_network(request):
            raise AssertionError("An integration test attempted an unexpected HTTP call")

        def offline_client(**kwargs):
            return _ASYNC_CLIENT(transport=httpx.MockTransport(reject_network), **kwargs)

        patch.object(sync.httpx, "AsyncClient", side_effect=offline_client).start()

    def write_config(self, **updates):
        sync.save_private(self.path, config(**updates))

    async def run_with(self, first, second=None, *, state=None, side_effect=None):
        sync.save_private(self.state_path, state or {})
        replies = [first] if second is None else [first, second]
        synchronize = AsyncMock(side_effect=side_effect or replies)
        with patch.object(sync, "synchronize", synchronize):
            result = await sync.run_once(self.path, gateway_factory=self.factory,
                                         validator=self.validator)
        return result, synchronize

    async def test_default_and_explicit_false_never_attempt_login(self):
        for option in ({}, {"allow_pool_login": False}):
            for reason in sync.LOGIN_TRIGGERS:
                with self.subTest(option=option, reason=reason):
                    self.write_config(**option)
                    self.recovery.reset_mock()
                    first = {"status": "error", "reason": reason}
                    result, operation = await self.run_with(first)
                    self.assertEqual(result, first)
                    self.recovery.assert_not_awaited()
                    operation.assert_awaited_once()

    async def test_wrong_identity_and_invalid_credits_do_not_attempt_login(self):
        self.write_config(allow_pool_login=True)
        for reason in ("google_identity_mismatch", "google_credit_validation_failed",
                       "generation_busy", "identity_validation_unavailable"):
            with self.subTest(reason=reason):
                self.recovery.reset_mock()
                result, operation = await self.run_with({"status": "error", "reason": reason})
                self.assertEqual(result["reason"], reason)
                self.recovery.assert_not_awaited()
                operation.assert_awaited_once()

    async def test_unbound_account_never_attempts_login(self):
        self.write_config(allow_pool_login=True, token_id=None)
        result, operation = await self.run_with(
            {"status": "error", "reason": "cookies_unavailable"})
        self.assertEqual(result["reason"], "cookies_unavailable")
        self.recovery.assert_not_awaited()
        operation.assert_awaited_once()

    async def test_legacy_auth_backoff_allows_one_login_then_one_sync(self):
        self.write_config(allow_pool_login=True)
        expected = {"status": "unchanged", "reason": "identity_validated", "token_id": 7}
        result, operation = await self.run_with(
            {"status": "deferred", "reason": "authentication_backoff"}, expected,
            state=backoff())
        self.assertEqual(result, expected)
        self.recovery.assert_awaited_once_with()
        self.assertEqual(operation.await_count, 2)
        self.assertEqual(self.factory_calls[1][1], {}, "Host recovery must not receive admin credentials")

    async def test_known_identity_or_credit_auth_backoff_never_attempts_login(self):
        self.write_config(allow_pool_login=True)
        for reason in ("google_identity_mismatch", "google_credit_validation_failed"):
            with self.subTest(reason=reason):
                self.recovery.reset_mock()
                first = {"status": "deferred", "reason": "authentication_backoff"}
                result, operation = await self.run_with(first,
                    state=backoff(auth_failed_reason=reason))
                self.assertEqual(result, first)
                self.recovery.assert_not_awaited()
                operation.assert_awaited_once()

    async def test_reserved_login_backoff_prevents_another_host_call(self):
        self.write_config(allow_pool_login=True)
        result, operation = await self.run_with(
            {"status": "error", "reason": "cookies_unavailable"},
            state={"login_retry_after": 1001})
        self.assertEqual(result, {"status": "deferred", "reason": "login_backoff", "token_id": 7,
                                  "retry_after": 1001})
        self.assertEqual(sync.private_json(self.state_path)["last_result"], result)
        self.recovery.assert_not_awaited()
        operation.assert_awaited_once()

    async def test_host_call_runs_after_account_lock_is_released_and_attempt_reserved(self):
        self.write_config(allow_pool_login=True)

        async def host():
            fd = os.open(self.root / "account.lock", os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                state = sync.private_json(self.state_path)
                self.assertEqual(state["login_attempted_at"], 1000)
                self.assertEqual(state["login_retry_after"], 2800)
            finally:
                os.close(fd)
            return proof()

        self.recovery.side_effect = host
        await self.run_with({"status": "error", "reason": "cookies_unavailable"},
                            {"status": "unchanged", "reason": "identity_validated"})
        self.recovery.assert_awaited_once()

    async def test_failed_second_sync_does_not_recursively_attempt_login(self):
        self.write_config(allow_pool_login=True)
        first = {"status": "error", "reason": "google_session_requires_attention"}
        result, operation = await self.run_with(first, first)
        self.assertEqual(result, first)
        self.assertEqual(operation.await_count, 2)
        self.recovery.assert_awaited_once()

    async def test_busy_manual_and_host_failures_return_only_fixed_safe_fields(self):
        self.write_config(allow_pool_login=True)
        for reason in sorted(sync.LOGIN_DEFERRED | sync.LOGIN_ERRORS | {"RAW_COOKIE_SECRET"}):
            with self.subTest(reason=reason):
                self.recovery.reset_mock()
                self.recovery.return_value = {"status": "error", "reason": reason,
                                              "message": "COOKIE_SECRET PASSWORD_SECRET"}
                result, operation = await self.run_with(
                    {"status": "error", "reason": "cookies_unavailable"})
                expected = reason if reason in sync.LOGIN_DEFERRED | sync.LOGIN_ERRORS else "login_internal_error"
                self.assertEqual(result, {"status": "deferred" if reason in sync.LOGIN_DEFERRED else "error",
                                          "reason": expected, "token_id": 7})
                self.assertEqual(set(result), {"status", "reason", "token_id"})
                saved = sync.private_json(self.state_path)
                self.assertEqual(saved["last_result"], result)
                self.assertEqual(saved["login_last_reason"], expected)
                operation.assert_awaited_once()
                self.recovery.assert_awaited_once()

    async def test_host_exception_is_sanitized(self):
        self.write_config(allow_pool_login=True)
        self.recovery.side_effect = RuntimeError("COOKIE_SECRET PASSWORD_SECRET")
        result, _ = await self.run_with({"status": "error", "reason": "cookies_unavailable"})
        self.assertEqual(result, {"status": "deferred", "reason": "login_host_unavailable", "token_id": 7})

    def configure_full_sync_gateway(self):
        cookies = [{"name": "SID", "value": "SYNTHETIC_SESSION", "domain": ".google.com",
                    "path": "/", "secure": True}]
        row = {"id": 7, "email": _EMAIL, "login_account": _EMAIL,
               "remark": "adspower-sync:one", "google_cookies": json.dumps(cookies),
               "proxy_url": "", "captcha_proxy_url": "", "is_active": False,
               "image_enabled": False, "video_enabled": False,
               "at_expires": "2099-01-01T00:00:00Z"}
        self.gateway.profile = AsyncMock(return_value={"ws": "ws://127.0.0.1:9222/fake", "proxy": ""})
        self.gateway.tokens = AsyncMock(return_value=[row])
        self.gateway.cookies = AsyncMock(return_value=cookies)
        self.gateway.busy = AsyncMock(return_value=(False, False))
        self.gateway.write = AsyncMock()
        self.gateway.disable = AsyncMock()
        self.recovery.return_value = proof(verified_cookie_hash=sync.auth_hash(cookies),
                                          verified_proxy_hash=sync.validation_proxy_hash(""))

    async def test_full_sync_revalidates_identity_after_exact_host_proof(self):
        self.write_config(allow_pool_login=True)
        self.configure_full_sync_gateway()
        error = type("SyntheticAuthError", (Exception,), {"category": "authentication_required"})("COOKIE_SECRET")
        self.validator.side_effect = [error, {"email": _EMAIL, "credits": 925}]
        result = await sync.run_once(self.path, gateway_factory=self.factory,
                                     validator=self.validator)
        self.assertEqual(result, {"status": "unchanged", "reason": "identity_validated", "token_id": 7})
        self.assertEqual(self.validator.await_count, 2, "Host proof must not replace ordinary sync identity validation")
        self.recovery.assert_awaited_once()
        self.gateway.write.assert_not_awaited()
        self.gateway.disable.assert_not_awaited()
        state = sync.private_json(self.state_path)
        self.assertNotIn("auth_retry_after", state)
        self.assertNotIn("COOKIE_SECRET", json.dumps(state))

    async def test_full_sync_identity_or_credit_mismatch_never_calls_host(self):
        self.write_config(allow_pool_login=True)
        self.configure_full_sync_gateway()
        for value, reason in (({"email": "other@example.test", "credits": 840}, "google_identity_mismatch"),
                              ({"email": _EMAIL, "credits": None}, "google_credit_validation_failed")):
            with self.subTest(reason=reason):
                sync.save_private(self.state_path, {})
                self.validator.side_effect = None
                self.validator.return_value = value
                result = await sync.run_once(self.path, gateway_factory=self.factory,
                                             validator=self.validator)
                self.assertEqual(result, {"status": "error", "reason": reason})
                self.recovery.assert_not_awaited()
                self.gateway.write.assert_not_awaited()
                self.gateway.disable.assert_not_awaited()

    async def test_authentication_backoff_preserves_known_manual_action_reason(self):
        self.write_config(allow_pool_login=True)
        self.configure_full_sync_gateway()
        for value, reason in (({"email": "other@example.test", "credits": 840}, "google_identity_mismatch"),
                              ({"email": _EMAIL, "credits": None}, "google_credit_validation_failed")):
            with self.subTest(reason=reason):
                sync.save_private(self.state_path, {})
                self.validator.return_value = value
                await sync.run_once(self.path, gateway_factory=self.factory, validator=self.validator)
                result = await sync.run_once(self.path, gateway_factory=self.factory, validator=self.validator)
                self.assertEqual(result["reason"], "authentication_backoff")
                self.assertEqual(result.get("prior_reason"), reason)
                self.assertEqual(result.get("retry_after"), 4600)
                self.assertEqual(sync.private_json(self.state_path)["last_result"], result)
                self.recovery.assert_not_awaited()

    async def test_only_exact_session_proxy_and_binding_proof_clear_old_backoff(self):
        scenarios = [(True, {}, {}, True),
                     (True, {"verified_cookie_hash": "c" * 64}, {}, False),
                     (True, {"verified_proxy_hash": "c" * 64}, {}, False),
                     (True, {"token_id": 8}, {}, False),
                     (True, {"verified_proxy_hash": None}, {}, False),
                     (True, {"verified_proxy_hash": None}, {"auth_failed_proxy_hash": None}, False),
                     (True, {"status": "error"}, {}, False),
                     (True, {"reason": "logged_in"}, {}, False),
                     (True, {}, {"observed_hash": "c" * 64}, False),
                     (False, {}, {}, False)]
        for enabled, proof_updates, state_updates, cleared in scenarios:
            with self.subTest(enabled=enabled, proof=proof_updates, state=state_updates):
                self.write_config(allow_pool_login=enabled)
                sync.save_private(self.state_path, backoff(auth_failed_reason="google_session_requires_attention",
                                                           **state_updates))
                snapshots = []

                async def inspect_state(conf, state, gateway, **kwargs):
                    snapshots.append(copy.deepcopy(state))
                    return {"status": "deferred", "reason": "generation_busy"}

                with patch.object(sync, "synchronize", AsyncMock(side_effect=inspect_state)):
                    await sync._run_once_locked(self.path, gateway_factory=self.factory,
                                                validator=self.validator,
                                                login_proof=proof(**proof_updates))
                fields = ("auth_failed_hash", "auth_failed_proxy_hash", "auth_retry_after", "auth_failed_reason")
                for field in fields:
                    self.assertEqual(field not in snapshots[0], cleared)


class GatewayRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def recover(self, status=200, value=None, *, content=None, exception=None):
        received = []

        def transport(request):
            received.append(request)
            if exception:
                raise exception
            kwargs = {"content": json.dumps(value).encode()} if content is None else {"content": content}
            return httpx.Response(status, headers={"set-cookie": "HOST_COOKIE_SECRET=x; Path=/"}, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "spark.json"
            sync.save_private(path, {"accessCode": "SYNTHETIC_SPARK_ACCESS"})
            async with _ASYNC_CLIENT(transport=httpx.MockTransport(transport)) as client:
                client.cookies.set("ADMIN_COOKIE_SECRET", "secret", domain="127.0.0.1")
                gateway = sync.Gateway(config(spark_config_path=str(path)), client,
                                       {"username": "ADMIN_USER_SECRET", "password": "ADMIN_PASSWORD_SECRET"})
                gateway.authorization = {"Authorization": "Bearer ADMIN_TOKEN_SECRET"}
                result = await gateway.recover_login()
                self.assertEqual(list(client.cookies.items()), [])
        self.assertEqual(len(received), 1)
        request = received[0]
        self.assertEqual(str(request.url), "http://127.0.0.1:8085/api/account-pool/login-sync")
        self.assertEqual(json.loads(request.content), {"profile_id": "one", "expected_email": _EMAIL, "token_id": 7})
        self.assertNotIn("cookie", request.headers)
        self.assertNotIn("authorization", request.headers)
        self.assertEqual(request.headers["x-access-code"], "SYNTHETIC_SPARK_ACCESS")
        self.assertNotIn("ADMIN_", request.content.decode())
        return result

    async def test_success_response_has_only_whitelisted_fields(self):
        result = await self.recover(value=dict(status="ok", code="login_verified", token_id=7,
            credits=840, verified_cookie_hash=_COOKIE_HASH, verified_proxy_hash=_PROXY_HASH,
            cookie="COOKIE_SECRET", password="PASSWORD_SECRET", message="PRIVATE_PAGE_SECRET"))
        self.assertEqual(result, proof())

    async def test_invalid_optional_hashes_are_dropped(self):
        result = await self.recover(value=dict(status="ok", code="login_verified", token_id=7,
            credits=0, verified_cookie_hash="COOKIE_SECRET", verified_proxy_hash="B" * 64))
        self.assertEqual(result, {"status": "ok", "reason": "login_verified", "token_id": 7})

    async def test_busy_and_manual_codes_require_expected_http_status(self):
        for codes, status, result_status in ((sync.LOGIN_DEFERRED, 409, "deferred"),
                                             (sync.LOGIN_ERRORS, 422, "error")):
            for code in sorted(codes):
                with self.subTest(code=code):
                    result = await self.recover(status, {"code": code, "message": "COOKIE_SECRET"})
                    self.assertEqual(result, {"status": result_status, "reason": code})
        for status, code in ((200, "generation_busy"), (422, "generation_busy"),
                             (409, "login_wrong_password"), (200, "UNKNOWN_COOKIE_SECRET")):
            with self.subTest(status=status, code=code):
                self.assertEqual(await self.recover(status, {"code": code}),
                                 {"status": "error", "reason": "login_internal_error"})

    async def test_unknown_status_malformed_oversized_and_transport_errors_are_safe(self):
        for status in (201, 302, 401, 403, 500):
            with self.subTest(status=status):
                result = await self.recover(status, {"code": "COOKIE_SECRET"})
                self.assertEqual(result, {"status": "deferred", "reason": "login_host_unavailable"})
        for content, expected in ((b"COOKIE_SECRET", "login_internal_error"),
                                  (b"x" * 4097, "login_host_unavailable"),
                                  (b"[]", "login_internal_error")):
            with self.subTest(content_size=len(content)):
                self.assertEqual((await self.recover(content=content))["reason"], expected)
        result = await self.recover(exception=httpx.ConnectError("PASSWORD_SECRET"))
        self.assertEqual(result, {"status": "deferred", "reason": "login_host_unavailable"})

    async def test_success_requires_matching_integer_token_and_finite_valid_credits(self):
        for updates in ({"token_id": True}, {"token_id": 8}, {"token_id": "7"},
                        {"credits": None}, {"credits": True}, {"credits": -1},
                        {"credits": math.nan}, {"credits": math.inf}, {"credits": 10**12},
                        {"status": "error"}, {"code": "logged_in"}):
            with self.subTest(updates=updates):
                value = dict(status="ok", code="login_verified", token_id=7, credits=840)
                value.update(updates)
                self.assertEqual(await self.recover(value=value),
                                 {"status": "error", "reason": "login_internal_error"})


class VerifiedSessionRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_valid_identity_with_real_zero_is_accepted(self):
        check = AsyncMock(return_value={"email": "OWNER@EXAMPLE.TEST", "credits": 0})
        self.assertEqual(await sync.verified_session(check, "SYNTHETIC_COOKIE", _EMAIL, ""), 0)

    async def test_invalid_identity_and_credits_have_distinct_non_login_failures(self):
        for value, reason in (({}, "google_identity_mismatch"),
                             ({"email": "other@example.test", "credits": 840}, "google_identity_mismatch"),
                             ({"email": _EMAIL}, "google_credit_validation_failed"),
                             *[({"email": _EMAIL, "credits": credits}, "google_credit_validation_failed")
                               for credits in (None, True, "840", -1, math.nan, math.inf, 10**12)]):
            with self.subTest(value=value):
                with self.assertRaises(sync.SyncError) as raised:
                    await sync.verified_session(AsyncMock(return_value=value), "COOKIE_SECRET", _EMAIL, "")
                self.assertEqual(raised.exception.reason, reason)
                self.assertNotIn(reason, sync.LOGIN_TRIGGERS)

    async def test_validator_categories_map_without_exception_secret_leak(self):
        for category, reason in (("identity_mismatch", "google_identity_mismatch"),
                                 ("credits_unverifiable", "google_credit_validation_failed"),
                                 ("authentication_required", "google_session_requires_attention"),
                                 ("identity_unverifiable", "google_session_requires_attention"),
                                 ("network", "identity_validation_unavailable")):
            with self.subTest(category=category):
                error = type("SyntheticValidationError", (Exception,), {"category": category})("COOKIE_SECRET")
                with self.assertRaises(sync.SyncError) as raised:
                    await sync.verified_session(AsyncMock(side_effect=error), "COOKIE_SECRET", _EMAIL, "")
                self.assertEqual(str(raised.exception), reason)


class RecoverySummaryTests(unittest.TestCase):
    def test_pool_summary_preserves_only_actionable_auth_and_login_backoff_details(self):
        spec = importlib.util.spec_from_file_location("synthetic_pool_sanitizer_tests",
            Path(__file__).resolve().parents[1] / "local/sync_adspower_cookie_pool.py")
        pool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pool)
        for outer, prior in (("authentication_backoff", "google_identity_mismatch"),
                             ("authentication_backoff", "google_credit_validation_failed"),
                             ("login_backoff", "login_captcha_required"),
                             ("login_backoff", "login_host_unavailable")):
            with self.subTest(outer=outer, prior=prior):
                expected = {"status": "deferred", "reason": outer, "token_id": 7,
                            "prior_reason": prior, "retry_after": 4600}
                self.assertEqual(pool._safe_result(dict(expected, detail="COOKIE_SECRET")), expected)
                redacted = pool._safe_result(dict(expected, prior_reason="PASSWORD_SECRET",
                                                   retry_after=float("nan")))
                self.assertEqual(redacted, {"status": "deferred", "reason": outer, "token_id": 7})


if __name__ == "__main__":
    unittest.main()
