"""Offline proof-worker tests: fake CDP, cookies, proxy and identity only."""
import asyncio
import contextlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import signal
import sys
import time
import types
import unittest
from unittest.mock import patch


_SPEC = importlib.util.spec_from_file_location(
    "sync_adspower_login_verify", Path(__file__).resolve().parents[1] / "local/sync_adspower_login_verify.py")
worker = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(worker)


def request(**updates):
    result = {"ws_url": "ws://127.0.0.1:9222/devtools/browser/fake-id",
              "expected_email": "owner@example.test",
              "proxy_url": "socks5h://proxy_user:PROXY_SECRET@proxy.example.test:1080"}
    result.update(updates)
    return result


class SyncError(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__("COOKIE_SECRET PROXY_SECRET")


class FakeSync:
    SyncError = SyncError

    def __init__(self, credits=840, error=None):
        self.credits, self.error = credits, error
        self.calls = []
        self.cookies_value = [{"name": "SID", "value": "COOKIE_SECRET"}]
        self.cookie_hash = "a" * 64
        self.proxy_hash = "b" * 64
        outer = self
        class Gateway:
            def __init__(self, config, client, credentials):
                outer.calls.append(("gateway", config, client, credentials))
                assert config == {} and client is None and credentials == {}

            async def cookies(self, source):
                outer.calls.append(("cookies", source))
                return outer.cookies_value
        self.Gateway = Gateway

    def proxy_identity(self, proxy):
        self.calls.append(("proxy_identity", proxy))

    def auth_hash(self, cookies):
        self.calls.append(("auth_hash", cookies))
        return self.cookie_hash

    def validation_proxy_hash(self, proxy):
        self.calls.append(("proxy_hash", proxy))
        return self.proxy_hash

    async def validate_identity(self, cookies, expected_email, proxy):
        raise AssertionError("Only verified_session may call its validator")

    async def verified_session(self, validator, cookies, expected_email, proxy):
        self.calls.append(("verify", validator, cookies, expected_email, proxy))
        assert cookies is self.cookies_value
        assert validator == self.validate_identity
        if self.error:
            raise self.error
        return self.credits


class VerifyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.enterContext(patch.object(worker, "_install_no_file_logger"))

    async def execute(self, fake=None, payload=None):
        return await worker.run_verification(payload or request(), load_sync=lambda: fake or FakeSync())

    async def test_live_cdp_read_and_authorized_proxy_are_pinned(self):
        fake = FakeSync()
        result = await self.execute(fake)
        self.assertEqual(result, {"ok": True, "code": "login_verified", "credits": 840,
            "verified_cookie_hash": "a" * 64, "verified_proxy_hash": "b" * 64})
        source = next(call[1] for call in fake.calls if call[0] == "cookies")
        self.assertEqual(source, {"source": "cdp", "ws": request()["ws_url"]})
        verification = next(call for call in fake.calls if call[0] == "verify")
        self.assertEqual(verification[3:], (request()["expected_email"], request()["proxy_url"]))
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertNotIn("ws_url", result)

    async def test_real_zero_credits_remains_valid(self):
        self.assertEqual((await self.execute(FakeSync(credits=0)))["credits"], 0)

    async def test_direct_proxy_is_allowed_without_substitution(self):
        for proxy in (None, ""):
            fake = FakeSync()
            result = await self.execute(fake, request(proxy_url=proxy))
            self.assertTrue(result["ok"])
            self.assertEqual(next(call for call in fake.calls if call[0] == "verify")[-1], proxy)

    async def test_invalid_or_unknown_credits_never_become_zero(self):
        for credits in (None, True, -1, 10**12, math.nan, math.inf, "840"):
            with self.subTest(credits=credits):
                with self.assertRaises(worker.VerifyAbort) as raised:
                    await self.execute(FakeSync(credits=credits))
                self.assertEqual(raised.exception.code, "login_credits_unverifiable")

    async def test_safe_identity_and_transport_errors_are_mapped(self):
        reasons = {"google_identity_mismatch": "login_identity_mismatch",
            "google_credit_validation_failed": "login_credits_unverifiable",
            "google_session_requires_attention": "login_identity_unverifiable",
            "cookies_unavailable": "login_identity_unverifiable",
            "authentication_cookies_missing": "login_identity_unverifiable",
            "identity_validation_unavailable": "login_host_unavailable",
            "browser_context_ambiguous": "login_browser_unavailable",
            "invalid_loopback_endpoint": "login_browser_unavailable",
            "account_proxy_invalid": "login_proxy_mismatch",
            "COOKIE_SECRET": "login_worker_failed"}
        for reason, code in reasons.items():
            with self.subTest(reason=reason):
                with self.assertRaises(worker.VerifyAbort) as raised:
                    await self.execute(FakeSync(error=SyncError(reason)))
                self.assertEqual(raised.exception.code, code)
                self.assertNotIn("SECRET", str(raised.exception))

    async def test_exception_and_timeout_do_not_echo_input(self):
        for error, code in ((RuntimeError("COOKIE_SECRET PROXY_SECRET"), "login_worker_failed"),
                            (asyncio.TimeoutError(), "login_timeout")):
            with self.subTest(code=code):
                with self.assertRaises(worker.VerifyAbort) as raised:
                    await self.execute(FakeSync(error=error))
                self.assertEqual(raised.exception.code, code)

    async def test_invalid_hash_proof_is_rejected(self):
        for field in ("cookie_hash", "proxy_hash"):
            fake = FakeSync()
            setattr(fake, field, "COOKIE_SECRET")
            with self.subTest(field=field):
                with self.assertRaises(worker.VerifyAbort) as raised:
                    await self.execute(fake)
                self.assertEqual(raised.exception.code, "login_worker_failed")

    async def test_dependency_failure_has_fixed_code(self):
        def unavailable():
            raise ImportError("PROXY_SECRET")
        with self.assertRaises(worker.VerifyAbort) as raised:
            await worker.run_verification(request(), load_sync=unavailable)
        self.assertEqual(raised.exception.code, "login_host_unavailable")


class VerifyProtocolTests(unittest.TestCase):
    def test_strict_three_field_protocol(self):
        self.assertEqual(worker.validate_request(request()), request())
        for value in (None, {}, [], request(cookies="COOKIE_SECRET"), request(profile_id="other"),
                      request(password="PASSWORD_SECRET")):
            with self.subTest(value=value):
                with self.assertRaises(worker.VerifyAbort):
                    worker.validate_request(value)

    def test_loopback_cdp_only_without_credentials(self):
        for host in ("127.0.0.1", "localhost", "[::1]"):
            worker.validate_request(request(ws_url=f"ws://{host}:9222/devtools/browser/id"))
        for url in ("ws://evil.example.test:9222/devtools/browser/id",
                    "ws://localhost:9222/devtools/browser/id?token=SECRET",
                    "ws://user:secret@localhost:9222/devtools/browser/id",
                    "http://localhost:9222/devtools/browser/id",
                    "ws://localhost:9222/arbitrary", "ws://localhost:99999/devtools/browser/id",
                    "ws://localhost/devtools/browser/id"):
            with self.subTest(url=url):
                with self.assertRaises(worker.VerifyAbort) as raised:
                    worker.validate_request(request(ws_url=url))
                self.assertEqual(raised.exception.code, "invalid_login_request")

    def test_email_is_fixed_canonical_and_proxy_shape_is_checked(self):
        for email in ("OWNER@EXAMPLE.TEST", " owner@example.test", "bad\nemail@example.test", 2):
            with self.subTest(email=email):
                with self.assertRaises(worker.VerifyAbort):
                    worker.validate_request(request(expected_email=email))
        for proxy in ("file:///tmp/secret", "https://proxy.test:443/path", "http://proxy.test:80?token=SECRET",
                      "http://proxy.test", "http://proxy.test:99999", 2, "http://proxy.test:80\nSECRET"):
            with self.subTest(proxy=proxy):
                with self.assertRaises(worker.VerifyAbort):
                    worker.validate_request(request(proxy_url=proxy))

    def test_invalid_and_oversized_input_never_runs_dependencies(self):
        for raw in ("{COOKIE_SECRET", "x" * (worker.MAX_REQUEST_BYTES + 1)):
            output = io.StringIO()
            with patch.object(worker, "run_verification", side_effect=AssertionError("No execution")):
                code = worker.main(io.StringIO(raw), output)
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output.getvalue()), {"ok": False, "code": "invalid_login_request"})

    def test_no_file_logger_stub_precedes_flowclient_import(self):
        with patch.dict(sys.modules):
            worker._install_no_file_logger()
            module = sys.modules["src.core.logger"]
            self.assertFalse(hasattr(module, "DebugLogger"))
            self.assertIsNone(module.debug_logger.log_request("Cookie=SECRET", proxy="PROXY_SECRET"))
            self.assertIsNone(module.debug_logger.log_error("COOKIE_SECRET"))

    def test_python_and_native_dependency_output_are_discarded(self):
        output, stderr = io.StringIO(), io.StringIO()
        async def noisy(_):
            print("COOKIE_SECRET")
            print("PROXY_SECRET", file=sys.stderr)
            os.write(1, b"NATIVE_COOKIE_SECRET\n")
            os.write(2, b"NATIVE_PROXY_SECRET\n")
            raise RuntimeError("PASSWORD_SECRET")
        with contextlib.redirect_stderr(stderr), patch.object(worker, "run_verification", noisy):
            code = worker.main(io.StringIO(json.dumps(request())), output)
        self.assertEqual(code, 1)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(json.loads(output.getvalue()), {"ok": False, "code": "login_worker_failed"})

    def test_safe_success_output_and_exit_zero(self):
        output = io.StringIO()
        async def successful(_):
            return {"ok": True, "code": "login_verified", "credits": 0,
                    "verified_cookie_hash": "a" * 64, "verified_proxy_hash": "b" * 64}
        with patch.object(worker, "run_verification", successful):
            code = worker.main(io.StringIO(json.dumps(request())), output)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["credits"], 0)
        self.assertNotIn("SECRET", output.getvalue())

    @unittest.skipUnless(hasattr(signal, "setitimer"), "POSIX bounded verifier timer")
    def test_worker_budget_interrupts_verification(self):
        output = io.StringIO()
        original_handler = signal.getsignal(signal.SIGALRM)
        async def blocked(_):
            await asyncio.sleep(0.1)
        with patch.object(worker, "VERIFY_TIMEOUT_SECONDS", 0.01), patch.object(worker, "run_verification", blocked):
            worker.main(io.StringIO(json.dumps(request())), output)
        self.assertEqual(json.loads(output.getvalue()), {"ok": False, "code": "login_timeout"})
        self.assertEqual(signal.getsignal(signal.SIGALRM), original_handler)


if __name__ == "__main__":
    unittest.main()
