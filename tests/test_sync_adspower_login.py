"""Offline login worker tests: no credentials, AdsPower or network access."""
import contextlib
import importlib.util
import io
import json
import logging
import os
from pathlib import Path
import signal
import time
import types
import unittest
from unittest.mock import patch


_SPEC = importlib.util.spec_from_file_location(
    "sync_adspower_login", Path(__file__).resolve().parents[1] / "local/sync_adspower_login.py")
worker = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(worker)


def request(**updates):
    result = {"profile_id": "one", "expected_email": "owner@example.test",
              "ws_url": "ws://127.0.0.1:9222/devtools/browser/fake-id",
              "spark_root": "/temporary/fake-spark"}
    result.update(updates)
    return result


class Page:
    def __init__(self, step="password", identities=None, manual="", url=None):
        self.step = step
        self.identities = ["owner@example.test"] if identities is None else identities
        self.manual = manual
        self.url = url or "https://accounts.google.com/v3/signin/challenge/pwd"
        self.writes = []
        self.navigations = []
        self.timeouts = []
        self.identity_reads = 0
        self.guard_error = False
        self.marker = ""
        self.init_scripts = []

    def evaluate(self, script, value=None):
        if script == worker._TAB_MARKER_READ_SCRIPT:
            return self.marker
        if script == worker._TAB_MARKER_SET_SCRIPT:
            self.marker = value
            return None
        if script == worker._CURRENT_IDENTITY_SCRIPT:
            self.identity_reads += 1
            return self.identities
        if script == worker._MANUAL_GUARD_SCRIPT:
            if self.guard_error:
                raise RuntimeError("PASSWORD_SECRET")
            return self.manual
        raise AssertionError("Unreviewed page script")

    def set_default_timeout(self, value):
        self.timeouts.append(value)

    def add_init_script(self, *, script):
        self.init_scripts.append(script)

    def set_default_navigation_timeout(self, value):
        self.timeouts.append(value)

    def goto(self, url, **kwargs):
        self.navigations.append(url)

    def close(self):
        raise AssertionError("No tab may be closed")


class Result:
    def __init__(self, ok, reason, message):
        self.ok, self.reason, self.message = ok, reason, message


class AutoLogin:
    AutoLoginResult = Result
    __package__ = "fake_spark.utils"

    def __init__(self, email="owner@example.test", user_id="one", failure=None):
        self.email = email
        self.user_id = user_id
        self.failure = failure
        self.attempts = []
        self.recorded_password = None
        self.calls = []
        self.account_credentials = types.SimpleNamespace(record_attempt=self._record)
        self.log = lambda *_args, **_kwargs: None

    def _record(self, *args):
        self.attempts.append(args)

    def _detect_step(self, page):
        return page.step, ""

    def _submit(self, page, locator, value):
        page.writes.append(value)
        return True

    def _first_visible(self, page, selectors):
        return getattr(page, "entry", None)

    def _run_login_steps(self, page, email, password, has_totp, user_id,
                         submits, deadline, cancel_check):
        self.recorded_password = password
        step, detail = self._detect_step(page)
        if step == "hard_stop":
            return Result(False, detail[0], "RAW_SECRET error")
        if step in {"password", "totp", "email"}:
            value = {"password": password, "totp": "123456", "email": email}[step]
            self._submit(page, object(), value)
        if self.failure:
            return Result(False, self.failure, "PASSWORD_SECRET 123456 COOKIE_SECRET")
        return Result(True, "logged_in", "COOKIE_SECRET")

    def try_auto_login(self, page, **kwargs):
        self.calls.append(kwargs)
        if self.failure == "breaker_open":
            return Result(False, "breaker_open", "private")
        result = self._run_login_steps(page, self.email, "PASSWORD_SECRET", True,
            self.user_id, {}, 180, None)
        self.account_credentials.record_attempt(self.user_id, "ok" if result.ok else "failed",
            result.reason, result.message)
        return result


class Context:
    def __init__(self, page):
        self.page = page
        self.pages = [Page(url="https://flow.google.com/project/existing")]
        self.created = 0

    def new_page(self):
        self.created += 1
        self.pages.append(self.page)
        return self.page

    def close(self):
        raise AssertionError("No context may be closed")


class Browser:
    def __init__(self, context):
        self.contexts = [context]

    def close(self):
        raise AssertionError("No browser may be closed")


class Playwright:
    def __init__(self, browser):
        self.browser = browser
        self.chromium = self
        self.connections = []
        self.stops = 0

    def start(self):
        return self

    def connect_over_cdp(self, url, **kwargs):
        self.connections.append((url, kwargs))
        return self.browser

    def stop(self):
        self.stops += 1


class LoginGuardTests(unittest.TestCase):
    def execute(self, page, auto=None):
        auto = auto or AutoLogin()
        with worker.guarded_auto_login(auto, "one", "owner@example.test"):
            result = auto.try_auto_login(page, user_id="one")
        return result, auto

    def test_password_only_submitted_for_matching_visible_current_identity(self):
        page = Page(identities=["OWNER@EXAMPLE.TEST", "owner@example.test"])
        result, auto = self.execute(page)
        self.assertTrue(result.ok)
        self.assertEqual(page.writes, ["PASSWORD_SECRET"])
        self.assertEqual(auto.recorded_password, "PASSWORD_SECRET")
        self.assertEqual(page.identity_reads, 1)

    def test_totp_matching_current_identity_is_allowed(self):
        page = Page("totp", url="https://accounts.google.com/v3/signin/challenge/totp")
        result, _ = self.execute(page)
        self.assertTrue(result.ok)
        self.assertEqual(page.writes, ["123456"])

    def test_current_identity_is_rechecked_before_every_secret_submission(self):
        auto = AutoLogin()
        page = Page()
        with worker.guarded_auto_login(auto, "one", "owner@example.test"):
            auto._submit(page, object(), "PASSWORD_SECRET")
            page.step = "totp"
            page.url = "https://accounts.google.com/v3/signin/challenge/totp"
            page.identities = ["other@example.test"]
            with self.assertRaises(worker.LoginAbort) as raised:
                auto._submit(page, object(), "123456")
            self.assertEqual(raised.exception.code, "identity_mismatch")
        self.assertEqual(page.writes, ["PASSWORD_SECRET"])
        self.assertEqual(page.identity_reads, 2)

    def test_password_and_totp_wrong_or_unconfirmed_identity_never_write(self):
        for step in ("password", "totp"):
            for identities, reason in (([], "identity_unconfirmed"),
                (["other@example.test"], "identity_mismatch"),
                (["owner@example.test", "other@example.test"], "identity_unconfirmed"),
                (["not-an-email"], "identity_unconfirmed"),
                ("owner@example.test", "identity_unconfirmed")):
                with self.subTest(step=step, identities=identities):
                    url = "https://accounts.google.com/v3/signin/challenge/" + ("totp" if step == "totp" else "pwd")
                    page = Page(step, identities, url=url)
                    result, auto = self.execute(page)
                    self.assertEqual(result.reason, reason)
                    self.assertEqual(page.writes, [])
                    self.assertEqual(auto.attempts[0][2:], (reason, reason))

    def test_credentials_email_or_profile_mismatch_never_write(self):
        for auto in (AutoLogin(email="other@example.test"), AutoLogin(user_id="other")):
            page = Page()
            with self.subTest(email=auto.email, profile=auto.user_id):
                if auto.user_id != "one":
                    # Even the persistent attempt cannot be redirected to another profile.
                    with self.assertRaises(worker.LoginAbort) as raised:
                        self.execute(page, auto)
                    self.assertEqual(raised.exception.code, "credential_identity_mismatch")
                    self.assertEqual(auto.attempts, [])
                else:
                    result, _ = self.execute(page, auto)
                    self.assertEqual(result.reason, "credential_identity_mismatch")
                self.assertEqual(page.writes, [])
                self.assertIsNone(auto.recorded_password)

    def test_credentials_email_case_is_normalized(self):
        page = Page()
        result, _ = self.execute(page, AutoLogin(email="OWNER@EXAMPLE.TEST"))
        self.assertTrue(result.ok)

    def test_password_never_written_to_spoofed_or_unencrypted_origin(self):
        for url in ("http://accounts.google.com/v3/signin/challenge/pwd",
                    "https://accounts.google.com.evil.test/signin/challenge/pwd",
                    "https://evil.test/?next=accounts.google.com",
                    "https://user:password@accounts.google.com/signin/challenge/pwd",
                    "https://accounts.google.com:444/signin/challenge/pwd",
                    "https://flow.google.com/"):
            with self.subTest(url=url):
                page = Page(url=url)
                result, _ = self.execute(page)
                self.assertEqual(result.reason, "unsafe_login_page")
                self.assertEqual(page.writes, [])

    def test_captcha_device_and_verification_stop_before_any_action(self):
        for reason in ("captcha_required", "device_confirm_required", "verification_required"):
            with self.subTest(reason=reason):
                page = Page("challenge_picker", manual=reason)
                result, _ = self.execute(page)
                self.assertEqual(result.reason, reason)
                self.assertEqual(page.writes, [])
                self.assertEqual(page.identity_reads, 0)

    def test_cannot_inspect_manual_guard_stops(self):
        page = Page()
        page.guard_error = True
        result, _ = self.execute(page)
        self.assertEqual(result.reason, "unknown_page")
        self.assertEqual(page.writes, [])

    def test_generic_sms_or_backup_otp_is_rejected(self):
        for path in ("sms", "backup-code", "ootp"):
            page = Page("totp", url="https://accounts.google.com/v3/signin/challenge/" + path)
            result, _ = self.execute(page)
            self.assertEqual(result.reason, "verification_required")
            self.assertEqual(page.writes, [])

    def test_attempt_reason_preserves_existing_breaker_classification_without_raw_message(self):
        for reason in ("wrong_password", "wrong_totp", "account_rejected", "timeout"):
            with self.subTest(reason=reason):
                result, auto = self.execute(Page(), AutoLogin(failure=reason))
                self.assertEqual(result.reason, reason)
                self.assertEqual(auto.attempts, [("one", "failed", reason, reason)])

    def test_unknown_attempt_reason_is_redacted(self):
        _, auto = self.execute(Page(), AutoLogin(failure="PASSWORD_SECRET"))
        self.assertEqual(auto.attempts, [("one", "failed", "login_exception", "login_exception")])

    def test_existing_breaker_result_is_respected_without_submit(self):
        page = Page()
        result, auto = self.execute(page, AutoLogin(failure="breaker_open"))
        self.assertEqual(result.reason, "breaker_open")
        self.assertEqual(page.writes, [])
        self.assertEqual(auto.attempts, [])

    def test_wrapper_restores_functions_after_failure(self):
        auto = AutoLogin()
        functions = (auto._run_login_steps, auto._submit, auto._detect_step,
                     auto.log, auto.account_credentials.record_attempt)
        with self.assertRaises(RuntimeError):
            with worker.guarded_auto_login(auto, "one", "owner@example.test"):
                raise RuntimeError("fake")
        self.assertEqual(functions, (auto._run_login_steps, auto._submit,
            auto._detect_step, auto.log, auto.account_credentials.record_attempt))


class ProtocolTests(unittest.TestCase):
    def test_protocol_requires_only_safe_four_fields(self):
        self.assertEqual(worker.validate_request(request()), request())
        for value in (None, [], {}, request(password="PASSWORD_SECRET"), request(cookie="COOKIE_SECRET")):
            with self.subTest(value=value):
                with self.assertRaises(worker.LoginAbort):
                    worker.validate_request(value)

    def test_loopback_cdp_endpoints_only(self):
        for host in ("127.0.0.1", "localhost", "[::1]"):
            worker.validate_request(request(ws_url=f"ws://{host}:9222/devtools/browser/id"))
        for url in ("ws://evil.test:9222/devtools/browser/id",
                    "http://127.0.0.1:9222/devtools/browser/id",
                    "ws://user:secret@localhost:9222/devtools/browser/id",
                    "ws://localhost:9222/devtools/browser/id?token=SECRET",
                    "ws://localhost:9222/devtools/browser/id#SECRET",
                    "ws://localhost:9222/evil", "ws://localhost/devtools/browser/id",
                    "ws://localhost:99999/devtools/browser/id"):
            with self.subTest(url=url):
                with self.assertRaises(worker.LoginAbort):
                    worker.validate_request(request(ws_url=url))

    def test_bad_profile_email_root_or_nonstring_rejected(self):
        for changes in ({"profile_id": "../other"}, {"expected_email": "bad email"},
                        {"spark_root": "relative"}, {"spark_root": "/temp/../other"},
                        {"profile_id": 2}, {"ws_url": None}):
            with self.subTest(changes=changes):
                with self.assertRaises(worker.LoginAbort):
                    worker.validate_request(request(**changes))

    def test_invalid_json_does_not_echo_input(self):
        output = io.StringIO()
        code = worker.main(io.StringIO("{PASSWORD_SECRET"), output)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue()), {"ok": False, "code": "invalid_request"})

    def test_oversized_request_rejected_before_dependencies(self):
        output = io.StringIO()
        with patch.object(worker, "run_login", side_effect=AssertionError("no execution")):
            worker.main(io.StringIO("x" * (worker.MAX_REQUEST_BYTES + 1)), output)
        self.assertEqual(json.loads(output.getvalue())["code"], "invalid_request")

    def test_dependency_stdout_stderr_native_output_and_errors_are_hidden(self):
        output, stderr = io.StringIO(), io.StringIO()
        def noisy(_):
            import sys
            print("PASSWORD_SECRET")
            print("COOKIE_SECRET", file=sys.stderr)
            os.write(1, b"NATIVE_COOKIE_SECRET\n")
            os.write(2, b"NATIVE_PASSWORD_SECRET\n")
            raise RuntimeError("proxy://user:PASSWORD_SECRET@host COOKIE_SECRET")
        with contextlib.redirect_stderr(stderr), patch.object(worker, "run_login", noisy):
            worker.main(io.StringIO(json.dumps(request())), output)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(json.loads(output.getvalue()), {"ok": False, "code": "login_exception"})

    def test_playwright_debug_and_file_logging_suppressed(self):
        previous = logging.root.manager.disable
        with patch.dict(os.environ, {"DEBUG": "pw:*", "PWDEBUG": "1", "DEBUG_FILE": "/tmp/secret.log"}):
            with worker._quiet_worker():
                self.assertNotIn("DEBUG", os.environ)
                self.assertNotIn("PWDEBUG", os.environ)
                self.assertNotIn("DEBUG_FILE", os.environ)
                self.assertGreater(logging.root.manager.disable, logging.CRITICAL)
        self.assertEqual(logging.root.manager.disable, previous)

    def test_success_flag_requires_allowlisted_success_code(self):
        self.assertEqual(worker.safe_result(True, "logged_in"), {"ok": True, "code": "logged_in"})
        self.assertEqual(worker.safe_result(True, "wrong_password"), {"ok": False, "code": "wrong_password"})
        self.assertEqual(worker.safe_result(True, "COOKIE_SECRET"), {"ok": False, "code": "login_exception"})

    @unittest.skipUnless(hasattr(signal, "setitimer"), "POSIX bounded worker timer")
    def test_total_budget_interrupts_login_and_restores_signal_handler(self):
        original_handler = signal.getsignal(signal.SIGALRM)
        output = io.StringIO()
        with patch.object(worker, "LOGIN_TIMEOUT_SECONDS", 0.01), \
                patch.object(worker, "run_login", side_effect=lambda _: time.sleep(0.1)):
            worker.main(io.StringIO(json.dumps(request())), output)
        self.assertEqual(json.loads(output.getvalue()), {"ok": False, "code": "timeout"})
        self.assertEqual(signal.getsignal(signal.SIGALRM), original_handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))


class BrowserIsolationTests(unittest.TestCase):
    def setUp(self):
        self.page = Page()
        self.context = Context(self.page)
        self.browser = Browser(self.context)
        self.playwright = Playwright(self.browser)
        self.auto = AutoLogin()
        browser_utils = types.SimpleNamespace(wait_for_login_redirect=lambda *_args, **_kwargs: True)
        self.enterContext(patch.object(worker.importlib, "import_module", return_value=browser_utils))

    def execute(self):
        return worker.run_login(request(), load_auto_login=lambda _: self.auto,
            playwright_factory=lambda: self.playwright)

    def test_only_new_page_navigated_and_transport_disconnected(self):
        old = self.context.pages[0]
        result = self.execute()
        self.assertEqual(result, {"ok": True, "code": "logged_in"})
        self.assertEqual(self.context.created, 1)
        self.assertEqual(old.navigations, [])
        self.assertEqual(old.writes, [])
        self.assertEqual(self.page.navigations, [worker.FLOW_HOME_URL])
        self.assertEqual(self.playwright.stops, 1)
        self.assertEqual(self.auto.calls[0]["user_id"], "one")
        self.assertLessEqual(self.auto.calls[0]["timeout_seconds"], 180)
        self.assertEqual(self.page.marker, "flow2api-cookie-login:one")
        self.assertEqual(self.page.init_scripts, ['window.name = "flow2api-cookie-login:one";'])
        self.assertEqual(old.init_scripts, [])

    def test_only_matching_marked_google_tab_is_reused_without_navigation(self):
        dedicated = Page()
        dedicated.marker = "flow2api-cookie-login:one"
        self.context.pages.append(dedicated)
        result = self.execute()
        self.assertTrue(result["ok"])
        self.assertEqual(self.context.created, 0)
        self.assertEqual(dedicated.navigations, [])
        self.assertEqual(dedicated.writes, ["PASSWORD_SECRET"])
        self.assertEqual(self.context.pages[0].writes, [])

    def test_marked_captcha_or_device_page_is_retained_without_navigation_or_action(self):
        for reason in ("captcha_required", "device_confirm_required"):
            with self.subTest(reason=reason):
                dedicated = Page("challenge_picker", manual=reason)
                dedicated.marker = "flow2api-cookie-login:one"
                self.context.pages = [dedicated]
                result = self.execute()
                self.assertEqual(result, {"ok": False, "code": reason})
                self.assertEqual(self.context.created, 0)
                self.assertEqual(dedicated.navigations, [])
                self.assertEqual(dedicated.writes, [])
                self.assertEqual(self.auto.calls, [])
                self.assertEqual(self.auto.attempts, [])

    def test_marked_untrusted_page_is_not_reused_or_changed(self):
        old = self.context.pages[0]
        old.marker = "flow2api-cookie-login:one"
        old.url = "https://evil.test/"
        self.execute()
        self.assertEqual(self.context.created, 1)
        self.assertEqual(old.navigations, [])
        self.assertEqual(old.writes, [])

    def test_different_profile_marker_is_not_reused(self):
        old = self.context.pages[0]
        old.marker = "flow2api-cookie-login:other"
        self.execute()
        self.assertEqual(self.context.created, 1)
        self.assertEqual(old.navigations, [])
        self.assertEqual(old.writes, [])

    def test_failed_login_preserves_new_page_for_manual_work(self):
        self.page.manual = "device_confirm_required"
        result = self.execute()
        self.assertEqual(result, {"ok": False, "code": "device_confirm_required"})
        self.assertIn(self.page, self.context.pages)
        self.assertEqual(self.playwright.stops, 1)

    def test_multiple_contexts_stop_before_tab_creation(self):
        self.browser.contexts.append(Context(Page()))
        result = self.execute()
        self.assertEqual(result["code"], "browser_context_unavailable")
        self.assertEqual(self.context.created, 0)
        self.assertEqual(self.playwright.stops, 1)

    def test_cdp_failure_is_redacted_and_disconnects(self):
        with patch.object(self.playwright, "connect_over_cdp", side_effect=RuntimeError("WS_TOKEN_SECRET")):
            result = self.execute()
        self.assertEqual(result, {"ok": False, "code": "login_exception"})
        self.assertEqual(self.context.created, 0)
        self.assertEqual(self.playwright.stops, 1)

    def test_dependency_failure_is_redacted(self):
        with self.assertRaises(worker.LoginAbort) as raised:
            worker.run_login(request(), load_auto_login=lambda _: (_ for _ in ()).throw(RuntimeError("PASSWORD_SECRET")))
        self.assertEqual(raised.exception.code, "login_dependency_unavailable")

    def test_untrusted_flow_entry_link_never_navigated(self):
        self.page.step = "done"
        self.page.url = "https://flow.google.com/"
        self.page.entry = types.SimpleNamespace(evaluate=lambda _: "https://evil.test/?secret=SECRET")
        result = self.execute()
        self.assertEqual(result["code"], "unsafe_login_page")
        self.assertEqual(self.page.navigations, [worker.FLOW_HOME_URL])
        self.assertEqual(self.page.writes, [])

    def test_official_flow_entry_uses_only_new_page(self):
        self.page.step = "done"
        self.page.url = "https://flow.google.com/"
        self.page.entry = types.SimpleNamespace(evaluate=lambda _: "https://labs.google/fx/tools/flow")
        result = self.execute()
        self.assertTrue(result["ok"])
        self.assertEqual(self.page.navigations, [worker.FLOW_HOME_URL, "https://labs.google/fx/tools/flow"])
        self.assertEqual(self.context.pages[0].navigations, [])


if __name__ == "__main__":
    unittest.main()
