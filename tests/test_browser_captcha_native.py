"""Native captcha regressions; AST loading never installs or launches a browser."""
import ast
import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
import hashlib
import json
import os
import random
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import parse_qs, unquote, urlencode, urlparse

from src.services.browser_cookie_utils import build_browser_cookie_targets, build_cookie_signature
from src.services.captcha_errors import BrowserCaptchaError


SOURCE = Path(__file__).parents[1] / "src/services/browser_captcha.py"
tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
namespace = dict(globals())
namespace["__package__"] = "src.services"
namespace["__spec__"] = None
namespace.update(
    debug_logger=types.SimpleNamespace(log_info=Mock(), log_warning=Mock(), log_error=Mock()),
    config=types.SimpleNamespace(browser_flow_page_warmup_seconds=0),
    LABS_URL="https://flow.google.com",
    BROWSER_SESSION_COOKIE_TARGET_URLS=("https://flow.google.com/",),
)
exec(compile(ast.Module(body=[node for node in tree.body
                             if (isinstance(node, ast.ClassDef)
                                 and node.name in {"TokenBrowser", "_BrowserRequest", "BrowserCaptchaService"})
                             or (isinstance(node, ast.FunctionDef) and node.name == "_resolve_flow_page_warmup_seconds")],
                        type_ignores=[]), str(SOURCE), "exec"), namespace)
TokenBrowser = namespace["TokenBrowser"]
BrowserCaptchaError = namespace["BrowserCaptchaError"]
BrowserCaptchaService = namespace["BrowserCaptchaService"]


class NativeCaptchaTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        # Avoid creating normal runtime directories during a unit test.
        self.browser = TokenBrowser.__new__(TokenBrowser)
        self.browser.token_id = 0
        self.browser._pid_dir = self.directory.name
        self.browser._captcha_stage = "idle"
        self.browser._captcha_started_at = time.monotonic()
        self.browser._captcha_diagnostics = []
        self.browser._harvest_streamchat_post = None
        self.browser._harvest_rpc = None
        self.browser._last_fingerprint = None
        self.browser._last_harvest_session_id = None
        self.browser._harvest_route_error = None
        self.browser._browser_proxy_active = False
        self.browser._semaphore = asyncio.Semaphore(1)
        self.browser._solve_inflight = 0
        self.browser._solve_count = 0
        self.browser._error_count = 0
        self.browser._consecutive_browser_failures = 0
        self.browser.note_idle = Mock()
        async def new_page(context):
            return await context.new_page()
        self.browser._new_page = AsyncMock(side_effect=new_page)

    def _run_page_scripts_in_fake_dom(self, calls):
        node_path = shutil.which("node")
        if not node_path:
            self.skipTest("Node.js is required to execute the window focus regression")
        harness = r"""
const vm = require('node:vm');
const scripts = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const events = [];
let focusCount = 0;
let scrollCount = 0;
class Navigator {}
class Screen {}
class Document {}
class Event { constructor(type) { this.type = type; } }
class MouseEvent extends Event {}
const window = {
    innerWidth: 1280, innerHeight: 720,
    focus() { focusCount++; },
    dispatchEvent(event) { events.push(event.type); },
    scrollTo() { scrollCount++; },
};
const document = new Document();
document.body = { scrollHeight: 1200 };
document.hidden = true;
document.visibilityState = 'hidden';
document.hasFocus = () => false;
document.dispatchEvent = event => events.push(event.type);
const context = vm.createContext({
    window, document, Navigator, navigator: new Navigator(),
    Screen, screen: new Screen(), Document, Event, MouseEvent,
});
for (const call of scripts) {
    const result = vm.runInContext(call.source, context);
    if (typeof result === 'function') result(call.argument);
}
process.stdout.write(JSON.stringify({
    focusCount, scrollCount, events,
    hidden: document.hidden,
    visibilityState: document.visibilityState,
    hasFocus: document.hasFocus(),
}));
"""
        result = subprocess.run(
            [node_path, "-e", harness],
            input=json.dumps(calls), capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    @staticmethod
    def _window_focus_config(background):
        runtime_config = types.SimpleNamespace(
            browser_flow_page_warmup_seconds=-1,
            browser_score_test_warmup_seconds=-1,
            browser_recaptcha_settle_seconds=-1,
        )
        if background is not None:
            runtime_config.browser_launch_background = background
        return runtime_config

    async def test_flow_warmup_respects_background_mode_and_keeps_page_ready(self):
        for background in (None, True, False):
            with self.subTest(background=background):
                page = types.SimpleNamespace(
                    route=AsyncMock(), goto=AsyncMock(), bring_to_front=AsyncMock(),
                    evaluate=AsyncMock(side_effect=lambda source, *_args:
                        "complete" if source == "document.readyState" else None),
                    mouse=types.SimpleNamespace(move=AsyncMock(), wheel=AsyncMock()),
                )
                editor = types.SimpleNamespace(wait_for=AsyncMock())
                editor.first = editor
                page.locator = Mock(return_value=editor)
                self.browser._capture_captcha_page_state = AsyncMock(return_value={"location": "flow_editor"})
                self.browser._wait_for_enterprise_ready = AsyncMock(return_value=True)
                self.browser._capture_page_fingerprint = AsyncMock()
                with patch.dict(namespace, {"config": self._window_focus_config(background)}):
                    ready = await self.browser._prepare_flow_runtime_page(page, "project", "key", "action")
                self.assertTrue(ready)
                self.assertEqual(page.bring_to_front.await_count, int(background is False))
                self.assertEqual(page.mouse.move.await_count, 2)
                page.mouse.wheel.assert_awaited_once()
                page.goto.assert_awaited_once()
                self.browser._wait_for_enterprise_ready.assert_awaited_once()
                self.browser._capture_page_fingerprint.assert_awaited_once_with(page)
                self.assertEqual(editor.wait_for.await_count, 2)
                warmup_calls = [
                    {"source": call.args[0], "argument": call.args[1] if len(call.args) > 1 else None}
                    for call in page.evaluate.await_args_list
                    if call.args[0] != "document.readyState"
                ]
                dom = self._run_page_scripts_in_fake_dom(warmup_calls)
                self.assertEqual(dom["focusCount"], int(background is False))
                self.assertEqual(dom["events"], ["focus", "mousemove"])
                self.assertEqual(dom["scrollCount"], 1)

    async def test_custom_captcha_warmup_respects_background_mode_and_returns_token(self):
        for background in (None, True, False):
            with self.subTest(background=background):
                action = "synthetic-action"
                def evaluate(source, *args):
                    if source == "document.readyState":
                        return "complete"
                    if args and args[0] == action:
                        return "synthetic-token"
                    return None
                page = types.SimpleNamespace(
                    on=Mock(), add_init_script=AsyncMock(), goto=AsyncMock(), close=AsyncMock(),
                    bring_to_front=AsyncMock(), evaluate=AsyncMock(side_effect=evaluate),
                    wait_for_function=AsyncMock(),
                    mouse=types.SimpleNamespace(move=AsyncMock(), wheel=AsyncMock()),
                )
                context = types.SimpleNamespace(new_page=AsyncMock(return_value=page))
                self.browser._apply_browser_environment_patch = AsyncMock()
                self.browser._capture_page_fingerprint = AsyncMock()
                with patch.dict(namespace, {"config": self._window_focus_config(background)}):
                    token = await self.browser._execute_custom_captcha(
                        context, "https://synthetic.invalid/score", "key", action,
                    )
                self.assertEqual(token, "synthetic-token")
                self.assertEqual(page.bring_to_front.await_count, int(background is False))
                self.assertEqual(page.mouse.move.await_count, 2)
                page.mouse.wheel.assert_awaited_once()
                page.wait_for_function.assert_awaited_once()
                page.close.assert_awaited_once()
                self.browser._capture_page_fingerprint.assert_awaited_once_with(page)
                warmup_calls = [
                    {"source": call.args[0], "argument": call.args[1] if len(call.args) > 1 else None}
                    for call in page.evaluate.await_args_list
                    if call.args[0] != "document.readyState" and not (len(call.args) > 1 and call.args[1] == action)
                ]
                dom = self._run_page_scripts_in_fake_dom(warmup_calls)
                self.assertEqual(dom["focusCount"], int(background is False))
                self.assertEqual(dom["events"], ["focus", "mousemove"])
                self.assertEqual(dom["scrollCount"], 1)

    async def test_environment_patch_preserves_visibility_without_background_window_focus(self):
        self.browser._profile_viewport = {"width": 1280, "height": 720}
        self.browser._profile_env_seed = "synthetic-seed"
        for background in (None, True, False):
            with self.subTest(background=background):
                target = types.SimpleNamespace(add_init_script=AsyncMock())
                with patch.dict(namespace, {
                    "config": self._window_focus_config(background),
                    "BROWSER_ENVIRONMENT_PATCH_MARKER": "synthetic-environment-patch",
                }):
                    self.assertTrue(await self.browser._apply_browser_environment_patch(target, label="test"))
                target.add_init_script.assert_awaited_once()
                source = target.add_init_script.await_args.args[0]
                # Re-running an installed patch must not activate the window again.
                dom = self._run_page_scripts_in_fake_dom([{"source": source}] * 2)
                self.assertEqual(dom["focusCount"], int(background is False))
                self.assertFalse(dom["hidden"])
                self.assertEqual(dom["visibilityState"], "visible")
                self.assertTrue(dom["hasFocus"])

    def test_header_cookie_targets_are_valid_for_playwright(self):
        cookies = self.browser._build_google_cookie_targets("SID=fake-cookie")
        self.assertEqual(len(cookies), 2)
        for cookie in cookies:
            self.assertIn("url", cookie)
            self.assertNotIn("path", cookie)
            self.assertNotIn("domain", cookie)

    def test_scoped_cookies_keep_original_scope(self):
        scoped = [{"name": "OSID", "value": "fake", "domain": "flow.google.com", "path": "/"}]
        # Root-path host cookies are expressed by URL, which keeps the same scope.
        self.assertEqual(self.browser._build_google_cookie_targets(json.dumps(scoped)), [
            {"name": "OSID", "value": "fake", "url": "https://flow.google.com/"}])

    def test_private_diagnostics_are_bounded_and_allowlisted(self):
        for _ in range(80):
            self.browser._record_captcha_stage("editor_wait", "editor_missing", editor_present=False,
                cookie_count=26, url="https://private.invalid/account", editorText="private text", token="secret")
        directory = Path(self.directory.name) / "diagnostics"
        path = directory / "slot_0.json"
        raw = path.read_text()
        self.assertEqual(len(json.loads(raw)), 48)
        self.assertNotIn("private", raw)
        self.assertNotIn("secret", raw)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)

    async def test_page_state_detects_generation_controls_in_current_locales(self):
        node_path = shutil.which("node")
        if not node_path:
            self.skipTest("Node.js is required to execute the page state regression")
        page = types.SimpleNamespace(evaluate=AsyncMock(return_value={}))
        await self.browser._capture_captcha_page_state(page)
        script = page.evaluate.await_args.args[0]
        harness = r"""
const vm = require('node:vm');
const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const button = { disabled: true };
const document = {
    readyState: 'interactive',
    querySelector(selector) {
        const control = `button[aria-label='${input.label}']`;
        return selector.split(',').map(value => value.trim()).includes(control) ? button : null;
    },
    querySelectorAll() { return []; },
};
const context = vm.createContext({
    document, location: { hostname: 'flow.google.com', pathname: '/project/synthetic' },
    window: {},
});
process.stdout.write(JSON.stringify(vm.runInContext(input.script, context)()));
"""
        for label in ("Start generation", "开始生成", "開始生成", "Unrelated action"):
            with self.subTest(label=label):
                result = subprocess.run(
                    [node_path, "-e", harness], input=json.dumps({"script": script, "label": label}),
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                state = json.loads(result.stdout)
                self.assertEqual(state["submit_present"], label != "Unrelated action")
                self.assertEqual(state["submit_disabled"], label != "Unrelated action")
                self.assertEqual(state["location"], "flow_project")

    async def test_raw_exception_becomes_safe_stage_failure(self):
        context = types.SimpleNamespace(new_page=AsyncMock(side_effect=RuntimeError("secret https://private.invalid")))
        with self.assertRaises(BrowserCaptchaError) as raised:
            await self.browser._execute_captcha(context, "private-project", "key", "IMAGE_GENERATION")
        self.assertEqual(raised.exception.stage, "page_creation")
        self.assertEqual(raised.exception.reason, "browser_operation_failed")
        self.assertNotIn("secret", str(raised.exception))
        self.assertNotIn("private", str(raised.exception))

    async def test_route_registration_failure_stops_before_navigation(self):
        page = types.SimpleNamespace(route=AsyncMock(side_effect=RuntimeError("cannot route")), goto=AsyncMock())
        with self.assertRaises(BrowserCaptchaError) as raised:
            await self.browser._prepare_flow_runtime_page(page, "project", "key", "action")
        self.assertEqual(raised.exception.reason, "route_registration_failed")
        page.goto.assert_not_awaited()

    def _ready_flow_page(self, *, url="https://flow.google.com/project/project", navigation_error=None):
        editor = types.SimpleNamespace(wait_for=AsyncMock())
        editor.first = editor
        page = types.SimpleNamespace(
            url=url, route=AsyncMock(), goto=AsyncMock(side_effect=navigation_error),
            locator=Mock(return_value=editor), bring_to_front=AsyncMock(),
            evaluate=AsyncMock(),
            mouse=types.SimpleNamespace(move=AsyncMock(), wheel=AsyncMock()),
        )
        self.browser._capture_captcha_page_state = AsyncMock(return_value={
            "location": "flow_project", "ready_state": "interactive", "editor_visible": True,
        })
        self.browser._wait_for_enterprise_ready = AsyncMock(return_value=True)
        self.browser._capture_page_fingerprint = AsyncMock()
        return page, editor

    async def _prepare_ready_page(self, page):
        with patch.dict(namespace, {"config": self._window_focus_config(True)}):
            return await self.browser._prepare_flow_runtime_page(page, "project", "key", "action")

    async def test_committed_project_recovers_interrupted_navigation_without_new_navigation(self):
        for error in (
            TimeoutError("synthetic DOMContentLoaded timeout"),
            RuntimeError("Page.goto: net::ERR_ABORTED synthetic private URL"),
            RuntimeError("Navigation to synthetic private URL is interrupted by another navigation"),
        ):
            with self.subTest(error=type(error).__name__):
                page, editor = self._ready_flow_page(navigation_error=error)
                self.assertTrue(await self._prepare_ready_page(page))
                page.goto.assert_awaited_once_with(
                    "https://flow.google.com/project/project", wait_until="domcontentloaded", timeout=45000,
                )
                self.assertEqual(editor.wait_for.await_count, 2)
                self.assertTrue(all(row.get("reason") in {None, "timeout", "navigation_interrupted"}
                                    for row in self.browser._captcha_diagnostics))
                self.assertNotIn("synthetic private", json.dumps(self.browser._captcha_diagnostics))

    async def test_navigation_recovery_requires_exact_project_and_committed_document(self):
        for url, state in (
            ("about:blank", {"location": "other", "ready_state": "complete"}),
            ("https://flow.google.com/project/different", {"location": "flow_project", "ready_state": "complete"}),
            ("https://flow.google.com/about", {"location": "flow_landing", "ready_state": "complete"}),
            ("https://flow.google.com/project/project", {"location": "flow_project", "ready_state": "loading"}),
            ("https://private.invalid/project/project", {"location": "other", "ready_state": "complete"}),
        ):
            with self.subTest(url=url):
                page, editor = self._ready_flow_page(url=url, navigation_error=TimeoutError("synthetic timeout"))
                self.browser._capture_captcha_page_state.return_value = state
                with self.assertRaises(BrowserCaptchaError) as raised:
                    await self._prepare_ready_page(page)
                self.assertEqual((raised.exception.stage, raised.exception.reason), ("navigation", "timeout"))
                page.goto.assert_awaited_once()
                editor.wait_for.assert_not_awaited()
                self.browser._wait_for_enterprise_ready.assert_not_awaited()

    async def test_network_failure_never_recovered_even_if_project_editor_exists(self):
        for message, reason in (
            ("Page.goto: net::ERR_PROXY_CONNECTION_FAILED", "proxy_connection_failed"),
            ("Page.goto: net::ERR_CONNECTION_CLOSED", "network_connection_failed"),
            ("Page.goto: net::ERR_EMPTY_RESPONSE", "network_empty_response"),
        ):
            with self.subTest(reason=reason):
                page, editor = self._ready_flow_page(navigation_error=RuntimeError(message))
                with self.assertRaises(BrowserCaptchaError) as raised:
                    await self._prepare_ready_page(page)
                self.assertEqual(raised.exception.reason, reason)
                page.goto.assert_awaited_once()
                editor.wait_for.assert_not_awaited()

    async def test_navigation_to_signin_reports_account_requirement(self):
        page, editor = self._ready_flow_page(navigation_error=RuntimeError("net::ERR_ABORTED"))
        self.browser._capture_captcha_page_state.return_value = {"location": "google_signin"}
        with self.assertRaises(BrowserCaptchaError) as raised:
            await self._prepare_ready_page(page)
        self.assertEqual(raised.exception.reason, "login_required")
        page.goto.assert_awaited_once()
        editor.wait_for.assert_not_awaited()

    async def test_successful_landing_redirect_stops_before_editor_or_captcha(self):
        page, editor = self._ready_flow_page()
        self.browser._capture_captcha_page_state.return_value = {"location": "flow_landing"}
        with self.assertRaises(BrowserCaptchaError) as raised:
            await self._prepare_ready_page(page)
        self.assertEqual((raised.exception.stage, raised.exception.reason), ("page_loaded", "flow_editor_unavailable"))
        page.goto.assert_awaited_once()
        editor.wait_for.assert_not_awaited()
        self.browser._wait_for_enterprise_ready.assert_not_awaited()

    async def test_application_editor_readiness_does_not_require_complete_load_event(self):
        page, editor = self._ready_flow_page()
        page.evaluate.return_value = "loading"
        self.assertTrue(await self._prepare_ready_page(page))
        self.assertEqual(editor.wait_for.await_args_list, [
            unittest.mock.call(timeout=15000), unittest.mock.call(timeout=15000),
        ])
        self.assertFalse(any(call.args[0] == "document.readyState" for call in page.evaluate.await_args_list))

    async def test_missing_application_editor_stops_before_captcha_readiness(self):
        page, editor = self._ready_flow_page()
        editor.wait_for.side_effect = TimeoutError("synthetic timeout")
        self.browser._capture_captcha_page_state.return_value = {"location": "flow_project", "editor_visible": False}
        with self.assertRaises(BrowserCaptchaError) as raised:
            await self._prepare_ready_page(page)
        self.assertEqual((raised.exception.stage, raised.exception.reason), ("editor_readiness", "editor_missing"))
        editor.wait_for.assert_awaited_once_with(timeout=15000)
        self.browser._wait_for_enterprise_ready.assert_not_awaited()

    def _editor_evidence_names(self):
        return sorted(name for name in os.listdir(self.directory.name) if name.startswith("editor-readiness-"))

    async def test_missing_editor_keeps_private_screenshot_and_allowlisted_diagnostics(self):
        self.browser.EDITOR_EVIDENCE_DIR = self.directory.name
        self.browser._shared_bound_token_id = 14
        page, editor = self._ready_flow_page()
        page.screenshot = AsyncMock(return_value=b"\x89PNG synthetic page")
        editor.wait_for.side_effect = TimeoutError("synthetic private timeout")
        self.browser._capture_captcha_page_state.return_value = {"location": "flow_project", "editor_visible": False}
        with self.assertRaises(BrowserCaptchaError) as raised:
            await self._prepare_ready_page(page)
        self.assertEqual((raised.exception.stage, raised.exception.reason), ("editor_readiness", "editor_missing"))
        pictures = [name for name in self._editor_evidence_names() if name.endswith(".png")]
        self.assertEqual(len(pictures), 1)
        picture = Path(self.directory.name) / pictures[0]
        self.assertEqual(picture.read_bytes(), b"\x89PNG synthetic page")
        self.assertEqual(stat.S_IMODE(picture.stat().st_mode), 0o600)
        log = Path(self.directory.name) / "editor-readiness-diagnostics.jsonl"
        self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
        entry = json.loads(log.read_text())
        self.assertEqual((entry["reason"], entry["screenshot"], entry["account_id"]),
                         ("editor_missing", pictures[0], 14))
        self.assertTrue(entry["diagnostics"])
        self.assertNotIn("synthetic private", log.read_text())

    async def test_editor_evidence_failure_never_replaces_the_original_error(self):
        self.browser.EDITOR_EVIDENCE_DIR = self.directory.name
        for screenshot in (AsyncMock(side_effect=RuntimeError("page closed")), AsyncMock(return_value=None)):
            with self.subTest(screenshot=repr(screenshot.side_effect)):
                page, editor = self._ready_flow_page()
                page.screenshot = screenshot
                editor.wait_for.side_effect = TimeoutError("synthetic timeout")
                with self.assertRaises(BrowserCaptchaError) as raised:
                    await self._prepare_ready_page(page)
                self.assertEqual((raised.exception.stage, raised.exception.reason), ("editor_readiness", "editor_missing"))
        self.assertEqual(self._editor_evidence_names(), [])

    async def test_editor_evidence_keeps_only_the_newest_screenshots(self):
        self.browser.EDITOR_EVIDENCE_DIR = self.directory.name
        self.browser.EDITOR_EVIDENCE_KEEP = 2
        for index in range(4):
            page, editor = self._ready_flow_page()
            page.screenshot = AsyncMock(return_value=f"png-{index}".encode())
            editor.wait_for.side_effect = TimeoutError("synthetic timeout")
            with self.assertRaises(BrowserCaptchaError):
                await self._prepare_ready_page(page)
        pictures = [name for name in self._editor_evidence_names() if name.endswith(".png")]
        self.assertEqual([(Path(self.directory.name) / name).read_bytes() for name in pictures],
                         [b"png-2", b"png-3"])

    async def test_ready_editor_takes_no_evidence(self):
        self.browser.EDITOR_EVIDENCE_DIR = self.directory.name
        page, _ = self._ready_flow_page()
        page.screenshot = AsyncMock(return_value=b"png")
        self.assertTrue(await self._prepare_ready_page(page))
        page.screenshot.assert_not_awaited()
        self.assertEqual(self._editor_evidence_names(), [])

    async def test_auth_redirect_during_editor_wait_reports_login(self):
        page, editor = self._ready_flow_page()
        editor.wait_for.side_effect = TimeoutError("synthetic timeout")
        self.browser._capture_captcha_page_state.side_effect = [
            {"location": "flow_project", "ready_state": "interactive"},
            {"location": "google_signin", "ready_state": "complete"},
        ]
        with self.assertRaises(BrowserCaptchaError) as raised:
            await self._prepare_ready_page(page)
        self.assertEqual(raised.exception.reason, "login_required")
        self.browser._wait_for_enterprise_ready.assert_not_awaited()

    async def test_editor_is_reconfirmed_after_captcha_warmup(self):
        for late_state, reason in (
            ({"location": "google_signin"}, "login_required"),
            ({"location": "flow_landing"}, "flow_editor_unavailable"),
            ({"location": "flow_project", "editor_visible": False}, "editor_missing"),
        ):
            with self.subTest(reason=reason):
                page, editor = self._ready_flow_page()
                editor.wait_for.side_effect = [None, TimeoutError("synthetic timeout")]
                self.browser._capture_captcha_page_state.side_effect = [
                    {"location": "flow_project"}, {"location": "flow_project", "editor_visible": True}, late_state,
                ]
                with self.assertRaises(BrowserCaptchaError) as raised:
                    await self._prepare_ready_page(page)
                self.assertEqual((raised.exception.stage, raised.exception.reason), ("editor_readiness", reason))
                self.browser._wait_for_enterprise_ready.assert_awaited_once()
                self.browser._capture_page_fingerprint.assert_not_awaited()

    async def test_captcha_readiness_failure_checks_auth_redirect(self):
        page, _ = self._ready_flow_page()
        self.browser._wait_for_enterprise_ready.return_value = False
        self.browser._capture_captcha_page_state.side_effect = [
            {"location": "flow_project"}, {"location": "flow_project", "editor_visible": True},
            {"location": "google_signin"},
        ]
        with self.assertRaises(BrowserCaptchaError) as raised:
            await self._prepare_ready_page(page)
        self.assertEqual((raised.exception.stage, raised.exception.reason), ("recaptcha_readiness", "login_required"))

    async def _prepare_route(self):
        page = types.SimpleNamespace(route=AsyncMock(), goto=AsyncMock(), close=AsyncMock())
        self.browser._capture_captcha_page_state = AsyncMock(return_value={"location": "google_signin"})
        with self.assertRaises(BrowserCaptchaError) as raised:
            await self.browser._prepare_flow_runtime_page(page, "project", "key", "action")
        self.assertEqual(raised.exception.reason, "login_required")
        return page, page.route.await_args.args[1]

    async def test_duplicate_native_requests_are_all_aborted(self):
        _, handler = await self._prepare_route()
        route = types.SimpleNamespace(request=types.SimpleNamespace(method="POST", url="https://flow.google.com/rpc/StreamChat", post_data="first"),
                                      abort=AsyncMock(), continue_=AsyncMock())
        await handler(route)
        route.request.post_data = "second"
        await handler(route)
        self.assertEqual(self.browser._harvest_streamchat_post, "first")
        self.assertEqual(route.abort.await_count, 2)
        route.continue_.assert_not_awaited()

    async def test_abort_failure_never_continues_request(self):
        page, handler = await self._prepare_route()
        route = types.SimpleNamespace(request=types.SimpleNamespace(method="POST", url="https://flow.google.com/rpc/StreamChat", post_data="sensitive"),
                                      abort=AsyncMock(side_effect=RuntimeError("failed")), continue_=AsyncMock())
        await handler(route)
        route.continue_.assert_not_awaited()
        page.close.assert_awaited_once()
        self.assertIsNone(self.browser._harvest_streamchat_post)
        self.assertEqual(self.browser._harvest_route_error, "request_interception_failed")

    async def _harvest_fixture(self, inner, prompt="safe & synthetic prompt", rpc="StreamChat"):
        self.browser.HARVEST_PROMPT_POOL = (prompt,)
        self.browser._harvest_streamchat_post = None
        self.browser._harvest_rpc = rpc
        outer = [None, json.dumps(inner)] if rpc == "StreamChat" else [[[rpc, json.dumps(inner), None, "generic"]]]
        encoded = urlencode({"other": "field", "f.req": json.dumps(outer), "after": "field"})
        editor = types.SimpleNamespace(wait_for=AsyncMock(), fill=AsyncMock(), inner_text=AsyncMock(return_value=prompt))
        editor.first = editor
        async def capture(**_kwargs):
            self.browser._harvest_streamchat_post = encoded
        submit = types.SimpleNamespace(click=AsyncMock(side_effect=capture))
        submit.first = submit
        page = types.SimpleNamespace(locator=lambda selector: editor if "ProseMirror" in selector else submit,
                                     keyboard=types.SimpleNamespace(press=AsyncMock()))
        self.browser._dismiss_flow_overlays = AsyncMock()
        result = await self.browser._harvest_token_via_ui_submit(page)
        return result, editor, page

    @staticmethod
    def _streamchat_inner(captcha_token, prompt="safe & synthetic prompt", session="fake-session"):
        return [session, [[[[prompt]]]], ["projects/fake-project", None, [captcha_token, 1], None, None, 3]]

    async def test_fill_and_form_parsing_preserve_encoded_ampersand(self):
        fake_token = "03AFsynthetic_token"
        result, editor, page = await self._harvest_fixture(self._streamchat_inner(fake_token))
        self.assertEqual(result, {"token": fake_token, "session_id": "fake-session", "transport": "streamchat", "rpc": "StreamChat"})
        editor.fill.assert_awaited_once_with("safe & synthetic prompt", timeout=4000)
        page.keyboard.press.assert_not_awaited()

    async def test_harvest_reads_opaque_token_field_instead_of_prompt_match(self):
        prompt = 'render ["0cAFcWnot_the_captcha"]'
        for fake_token in ("0cAFcWsynthetic_token", "03AFsynthetic_token", "opaque.future-token"):
            with self.subTest(prefix=fake_token):
                result, _, _ = await self._harvest_fixture(self._streamchat_inner(fake_token, prompt), prompt)
                self.assertEqual(result["token"], fake_token)

    async def test_harvest_rejects_empty_or_non_string_captcha(self):
        for fake_token in (None, "", "   ", 17, ["unexpected"]):
            with self.subTest(value=fake_token):
                with self.assertRaises(BrowserCaptchaError) as raised:
                    await self._harvest_fixture(self._streamchat_inner(fake_token))
                self.assertEqual(raised.exception.reason, "captcha_missing_in_request")

    async def test_harvest_does_not_treat_malformed_context_as_token(self):
        inner = self._streamchat_inner("unused")
        inner[2][2] = "03AFstring-is-not-a-context-array"
        with self.assertRaises(BrowserCaptchaError) as raised:
            await self._harvest_fixture(inner)
        self.assertEqual(raised.exception.reason, "generation_payload_invalid")

    @staticmethod
    def _image_rpc_argument(token="03AFsynthetic", session="synthetic-session"):
        client_context = [None] * 11
        client_context[10] = [token, 1]
        request = [None] * 15
        request[7] = client_context
        request[13] = session
        return [None, [request], 1, client_context, [session]]

    async def test_image_rpc_harvest_and_private_schema_diagnostic(self):
        result, _, _ = await self._harvest_fixture(self._image_rpc_argument(), rpc="ogiZ0b")
        self.assertEqual(result, {"token": "03AFsynthetic", "session_id": "synthetic-session",
                                  "transport": "batchexecute", "rpc": "ogiZ0b"})
        raw = json.dumps(self.browser._captcha_diagnostics)
        self.assertNotIn("03AFsynthetic", raw)
        self.assertNotIn("synthetic-session", raw)
        self.assertTrue(any(row.get("payload_shape", "").startswith("a5[") for row in self.browser._captcha_diagnostics))

    async def test_image_and_video_rpc_requests_are_aborted_before_parse(self):
        _, handler = await self._prepare_route()
        for rpc in ("ogiZ0b", "YhhmEf"):
            with self.subTest(rpc=rpc):
                self.browser._harvest_streamchat_post = None
                body = urlencode({"f.req": json.dumps([[[rpc, json.dumps(self._image_rpc_argument()), None, "generic"]]])})
                # Body matching also covers a missing/unexpected rpcids query.
                route = types.SimpleNamespace(request=types.SimpleNamespace(method="POST", url="https://flow.google.com/data/batchexecute", post_data=body),
                                              abort=AsyncMock(), continue_=AsyncMock())
                await handler(route)
                route.abort.assert_awaited_once()
                route.continue_.assert_not_awaited()
                self.assertEqual(self.browser._harvest_rpc, rpc)

    async def test_malformed_generation_payload_is_still_aborted_from_query(self):
        _, handler = await self._prepare_route()
        route = types.SimpleNamespace(request=types.SimpleNamespace(method="POST", url="https://flow.google.com/data/batchexecute?rpcids=other,ogiZ0b", post_data="malformed"),
                                      abort=AsyncMock(), continue_=AsyncMock())
        await handler(route)
        route.abort.assert_awaited_once()
        route.continue_.assert_not_awaited()

    async def test_read_only_rpc_is_not_blocked(self):
        _, handler = await self._prepare_route()
        body = urlencode({"f.req": json.dumps([[["syntheticRead", "[]", None, "generic"]]])})
        route = types.SimpleNamespace(request=types.SimpleNamespace(method="POST", url="https://flow.google.com/data/batchexecute?rpcids=syntheticRead", post_data=body),
                                      abort=AsyncMock(), continue_=AsyncMock())
        await handler(route)
        route.abort.assert_not_awaited()
        route.continue_.assert_awaited_once()

    async def test_video_rpc_is_captured_but_explicitly_unsupported(self):
        with self.assertRaises(BrowserCaptchaError) as raised:
            await self._harvest_fixture([[], [], []], rpc="YhhmEf")
        self.assertEqual(raised.exception.reason, "generation_rpc_unsupported")
        self.assertTrue(any(row.get("payload_shape") for row in self.browser._captcha_diagnostics))

    async def test_transport_metadata_is_preserved_in_fingerprint(self):
        page = types.SimpleNamespace(on=Mock(), add_init_script=AsyncMock(), close=AsyncMock())
        context = types.SimpleNamespace(new_page=AsyncMock(return_value=page))
        self.browser._last_fingerprint = {"user_agent": "synthetic-agent"}
        self.browser._apply_browser_environment_patch = AsyncMock()
        self.browser._prepare_flow_runtime_page = AsyncMock(return_value=True)
        self.browser._harvest_token_via_ui_submit = AsyncMock(return_value={"token": "synthetic", "session_id": "session", "transport": "batchexecute", "rpc": "ogiZ0b"})
        token = await self.browser._execute_captcha(context, "project", "key", "CHAT_GENERATION")
        self.assertEqual(token, "synthetic")
        self.assertEqual(self.browser.get_last_fingerprint(), {"user_agent": "synthetic-agent", "harvest_transport": "batchexecute", "harvest_rpc": "ogiZ0b"})

    async def test_whole_solve_deadline_includes_browser_acquisition(self):
        async def hang(**_kwargs):
            await asyncio.sleep(10)
        self.browser._get_or_create_shared_browser = AsyncMock(side_effect=hang)
        self.browser.CAPTCHA_SOLVE_TIMEOUT_SECONDS = 0.02
        self.browser.CAPTCHA_REQUEST_TIMEOUT_SECONDS = 0.2
        started = time.monotonic()
        with self.assertRaises(BrowserCaptchaError) as raised:
            await self.browser.get_token("project", "key")
        self.assertLess(time.monotonic() - started, 0.2)
        self.assertEqual(raised.exception.stage, "browser_acquisition")
        self.assertEqual(raised.exception.reason, "timeout")
        self.browser._get_or_create_shared_browser.assert_awaited_once()
        self.assertEqual(self.browser._solve_inflight, 0)

    async def test_request_deadline_includes_waiting_for_slot(self):
        await self.browser._semaphore.acquire()
        self.browser.CAPTCHA_REQUEST_TIMEOUT_SECONDS = 0.02
        with self.assertRaises(BrowserCaptchaError) as raised:
            await self.browser.get_token("project", "key")
        self.assertEqual(raised.exception.stage, "request_deadline")
        self.assertEqual(self.browser._solve_inflight, 0)

    async def test_login_failure_does_not_retry(self):
        self.browser._get_or_create_shared_browser = AsyncMock(side_effect=BrowserCaptchaError("cookie_binding", "login_credentials_missing"))
        with self.assertRaises(BrowserCaptchaError):
            await self.browser.get_token("project", "key")
        self.browser._get_or_create_shared_browser.assert_awaited_once()

    async def test_success_keeps_captcha_and_session_contract(self):
        self.browser._get_or_create_shared_browser = AsyncMock(return_value=(object(), object(), object()))
        self.browser._execute_captcha = AsyncMock(return_value="fake-captcha")
        self.browser._last_harvest_session_id = "fake-session"
        result = await self.browser.get_token("project", "key")
        self.assertEqual(result, ("fake-captcha", "fake-session"))
        self.assertEqual(self.browser._solve_count, 1)
        self.assertEqual(self.browser._error_count, 0)

    async def test_cookie_binding_failure_keeps_category_without_cookie_values(self):
        self.browser._load_token_session_binding = AsyncMock(return_value=(1, None, "SID=private-value", "fake-signature"))
        self.browser._shared_bound_token_id = None
        context = types.SimpleNamespace(clear_cookies=AsyncMock(), add_cookies=AsyncMock(
            side_effect=RuntimeError("Cookie should have either url or path private-value")))
        with self.assertRaises(BrowserCaptchaError) as raised:
            await self.browser._ensure_shared_token_binding(context, 1)
        self.assertEqual(raised.exception.reason, "cookie_scope_invalid")
        self.assertNotIn("private-value", str(raised.exception))
        self.assertNotIn("private-value", json.dumps(self.browser._captcha_diagnostics))

    async def test_pool_deadline_covers_admission(self):
        service = BrowserCaptchaService.__new__(BrowserCaptchaService)
        async def hang(*_args):
            await asyncio.sleep(10)
        service._get_token_from_pool = AsyncMock(side_effect=hang)
        original = TokenBrowser.CAPTCHA_REQUEST_TIMEOUT_SECONDS
        TokenBrowser.CAPTCHA_REQUEST_TIMEOUT_SECONDS = 0.02
        try:
            with self.assertRaises(BrowserCaptchaError) as raised:
                await service.get_token("project")
        finally:
            TokenBrowser.CAPTCHA_REQUEST_TIMEOUT_SECONDS = original
        self.assertEqual(raised.exception.stage, "pool_deadline")

    def _native_image_service(self):
        service = BrowserCaptchaService.__new__(BrowserCaptchaService)
        service._check_available = Mock()
        service._stats = {"req_total": 0, "gen_ok": 0, "gen_fail": 0, "api_403": 0}
        service._token_semaphore = asyncio.Semaphore(1)
        service._slot_allocation_lock = asyncio.Lock()
        service._slot_condition = asyncio.Condition(service._slot_allocation_lock)
        service._slot_recovery = {}
        service._requests = {}
        service._cleanup_tasks = set()
        service._closed = False
        service._queue_timeouts = 0
        service._queue_wait_total_seconds = 0.0
        service._admitted_requests = 0
        service._browsers_lock = asyncio.Lock()
        service._slot_reservations = {}
        service._browsers = {0: self.browser}
        service._browser_count = 1
        service._round_robin_index = 0
        service.website_key = "synthetic-site-key"
        service._resolve_token_proxy_url = AsyncMock(return_value="synthetic-proxy")
        self.browser.has_shared_browser = Mock(return_value=True)
        self.browser._get_or_create_shared_browser = AsyncMock(return_value=(None, None, "bound-context"))
        self.browser.get_token = AsyncMock()
        self.browser._last_fingerprint = {"user_agent": "synthetic-agent"}
        return service

    async def test_five_native_browser_slots_run_independently_and_queue_sixth(self):
        from copy import copy

        service = self._native_image_service()
        service._browser_count = 5
        service._token_semaphore = asyncio.Semaphore(5)
        service._browsers = {}
        for slot_id in range(5):
            browser = copy(self.browser)
            browser.token_id = slot_id
            browser._semaphore = asyncio.Semaphore(1)
            browser._captcha_diagnostics = []
            browser._get_or_create_shared_browser = AsyncMock(
                return_value=(None, None, f"synthetic-context-{slot_id}")
            )
            service._browsers[slot_id] = browser

        five_started = asyncio.Event()
        release = asyncio.Event()
        entries = []
        inflight = 0
        peak = 0

        async def submit(browser, context, project_id, spec, timeout):
            nonlocal inflight, peak
            self.assertEqual(context, f"synthetic-context-{browser.token_id}")
            entries.append(browser.token_id)
            inflight += 1
            peak = max(peak, inflight)
            if len(entries) == 5:
                five_started.set()
            try:
                await release.wait()
                return {"rpc": "YhhmEf", "response_text": "synthetic"}
            finally:
                inflight -= 1

        with patch("src.services.native_video_submission.submit_native_video", submit):
            tasks = [asyncio.create_task(service.generate_video(
                f"synthetic-project-{index}", index + 1, "prompt", "omni", "portrait", timeout=2
            )) for index in range(5)]
            await asyncio.wait_for(five_started.wait(), timeout=1)
            sixth = asyncio.create_task(service.generate_video(
                "synthetic-project-6", 6, "prompt", "omni", "portrait", timeout=2
            ))
            await asyncio.sleep(0.03)
            self.assertEqual(set(entries), set(range(5)))
            self.assertEqual(len(entries), 5)
            self.assertEqual(service._slot_reservations, {index: 1 for index in range(5)})
            release.set()
            await asyncio.gather(*tasks, sixth)
        self.assertEqual(peak, 5)
        self.assertEqual(len(entries), 6)
        self.assertEqual(service._slot_reservations, {})
        self.assertTrue(all(browser._solve_inflight == 0 for browser in service._browsers.values()))

    async def test_native_image_wrapper_holds_account_slot_until_response(self):
        service = self._native_image_service()
        image_inputs = [{"mediaId": "synthetic-input"}]
        async def submit(browser, context, project_id, spec, timeout):
            self.assertIs(browser, self.browser)
            self.assertEqual(context, "bound-context")
            self.assertEqual(project_id, "project")
            self.assertTrue(service._token_semaphore.locked())
            self.assertTrue(browser._semaphore.locked())
            self.assertEqual(browser._solve_inflight, 1)
            self.assertEqual(service._slot_reservations, {0: 1})
            self.assertEqual(spec, {"website_key": "synthetic-site-key", "prompt": "actual prompt", "model_name": "model", "aspect_ratio": "ratio", "image_inputs": image_inputs})
            self.assertIsNot(spec["image_inputs"], image_inputs)
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 1)
            return {"rpc": "ogiZ0b", "response_text": "synthetic-response", "session_id": "synthetic-session"}
        helper = AsyncMock(side_effect=submit)
        with patch.dict(sys.modules, {"src.services.native_image_submission": types.SimpleNamespace(submit_native_image=helper)}):
            result = await service.generate_image("project", 42, "actual prompt", "model", "ratio", image_inputs, timeout=1)
        self.browser._get_or_create_shared_browser.assert_awaited_once_with(token_proxy_url="synthetic-proxy", token_id=42)
        helper.assert_awaited_once()
        self.browser.get_token.assert_not_awaited()
        self.assertEqual(result["response_text"], "synthetic-response")
        self.assertEqual(result["fingerprint"], {"user_agent": "synthetic-agent"})
        self.assertEqual(service._slot_reservations, {})
        self.assertFalse(service._token_semaphore.locked())
        self.assertFalse(self.browser._semaphore.locked())
        self.assertEqual(self.browser._solve_inflight, 0)
        self.assertEqual(service._stats["gen_ok"], 1)
        self.browser.note_idle.assert_called_once()

    async def test_native_image_wrapper_releases_slot_without_retry_on_failure(self):
        service = self._native_image_service()
        service._token_semaphore = None
        failure = BrowserCaptchaError("native_submit", "upstream_rejected")
        helper = AsyncMock(side_effect=failure)
        with patch.dict(sys.modules, {"src.services.native_image_submission": types.SimpleNamespace(submit_native_image=helper)}):
            with self.assertRaises(BrowserCaptchaError) as raised:
                await service.generate_image("project", 42, "prompt", "model", "ratio", timeout=1)
        self.assertIs(raised.exception, failure)
        helper.assert_awaited_once()
        self.assertEqual(service._slot_reservations, {})
        self.assertFalse(self.browser._semaphore.locked())
        self.assertEqual(self.browser._solve_inflight, 0)
        self.assertEqual(self.browser._error_count, 1)
        self.assertEqual(service._stats["gen_fail"], 1)

    async def test_native_image_deadline_covers_waiting_for_slot(self):
        service = self._native_image_service()
        await self.browser._semaphore.acquire()
        with self.assertRaises(BrowserCaptchaError) as raised:
            await service.generate_image("project", 42, "prompt", "model", "ratio", timeout=0.02)
        self.assertEqual(raised.exception.stage, "native_image_deadline")
        self.assertEqual(service._slot_reservations, {})
        self.assertFalse(service._token_semaphore.locked())
        self.assertEqual(self.browser._solve_inflight, 0)
        self.browser._get_or_create_shared_browser.assert_not_awaited()
        self.browser._semaphore.release()

    async def test_native_image_timeout_cancels_submit_then_releases_resources(self):
        service = self._native_image_service()
        cleaned_up = asyncio.Event()
        async def submit(*_args, **_kwargs):
            try:
                await asyncio.sleep(10)
            finally:
                cleaned_up.set()
        helper = AsyncMock(side_effect=submit)
        with patch.dict(sys.modules, {"src.services.native_image_submission": types.SimpleNamespace(submit_native_image=helper)}):
            with self.assertRaises(BrowserCaptchaError) as raised:
                await service.generate_image("project", 42, "prompt", "model", "ratio", timeout=0.02)
        self.assertEqual(raised.exception.stage, "native_image_deadline")
        self.assertTrue(cleaned_up.is_set())
        self.assertEqual(service._slot_reservations, {})
        self.assertFalse(self.browser._semaphore.locked())
        self.assertFalse(service._token_semaphore.locked())
        self.assertEqual(self.browser._solve_inflight, 0)
        helper.assert_awaited_once()

    async def test_native_image_external_cancellation_releases_resources(self):
        service = self._native_image_service()
        started = asyncio.Event()
        async def submit(*_args, **_kwargs):
            started.set()
            await asyncio.sleep(10)
        with patch.dict(sys.modules, {"src.services.native_image_submission": types.SimpleNamespace(submit_native_image=submit)}):
            task = asyncio.create_task(service.generate_image("project", 42, "prompt", "model", "ratio", timeout=1))
            await started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(service._slot_reservations, {})
        self.assertFalse(self.browser._semaphore.locked())
        self.assertFalse(service._token_semaphore.locked())
        self.assertEqual(self.browser._solve_inflight, 0)
        self.browser.note_idle.assert_called_once()

    async def test_native_video_wrapper_forwards_video_spec_under_bound_slot(self):
        service = self._native_image_service()
        async def submit(browser, context, project_id, spec, timeout):
            self.assertIs(browser, self.browser)
            self.assertEqual(context, "bound-context")
            self.assertEqual(project_id, "video-project")
            self.assertEqual(spec, {"website_key": "synthetic-site-key", "prompt": "video prompt", "model_key": "omni", "aspect_ratio": "landscape", "mode": "text", "frame_images": [], "resolution": None})
            self.assertTrue(service._token_semaphore.locked())
            self.assertTrue(browser._semaphore.locked())
            self.assertEqual(service._slot_reservations, {0: 1})
            self.assertEqual(browser._solve_inflight, 1)
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 1)
            return {"rpc": "YhhmEf", "response_text": "synthetic-operation"}
        helper = AsyncMock(side_effect=submit)
        with patch.dict(sys.modules, {"src.services.native_video_submission": types.SimpleNamespace(submit_native_video=helper)}):
            result = await service.generate_video("video-project", 42, "video prompt", "omni", "landscape", timeout=1)
        helper.assert_awaited_once()
        self.browser._get_or_create_shared_browser.assert_awaited_once_with(token_proxy_url="synthetic-proxy", token_id=42)
        self.browser.get_token.assert_not_awaited()
        self.assertEqual(result["rpc"], "YhhmEf")
        self.assertEqual(result["fingerprint"], {"user_agent": "synthetic-agent"})
        self.assertEqual(service._slot_reservations, {})
        self.assertFalse(service._token_semaphore.locked())
        self.assertFalse(self.browser._semaphore.locked())
        self.assertEqual(self.browser._solve_inflight, 0)
        self.assertEqual(service._stats["gen_ok"], 1)
        self.browser.note_idle.assert_called_once()

    async def test_native_video_failure_releases_slot_without_retry(self):
        service = self._native_image_service()
        failure = BrowserCaptchaError("native_video_submit", "upstream_rejected")
        helper = AsyncMock(side_effect=failure)
        with patch.dict(sys.modules, {"src.services.native_video_submission": types.SimpleNamespace(submit_native_video=helper)}):
            with self.assertRaises(BrowserCaptchaError) as raised:
                await service.generate_video("project", 42, "prompt", "omni", "landscape", timeout=1)
        self.assertIs(raised.exception, failure)
        helper.assert_awaited_once()
        self.assertEqual(service._slot_reservations, {})
        self.assertFalse(service._token_semaphore.locked())
        self.assertFalse(self.browser._semaphore.locked())
        self.assertEqual(self.browser._solve_inflight, 0)
        self.assertEqual(service._stats["gen_fail"], 1)

    async def test_native_video_deadline_covers_pool_admission(self):
        service = self._native_image_service()
        await service._token_semaphore.acquire()
        with self.assertRaises(BrowserCaptchaError) as raised:
            await service.generate_video("project", 42, "prompt", "omni", "landscape", timeout=0.02)
        self.assertEqual(raised.exception.stage, "native_video_deadline")
        self.assertEqual(service._slot_reservations, {})
        self.browser._get_or_create_shared_browser.assert_not_awaited()
        service._token_semaphore.release()

    async def test_cancelled_proxy_lookup_leaves_no_started_playwright_runtime(self):
        self.browser._profile_viewport = {"width": 1280, "height": 720}
        self.browser._cleanup_stale_slot_process = AsyncMock()
        started_runtimes = []
        runtime = types.SimpleNamespace()
        async def start():
            started_runtimes.append(runtime)
            return runtime
        async def stop():
            started_runtimes.remove(runtime)
        runtime.stop = AsyncMock(side_effect=stop)
        async def lookup(**_kwargs):
            await asyncio.sleep(10)
        self.browser._resolve_proxy_runtime_config = AsyncMock(side_effect=lookup)
        with patch.dict(namespace, {"async_playwright": Mock(return_value=types.SimpleNamespace(start=AsyncMock(side_effect=start)))}):
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(self.browser._create_browser(), timeout=0.02)
        self.assertEqual(started_runtimes, [])


if __name__ == "__main__":
    unittest.main()
