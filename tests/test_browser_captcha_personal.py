import ast
import itertools
import json
import shutil
import subprocess
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlparse

from src.services.browser_captcha_personal import (
    BrowserCaptchaService,
    ResidentTabInfo,
    _PersonalBrowserPoolService,
    _compose_proxy_url,
    _patch_nodriver_connection_instance,
    _redact_proxy_url,
)


class _FakeTab:
    def __init__(self, result):
        self._result = result

    async def evaluate(self, expression, await_promise=False, return_by_value=False):
        return self._result


class _ClosableFakeTab:
    def __init__(self):
        self.closed = False

    async def close(self):
        self.closed = True

    async def sleep(self, _seconds):
        return None


class _FakeWebSocket:
    def __init__(self, owner):
        self.owner = owner
        self.close_code = None
        self.messages = []

    async def send(self, message):
        self.messages.append(message)
        payload = json.loads(message)
        transaction = self.owner.mapper[payload["id"]]
        transaction(result={"ok": True})


class _ConnectionWithoutClosed:
    def __init__(self):
        self.mapper = {}
        self.handlers = {}
        self.websocket = None
        self.connect_count = 0
        self.register_count = 0
        self.__count__ = itertools.count(0)

    async def send(self, _cdp_obj, _is_update=False):
        raise AssertionError("original send should be patched")

    async def connect(self):
        self.connect_count += 1
        self.websocket = _FakeWebSocket(self)

    async def _register_handlers(self):
        self.register_count += 1


def _fake_cdp_command():
    result = yield {"method": "Runtime.evaluate", "params": {}}
    return result


class BrowserCaptchaPersonalTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.service = BrowserCaptchaService()

    def test_authenticated_proxy_url_is_preserved_for_flow_requests(self):
        proxy_url = _compose_proxy_url(
            "http", "proxy.example.com", "8080", "user", "password"
        )

        self.assertEqual(proxy_url, "http://user:password@proxy.example.com:8080")
        self.assertEqual(
            _redact_proxy_url(proxy_url),
            "http://***:***@proxy.example.com:8080",
        )

    @staticmethod
    def _make_remote_object_result(token: str):
        return types.SimpleNamespace(
            type_="object",
            value=None,
            deep_serialized_value=types.SimpleNamespace(
                type_="object",
                value=[
                    ["ok", {"type": "boolean", "value": True}],
                    ["token", {"type": "string", "value": token}],
                ],
            ),
        )

    async def test_tab_evaluate_normalizes_deep_serialized_remote_object(self):
        tab = _FakeTab(self._make_remote_object_result("token-123"))

        result = await self.service._tab_evaluate(
            tab,
            "ignored",
            label="unit_test_tab_evaluate",
            await_promise=True,
            return_by_value=True,
        )

        self.assertEqual(result, {"ok": True, "token": "token-123"})

    async def test_execute_recaptcha_on_tab_accepts_remote_object_success_result(self):
        tab = _FakeTab(self._make_remote_object_result("token-xyz"))

        token = await self.service._execute_recaptcha_on_tab(
            tab, action="IMAGE_GENERATION"
        )

        self.assertEqual(token, "token-xyz")

    async def test_create_resident_tab_returns_none_when_browser_missing(self):
        self.service.browser = None

        resident_info = await self.service._create_resident_tab(
            "slot-1", project_id="project-1"
        )

        self.assertIsNone(resident_info)

    async def test_load_token_cookie_reads_google_cookies_field(self):
        self.service.db = types.SimpleNamespace(
            get_token=AsyncMock(
                return_value=types.SimpleNamespace(
                    google_cookies="OSID=flow-cookie; SID=google-cookie"
                )
            )
        )

        cookie_text = await self.service._load_token_cookie(7)

        self.assertEqual(cookie_text, "OSID=flow-cookie; SID=google-cookie")
        self.service.db.get_token.assert_awaited_once_with(7)

    async def test_persist_context_cookies_updates_google_cookies_field(self):
        resident_info = ResidentTabInfo(
            tab=object(),
            slot_id="slot-1",
            token_id=7,
            browser_context_id="context-1",
        )
        self.service.db = types.SimpleNamespace(update_token=AsyncMock())
        self.service._get_browser_cookies = AsyncMock(
            return_value=[
                {
                    "name": "OSID",
                    "value": "flow-cookie",
                    "domain": "flow.google.com",
                    "path": "/",
                    "secure": True,
                }
            ]
        )
        self.service._load_token_cookie = AsyncMock(return_value="SID=google-cookie")

        persisted = await self.service._persist_context_cookies_to_token(
            resident_info,
            7,
            label="unit_test",
        )

        self.assertTrue(persisted)
        self.service.db.update_token.assert_awaited_once()
        args, kwargs = self.service.db.update_token.await_args
        self.assertEqual(args, (7,))
        self.assertIn("google_cookies", kwargs)
        self.assertNotIn("cookie", kwargs)
        self.assertIn("OSID", kwargs["google_cookies"])

    async def test_close_clears_resident_tabs_when_warmup_task_attr_missing(self):
        tab = _ClosableFakeTab()
        self.service._resident_tabs["slot-1"] = ResidentTabInfo(
            tab=tab, slot_id="slot-1"
        )
        if hasattr(self.service, "_resident_warmup_task"):
            delattr(self.service, "_resident_warmup_task")

        await self.service.close()

        self.assertEqual(self.service._resident_tabs, {})
        self.assertTrue(tab.closed)

    async def test_create_resident_tab_cleans_tab_when_initialization_fails(self):
        tab = _ClosableFakeTab()
        self.service.browser = types.SimpleNamespace(stopped=False)
        self.service._create_isolated_context_tab = AsyncMock(
            return_value=(tab, "context-1")
        )
        self.service._tab_evaluate = AsyncMock(return_value="complete")
        self.service._apply_token_cookie_binding = AsyncMock(
            side_effect=RuntimeError("cookie failed")
        )
        self.service._dispose_browser_context_quietly = AsyncMock()
        self.service._close_tab_quietly = AsyncMock()

        resident_info = await self.service._create_resident_tab(
            "slot-1", project_id="project-1"
        )

        self.assertIsNone(resident_info)
        self.service._dispose_browser_context_quietly.assert_awaited_once_with(
            "context-1"
        )
        self.service._close_tab_quietly.assert_awaited_once_with(tab)

    async def test_restart_browser_for_project_reuses_recent_healthy_runtime(self):
        resident_info = ResidentTabInfo(
            tab=object(), slot_id="slot-1", project_id="project-1"
        )
        self.service.browser = types.SimpleNamespace(stopped=False)
        self.service._initialized = True
        self.service._mark_runtime_restart()
        self.service._probe_browser_runtime = AsyncMock(return_value=True)
        self.service._ensure_resident_tab = AsyncMock(
            return_value=("slot-1", resident_info)
        )
        self.service._restart_browser_for_project_unlocked = AsyncMock(
            return_value=True
        )

        result = await self.service._restart_browser_for_project("project-1")

        self.assertTrue(result)
        self.service._restart_browser_for_project_unlocked.assert_not_awaited()
        self.service._ensure_resident_tab.assert_awaited_once()

    async def test_wait_for_recaptcha_raises_on_runtime_disconnect(self):
        tab = _ClosableFakeTab()
        runtime_error = ConnectionRefusedError(1225, "远程计算机拒绝网络连接。")
        self.service._inject_recaptcha_bootstrap_script = AsyncMock(
            return_value="remote"
        )
        self.service._tab_evaluate = AsyncMock(side_effect=runtime_error)

        with self.assertRaises(ConnectionRefusedError):
            await self.service._wait_for_recaptcha(tab)

        self.assertFalse(self.service._last_health_probe_ok)
        self.assertEqual(self.service._tab_evaluate.await_count, 1)

    def test_all_bootstrap_candidates_request_trusted_types_compatible_loader(self):
        for script_path in ("recaptcha/enterprise.js", "/recaptcha/api.js"):
            for website_key in (None, "test-site-key"):
                with self.subTest(script_path=script_path, website_key=website_key):
                    urls = self.service._get_recaptcha_bootstrap_candidate_urls(
                        script_path, website_key=website_key
                    )
                    self.assertEqual(len(urls), 2)
                    for url in urls:
                        parsed = urlparse(url)
                        query = parse_qs(parsed.query)
                        self.assertEqual(query.get("trustedtypes"), ["true"])
                        self.assertEqual(parsed.path, "/" + script_path.lstrip("/"))
                        self.assertEqual(query.get("render"), [website_key] if website_key else None)

    async def _run_bootstrap_in_fake_dom(
        self, *, source=None, argument=None, fail_assignment=False, fail_append=False
    ):
        node_path = shutil.which("node")
        if not node_path:
            self.skipTest("Node.js is required to execute the bootstrap DOM regression")
        if source is None:
            self.service._tab_evaluate = AsyncMock()
            await self.service._inject_recaptcha_bootstrap_script(
                object(),
                script_path="recaptcha/enterprise.js",
                website_key="test-site-key",
                label="trusted_types_regression",
            )
            source = self.service._tab_evaluate.await_args.args[1]
        harness = r"""
const vm = require('node:vm');
const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const timers = new Map();
const scripts = [];
const attempts = [];
const policies = [];
let assignmentCount = 0;
let appendCount = 0;
let nextTimer = 1;
const window = {};
const nonceSource = { nonce: 'page-nonce', getAttribute: () => 'page-nonce' };
const trustedTypes = {
    createPolicy(name, rules) {
        const policy = {
            createScriptURL(value) {
                return { trustedScriptURL: true, value: rules.createScriptURL(value) };
            },
        };
        policies.push(policy);
        return policy;
    },
};
window.trustedTypes = trustedTypes;
const document = {
    querySelector(selector) {
        if (selector === 'script[nonce]') return nonceSource;
        return scripts.find(script => script.src.includes('recaptcha')) || null;
    },
    querySelectorAll() {
        return scripts.filter(script => script.src.includes('recaptcha'));
    },
    createElement() {
        let source = '';
        return {
            nonce: '',
            set src(value) {
                assignmentCount++;
                if (!value || !value.trustedScriptURL) {
                    throw new TypeError("Failed to set the 'src' property on 'HTMLScriptElement': This document requires 'TrustedScriptURL' assignment.");
                }
                attempts.push(value.value);
                if (input.failAssignment) throw new TypeError('src assignment blocked');
                source = value.value;
            },
            get src() { return source; },
            remove() {
                const index = scripts.indexOf(this);
                if (index >= 0) scripts.splice(index, 1);
            },
        };
    },
    head: {
        appendChild(script) {
            appendCount++;
            if (input.failAppend && appendCount === 1) throw new Error('append blocked');
            scripts.push(script);
            script.onload();
        },
    },
};
const context = vm.createContext({
    window, document, trustedTypes,
    setTimeout(callback) { const id = nextTimer++; timers.set(id, callback); return id; },
    clearTimeout(id) { timers.delete(id); },
});
const runBootstrap = () => {
    const result = vm.runInContext(input.source, context);
    if (typeof result === 'function') result(input.argument);
};
runBootstrap();
// A forced retry on the same page must reuse its policy and nonce.
if (input.repeat) runBootstrap();
const allowedCandidate = 'https://www.google.com/recaptcha/enterprise.js?render=test-site-key&trustedtypes=true';
const rejectsUnrelated = policies.every(policy => {
    try { policy.createScriptURL('https://example.com/unrelated.js'); return false; }
    catch (error) { return error.name === 'TypeError'; }
});
const acceptsFallback = policies.every(policy => policy.createScriptURL(allowedCandidate).value === allowedCandidate);
const state = window.__flow2apiRecaptchaBootstrapState;
process.stdout.write(JSON.stringify({
    state: { status: state.status, error: state.error, attempts: state.attempts, url: state.url },
    scripts: scripts.map(script => ({ src: script.src, nonce: script.nonce })),
    attempts, assignmentCount, appendCount, pendingTimers: timers.size,
    policyCount: policies.length, rejectsUnrelated, acceptsFallback,
}));
"""
        result = subprocess.run(
            [node_path, "-e", harness],
            input=json.dumps({
                "source": source,
                "argument": argument,
                "failAssignment": fail_assignment,
                "failAppend": fail_append,
                "repeat": not (fail_assignment or fail_append),
            }),
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    @staticmethod
    def _browser_enterprise_wait_method():
        # Importing browser_captcha may install Chromium. Compile only the actual
        # method under test so these DOM regressions never start runtime setup.
        source_path = Path(__file__).parents[1] / "src/services/browser_captcha.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        browser_class = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "TokenBrowser"
        )
        method = next(
            node for node in browser_class.body
            if isinstance(node, ast.AsyncFunctionDef)
            and node.name == "_wait_for_enterprise_ready"
        )
        namespace = {
            "debug_logger": types.SimpleNamespace(log_warning=lambda *_args: None)
        }
        exec(compile(ast.Module(body=[method], type_ignores=[]), str(source_path), "exec"), namespace)
        return namespace[method.name]

    async def _run_browser_enterprise_fallback(self, **dom_options):
        page = types.SimpleNamespace(
            wait_for_function=AsyncMock(side_effect=[TimeoutError("not ready"), None]),
            add_script_tag=AsyncMock(side_effect=RuntimeError("CSP rejects bare script")),
        )
        dom_result = None
        arguments = None

        # This matches Playwright's signature, which accepts only one argument.
        async def evaluate(expression, arg=None):
            nonlocal dom_result, arguments
            arguments = arg
            dom_result = await self._run_bootstrap_in_fake_dom(
                source=expression, argument=arg, **dom_options
            )
            if dom_result["state"]["status"] == "error":
                page.wait_for_function.side_effect = TimeoutError("bootstrap failed")

        page.evaluate = evaluate
        result = await self._browser_enterprise_wait_method()(
            types.SimpleNamespace(token_id=1),
            page,
            "test-site-key",
            "https://www.recaptcha.net",
            "https://www.google.com",
        )
        return result, page, dom_result, arguments

    async def test_browser_enterprise_fallback_uses_one_playwright_argument(self):
        ready, page, result, urls = await self._run_browser_enterprise_fallback()

        self.assertTrue(ready)
        self.assertEqual(len(urls), 2)
        for url in urls:
            self.assertEqual(parse_qs(urlparse(url).query), {
                "render": ["test-site-key"], "trustedtypes": ["true"]
            })
        self.assertEqual(result["scripts"][0]["nonce"], "page-nonce")
        page.add_script_tag.assert_not_awaited()

    async def test_browser_enterprise_bootstrap_executes_under_enforced_trusted_types(self):
        page = types.SimpleNamespace(
            wait_for_function=AsyncMock(side_effect=[TimeoutError("not ready"), None]),
            evaluate=AsyncMock(),
            add_script_tag=AsyncMock(side_effect=RuntimeError("CSP rejects bare script")),
        )
        await self._browser_enterprise_wait_method()(
            types.SimpleNamespace(token_id=1), page, "test-site-key",
            "https://www.recaptcha.net", "https://www.google.com",
        )
        # Accept the old Python call signature here to isolate its independent
        # TrustedScriptURL sink failure from the Playwright argument regression.
        call = page.evaluate.await_args.args
        argument = call[1] if len(call) == 2 else list(call[1:])
        result = await self._run_bootstrap_in_fake_dom(source=call[0], argument=argument)

        self.assertEqual(result["state"]["status"], "loaded")
        self.assertEqual(result["policyCount"], 1)
        self.assertTrue(result["rejectsUnrelated"])
        self.assertTrue(result["acceptsFallback"])
        self.assertEqual(result["pendingTimers"], 0)

    async def test_browser_enterprise_src_failure_returns_false_and_records_error(self):
        ready, page, result, _urls = await self._run_browser_enterprise_fallback(
            fail_assignment=True
        )

        self.assertFalse(ready)
        self.assertEqual(result["state"]["status"], "error")
        self.assertIn("src assignment blocked", result["state"]["error"])
        self.assertEqual(len(result["attempts"]), 2)
        self.assertEqual(result["pendingTimers"], 0)
        page.add_script_tag.assert_not_awaited()

    async def test_browser_enterprise_append_failure_tries_secondary_url(self):
        ready, page, result, _urls = await self._run_browser_enterprise_fallback(
            fail_append=True
        )

        self.assertTrue(ready)
        self.assertEqual(result["state"]["status"], "loaded")
        self.assertEqual(result["appendCount"], 2)
        self.assertIn("www.google.com/recaptcha/enterprise.js", result["scripts"][0]["src"])
        self.assertEqual(result["scripts"][0]["nonce"], "page-nonce")
        self.assertEqual(result["pendingTimers"], 0)
        page.add_script_tag.assert_not_awaited()

    async def test_browser_enterprise_ready_preserves_native_page_without_injection(self):
        page = types.SimpleNamespace(wait_for_function=AsyncMock(), evaluate=AsyncMock())
        ready = await self._browser_enterprise_wait_method()(
            types.SimpleNamespace(token_id=1), page, "test-site-key",
            "https://www.recaptcha.net", "https://www.google.com",
        )

        self.assertTrue(ready)
        page.evaluate.assert_not_awaited()

    async def test_bootstrap_supports_enforced_trusted_types_and_page_nonce(self):
        result = await self._run_bootstrap_in_fake_dom()

        self.assertEqual(result["state"]["status"], "loaded")
        self.assertEqual(result["scripts"][0]["nonce"], "page-nonce")
        self.assertIn("www.recaptcha.net/recaptcha/enterprise.js", result["scripts"][0]["src"])
        self.assertEqual(result["pendingTimers"], 0)
        self.assertEqual(result["policyCount"], 1)
        self.assertTrue(result["rejectsUnrelated"])
        self.assertTrue(result["acceptsFallback"])

    async def test_bootstrap_records_src_assignment_failure_without_staying_loading(self):
        result = await self._run_bootstrap_in_fake_dom(fail_assignment=True)

        self.assertEqual(result["state"]["status"], "error")
        self.assertIn("src assignment blocked", result["state"]["error"])
        self.assertEqual(len(result["attempts"]), 2)
        self.assertEqual(result["scripts"], [])
        self.assertEqual(result["pendingTimers"], 0)

    async def test_bootstrap_falls_back_when_dom_append_fails(self):
        result = await self._run_bootstrap_in_fake_dom(fail_append=True)

        self.assertEqual(result["state"]["status"], "loaded")
        self.assertEqual(result["appendCount"], 2)
        self.assertIn("www.google.com/recaptcha/enterprise.js", result["scripts"][0]["src"])
        self.assertEqual(result["scripts"][0]["nonce"], "page-nonce")
        self.assertEqual(result["pendingTimers"], 0)

    async def test_force_fresh_flow_error_defers_sync_browser_restart_until_drain(self):
        tab = _ClosableFakeTab()
        resident_info = ResidentTabInfo(
            tab=tab,
            slot_id="slot-1",
            project_id="project-1",
            token_id=1,
        )
        resident_info.recaptcha_ready = True
        self.service.browser = types.SimpleNamespace(stopped=False)
        self.service._initialized = True
        self.service._resident_tabs["slot-1"] = resident_info
        self.service._project_resident_affinity["project-1"] = "slot-1"
        self.service._token_resident_affinity["1"] = "slot-1"
        self.service._maybe_execute_pending_fresh_profile_restart = AsyncMock(
            return_value=False
        )
        self.service._restart_browser_for_project = AsyncMock(return_value=True)

        await self.service.report_flow_error(
            "project-1",
            "reCAPTCHA 验证失败",
            error_message="Flow API request failed: PUBLIC_ERROR_UNUSUAL_ACTIVITY: reCAPTCHA evaluation failed",
            token_id=1,
            slot_id="slot-1",
        )

        self.assertIn("slot-1", self.service._resident_unavailable_slots)
        self.assertTrue(self.service._fresh_profile_restart_pending)
        self.assertTrue(self.service._fresh_profile_restart_force_pending)
        self.service._restart_browser_for_project.assert_not_awaited()
        self.service._maybe_execute_pending_fresh_profile_restart.assert_awaited_once()

    async def test_pending_fresh_restart_task_is_preserved_during_runtime_shutdown(
        self,
    ):
        async def runner():
            self.service._fresh_profile_restart_task = asyncio.current_task()
            await self.service._cancel_background_runtime_tasks(reason="unit_test")
            self.assertIs(
                self.service._fresh_profile_restart_task, asyncio.current_task()
            )

        import asyncio

        task = asyncio.create_task(runner())
        await task

    async def test_get_token_waits_for_pending_fresh_restart_before_resident_pick(self):
        import asyncio

        events = []
        tab = _ClosableFakeTab()
        resident_info = ResidentTabInfo(
            tab=tab,
            slot_id="slot-1",
            project_id="project-1",
            token_id=1,
        )
        resident_info.recaptcha_ready = True
        self.service._fresh_profile_restart_every_n_solves = 5
        self.service._fresh_profile_restart_pending = True
        self.service._fresh_profile_restart_pending_reason = "unit:5/5"
        self.service._has_active_browser_work = AsyncMock(return_value=False)

        async def restart_unlocked(project_id, token_id=None, *, fresh_profile=False):
            events.append("fresh_restart")
            self.assertEqual(project_id, "project-1")
            self.assertTrue(fresh_profile)
            self.service._reset_browser_rotation_budget()
            return True

        async def initialize():
            events.append("initialize")

        async def ensure_resident(*args, **kwargs):
            events.append("ensure_resident")
            return "slot-1", resident_info

        async def solve_resident(*args, **kwargs):
            events.append("solve_resident")
            return "token-1"

        self.service._restart_browser_for_project_unlocked = AsyncMock(
            side_effect=restart_unlocked
        )
        self.service.initialize = AsyncMock(side_effect=initialize)
        self.service._ensure_resident_tab = AsyncMock(side_effect=ensure_resident)
        self.service._ensure_resident_token_binding = AsyncMock(return_value=True)
        self.service._solve_with_resident_tab = AsyncMock(side_effect=solve_resident)

        token, slot_id = await self.service._get_token_direct(
            "project-1",
            token_id=1,
            return_slot_id=True,
        )

        self.assertEqual((token, slot_id), ("token-1", "slot-1"))
        self.assertEqual(
            events, ["fresh_restart", "initialize", "ensure_resident", "solve_resident"]
        )
        self.assertFalse(self.service._fresh_profile_restart_pending)
        self.assertIsNone(self.service._fresh_profile_restart_task)

    async def test_wait_for_pending_fresh_restart_awaits_existing_task(self):
        import asyncio

        events = []
        self.service._fresh_profile_restart_pending = True

        async def restart_task():
            events.append("restart_start")
            await asyncio.sleep(0.01)
            self.service._fresh_profile_restart_pending = False
            events.append("restart_done")
            return True

        task = asyncio.create_task(restart_task())
        self.service._fresh_profile_restart_task = task

        result = (
            await self.service._wait_for_pending_fresh_profile_restart_before_solve(
            "project-1",
            token_id=1,
            source="unit_test",
        )
        )

        self.assertTrue(result)
        self.assertEqual(events, ["restart_start", "restart_done"])
        self.assertTrue(task.done())

    async def test_runtime_surface_profile_contains_extended_browser_environment(self):
        profile = self.service._get_runtime_surface_profile()

        self.assertIn("webgpu", profile)
        self.assertIn("mediaQueries", profile)
        self.assertIn("storage", profile)
        self.assertIn("behavior", profile)
        self.assertIn("visualViewport", profile["window"])
        self.assertIn("supportedExtensions", profile["graphics"])
        self.assertIn(
            "WEBGL_debug_renderer_info", profile["graphics"]["supportedExtensions"]
        )

        source = self.service._build_tab_fingerprint_spoof_source(
            types.SimpleNamespace(target_id="unit-tab")
        )
        for marker in (
            "ensureWebGpuEnvironment",
            "ensureMatchMediaEnvironment",
            "ensureVisualViewportEnvironment",
            "navigator.storage",
            "getSupportedConstraints",
            "userActivation",
        ):
            self.assertIn(marker, source)

    async def test_pool_tab_limits_use_browser_count_times_per_worker_tabs(self):
        pool = _PersonalBrowserPoolService()

        self.assertEqual(pool._build_worker_tab_limits(5, 10), [5] * 10)

        capped_limits = pool._build_worker_tab_limits(5, 20)
        self.assertEqual(len(capped_limits), 20)
        self.assertEqual(sum(capped_limits), 50)
        self.assertLessEqual(max(capped_limits), 5)

        warmup_limits = pool._build_worker_tab_limits(
            5,
            10,
            total_limit=5,
            allow_zero=True,
        )
        self.assertEqual(len(warmup_limits), 10)
        self.assertEqual(sum(warmup_limits), 5)
        self.assertEqual(sum(1 for item in warmup_limits if item > 0), 5)

    async def test_pool_dispatch_prefers_cold_idle_worker_over_busy_live_worker(self):
        pool = _PersonalBrowserPoolService()
        live_worker = BrowserCaptchaService(
            browser_instance_id=1, max_resident_tabs_override=5
        )
        cold_worker = BrowserCaptchaService(
            browser_instance_id=2, max_resident_tabs_override=5
        )
        live_worker._initialized = True
        live_worker.browser = types.SimpleNamespace(stopped=False)
        pool._workers = [live_worker, cold_worker]
        pool._worker_dispatch_reservations = {0: 1}

        self.assertLess(
            pool._worker_dispatch_score(1, cold_worker),
            pool._worker_dispatch_score(0, live_worker),
        )

    async def test_nodriver_send_patch_handles_connection_without_closed_attr(self):
        connection = _ConnectionWithoutClosed()

        _patch_nodriver_connection_instance(connection)
        result = await connection.send(_fake_cdp_command())

        self.assertEqual(result, {"ok": True})
        self.assertEqual(connection.connect_count, 1)
        self.assertEqual(connection.register_count, 1)
        self.assertTrue(getattr(connection, "_flow2api_send_patched", False))


if __name__ == "__main__":
    unittest.main()
