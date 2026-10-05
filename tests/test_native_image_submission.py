"""Native request tests use only in-memory pages, never a browser or network."""

import asyncio
import copy
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import parse_qs, urlencode

from src.services.captcha_errors import BrowserCaptchaError
from src.services.native_image_submission import submit_native_image


FLOW_ROUTE = "https://flow.google.com/**"
RPC_URL = "https://flow.google.com/_/AiSandboxAngularFrontend/data/batchexecute?rpcids=ogiZ0b&f.sid=original"


def captured_argument():
    context = [None, 22, None, None, None, "project", None, None, None, None, ["native-captcha-secret", 1]]
    request = [
        None, None, None, 12345, 1, "ORIGINAL_MODEL", None, context,
        [[["native UI prompt"]]], None, None, None, "native-session", "native-uuid",
    ]
    return [None, [request, copy.deepcopy(request)], 7, context, ["native-session"]]


def captured_body(argument=None, rpc="ogiZ0b"):
    envelope = [[[rpc, json.dumps(argument if argument is not None else captured_argument()), None, "generic"]]]
    return urlencode(
        {"f.req": json.dumps(envelope), "at": "native-xsrf&secret", "extra": ["one", "two"]},
        doseq=True,
    )


def make_route(body=None, url=RPC_URL, response_text="native-response", method="POST"):
    response = SimpleNamespace(text=AsyncMock(return_value=response_text))
    request = SimpleNamespace(
        method=method, url=url, post_data=body if body is not None else captured_body(),
        headers={"Cookie": "native-cookie", "User-Agent": "native-UA"},
        response=AsyncMock(return_value=response),
    )
    return SimpleNamespace(request=request, abort=AsyncMock(), continue_=AsyncMock())


class FakeLocator:
    def __init__(self, page, editor):
        self.page = page
        self.editor = editor
        self.first = self

    async def wait_for(self, **kwargs):
        if not self.editor and self.page.submit_missing:
            raise TimeoutError("localized submit control missing")
        self.page.events.append("editor_ready")

    async def fill(self, text, **kwargs):
        self.page.events.append("fill")
        self.page.text = text

    async def inner_text(self, **kwargs):
        return self.page.text

    async def evaluate(self, script, **kwargs):
        return self.page.text

    async def click(self, **kwargs):
        if kwargs.get("trial"):
            self.page.events.append("submit_trial")
            if self.page.submit_blocked:
                raise TimeoutError("submit disabled or overlay blocks it")
            return
        self.page.events.append("click")
        await self.page.on_submit()


class FakePage:
    def __init__(self):
        self.events = []
        self.handlers = []
        self.text = ""
        self.on_submit = AsyncMock()
        self.on_close = None
        self.closed = False
        self.submit_missing = False
        self.submit_blocked = False
        self.close = AsyncMock(side_effect=self._close)
        self.route = AsyncMock(side_effect=self._route)
        self.unroute = AsyncMock(side_effect=self._unroute)

    async def _route(self, pattern, handler):
        self.events.append("route")
        self.handlers.append((pattern, handler))

    async def _unroute(self, pattern):
        self.events.append("unroute")
        self.handlers = [entry for entry in self.handlers if entry[0] != pattern]

    async def _close(self):
        if self.on_close:
            callback, self.on_close = self.on_close, None
            await callback()
        self.closed = True
        self.events.append("close")

    def locator(self, selector):
        return FakeLocator(self, editor="ProseMirror" in selector)

    async def dispatch(self, route):
        await self.handlers[-1][1](route)


class NativeImageSubmissionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.configure_generation = self.enterContext(patch(
            "src.services.native_image_submission._configure_generation", new_callable=AsyncMock
        ))
        self.page = FakePage()
        self.context = SimpleNamespace(new_page=AsyncMock(return_value=self.page))
        self.harvest_handler = AsyncMock()

        async def prepare(page, *args, **kwargs):
            await page.route(FLOW_ROUTE, self.harvest_handler)
            return True

        async def new_page(context):
            return await context.new_page()

        self.browser = SimpleNamespace(
            _new_page=AsyncMock(side_effect=new_page),
            _record_captcha_stage=Mock(),
            _apply_browser_environment_patch=AsyncMock(),
            _prepare_flow_runtime_page=AsyncMock(side_effect=prepare),
            _dismiss_flow_overlays=AsyncMock(),
        )
        self.spec = {
            "prompt": "用户真实 prompt & symbols + =",
            "model_name": "REQUESTED_MODEL",
            "aspect_ratio": "IMAGE_ASPECT_RATIO_PORTRAIT",
            "image_inputs": [{"name": "reference-one"}, {"mediaId": "reference-two"}],
            "website_key": "public-site-key",
        }

    def dispatch_on_submit(self, route):
        async def dispatch():
            await self.page.dispatch(route)
        self.page.on_submit = AsyncMock(side_effect=dispatch)

    async def submit(self, timeout=1):
        return await submit_native_image(self.browser, self.context, "project", self.spec, timeout)

    async def test_submission_creates_page_through_browser_factory(self):
        native = make_route()
        self.dispatch_on_submit(native)
        self.context.new_page.side_effect = AssertionError("foreground page creation is forbidden")
        self.browser._new_page.side_effect = None
        self.browser._new_page.return_value = self.page

        result = await self.submit()

        self.assertEqual(result["rpc"], "ogiZ0b")
        self.browser._new_page.assert_awaited_once_with(self.context)
        self.context.new_page.assert_not_awaited()
        native.continue_.assert_awaited_once()

    async def test_transient_page_preparation_retries_once_before_any_submission(self):
        self.browser._prepare_flow_runtime_page.side_effect = [
            BrowserCaptchaError("navigation", "proxy_connection_failed"), True]
        native = make_route()
        self.dispatch_on_submit(native)
        with patch("src.services.native_image_submission.asyncio.sleep", new_callable=AsyncMock):
            await self.submit()
        self.assertEqual(self.browser._prepare_flow_runtime_page.await_count, 2)
        native.continue_.assert_awaited_once()

    async def test_page_auth_failure_does_not_retry_or_fill_prompt(self):
        self.browser._prepare_flow_runtime_page.side_effect = BrowserCaptchaError("navigation", "login_required")
        with self.assertRaises(BrowserCaptchaError):
            await self.submit()
        self.browser._prepare_flow_runtime_page.assert_awaited_once()
        self.assertNotIn("fill", self.page.events)
        self.assertTrue(self.page.closed)

    async def test_actual_network_categories_retry_only_preparation_before_submission(self):
        for reason in ('network_connection_failed', 'network_empty_response', 'navigation_interrupted', 'timeout'):
            with self.subTest(reason=reason):
                self.page = FakePage()
                self.context.new_page.return_value = self.page
                self.browser._prepare_flow_runtime_page.reset_mock()
                self.browser._prepare_flow_runtime_page.side_effect = [BrowserCaptchaError('navigation', reason), True]
                native = make_route()
                self.dispatch_on_submit(native)
                with patch('src.services.native_image_submission.asyncio.sleep', new_callable=AsyncMock):
                    await self.submit()
                self.assertEqual(self.browser._prepare_flow_runtime_page.await_count, 2)
                self.assertEqual(self.page.events.count('click'), 1)
                native.continue_.assert_awaited_once()

    async def test_prompt_mismatch_is_proven_unsubmitted_and_never_clicks(self):
        with patch("src.services.native_image_submission.read_native_prompt",
                   new=AsyncMock(return_value="different text")):
            with self.assertRaises(BrowserCaptchaError) as failure:
                await self.submit()
        self.assertEqual(failure.exception.reason, "prompt_input_mismatch")
        self.assertIs(failure.exception.submission_pending, False)
        self.assertNotIn("click", self.page.events)
        self.assertTrue(self.page.closed)

    async def test_missing_submit_is_proven_unsubmitted_without_arming_generation(self):
        self.page.submit_missing = True
        with self.assertRaises(BrowserCaptchaError) as failure:
            await self.submit()
        self.assertEqual(failure.exception.reason, "submit_control_missing")
        self.assertIs(failure.exception.submission_pending, False)
        self.assertNotIn("click", self.page.events)
        self.assertTrue(self.page.closed)

    async def test_disabled_or_obscured_submit_never_arms_or_sends_generation(self):
        self.page.submit_blocked = True
        native = make_route()
        self.dispatch_on_submit(native)
        with self.assertRaises(BrowserCaptchaError) as failure:
            await self.submit()
        self.assertEqual(failure.exception.reason, "submit_control_not_ready")
        self.assertIs(failure.exception.submission_pending, False)
        self.page.on_submit.assert_not_awaited()
        native.continue_.assert_not_awaited()
        self.assertTrue(self.page.closed)

    async def test_submit_readiness_trial_precedes_exactly_one_real_click(self):
        native = make_route()
        self.dispatch_on_submit(native)
        await self.submit()
        self.assertLess(self.page.events.index("submit_trial"), self.page.events.index("click"))
        self.assertEqual(self.page.events.count("click"), 1)
        native.continue_.assert_awaited_once()

    async def test_after_click_response_failure_does_not_claim_non_submission(self):
        native = make_route()
        native.request.response.side_effect = RuntimeError("connection lost")
        self.dispatch_on_submit(native)
        with self.assertRaises(BrowserCaptchaError) as failure:
            await self.submit()
        self.assertIsNone(failure.exception.submission_pending)
        native.continue_.assert_awaited_once()
        self.assertTrue(self.page.closed)

    async def test_native_request_preserves_auth_and_only_patches_business_fields(self):
        native = make_route()
        original = copy.deepcopy(captured_argument())
        original_url = native.request.url
        original_headers = dict(native.request.headers)
        self.dispatch_on_submit(native)
        result = await self.submit()

        self.assertEqual(result, {"rpc": "ogiZ0b", "response_text": "native-response", "session_id": "native-session"})
        native.continue_.assert_awaited_once()
        self.assertEqual(set(native.continue_.await_args.kwargs), {"post_data"})
        form = parse_qs(native.continue_.await_args.kwargs["post_data"], keep_blank_values=True)
        self.assertEqual(form["at"], ["native-xsrf&secret"])
        self.assertEqual(form["extra"], ["one", "two"])
        envelope = json.loads(form["f.req"][0])
        argument = json.loads(envelope[0][0][1])
        expected = copy.deepcopy(original)
        expected[1] = [expected[1][0]]
        expected[1][0][2] = [["reference-one", None, None, None, 1], ["reference-two", None, None, None, 1]]
        expected[1][0][4] = 2
        expected[1][0][5] = "REQUESTED_MODEL"
        expected[1][0][8] = [[[self.spec["prompt"]]]]
        self.assertEqual(argument, expected)
        self.assertEqual(len(argument[1][0]), 14)
        self.assertEqual(native.request.url, original_url)
        self.assertEqual(native.request.headers, original_headers)
        native.request.response.assert_awaited_once()
        self.harvest_handler.assert_not_awaited()
        self.page.unroute.assert_awaited_once_with(FLOW_ROUTE)
        self.assertLess(self.page.events.index("unroute"), self.page.events.index("fill"))
        self.assertEqual(self.page.events[:3], ["route", "route", "unroute"])
        self.configure_generation.assert_awaited_once_with(
            self.page, kind="IMAGE", aspect_ratio=self.spec["aspect_ratio"], model_key=None
        )
        self.assertTrue(self.page.closed)

    async def test_concurrent_duplicate_and_other_generation_requests_are_aborted(self):
        native = make_route()
        duplicate = make_route()
        other = make_route(url=RPC_URL.replace("ogiZ0b", "MZZa6b"), body=captured_body(rpc="MZZa6b"))
        unrelated = make_route(url=RPC_URL.replace("ogiZ0b", "nzlxg"), body=captured_body(rpc="nzlxg"))

        async def submit_requests():
            await asyncio.gather(*(self.page.dispatch(route) for route in (native, duplicate, other, unrelated)))

        self.page.on_submit = submit_requests
        await self.submit()
        native.continue_.assert_awaited_once()
        duplicate.abort.assert_awaited_once()
        other.abort.assert_awaited_once()
        duplicate.continue_.assert_not_awaited()
        other.continue_.assert_not_awaited()
        unrelated.continue_.assert_awaited_once_with()
        duplicate.request.response.assert_not_awaited()

    async def test_route_replacement_already_blocks_historical_requests_before_submit(self):
        historical = make_route()
        native = make_route()
        async def unroute_while_page_is_active(pattern):
            await self.page._unroute(pattern)
            await self.page.dispatch(historical)
        self.page.unroute.side_effect = unroute_while_page_is_active
        self.dispatch_on_submit(native)
        await self.submit()
        historical.abort.assert_awaited_once()
        historical.continue_.assert_not_awaited()
        native.continue_.assert_awaited_once()
        self.harvest_handler.assert_not_awaited()

    async def test_cancellation_during_page_cleanup_still_closes_owned_page(self):
        native = make_route()
        self.dispatch_on_submit(native)
        close_started = asyncio.Event()
        release_close = asyncio.Event()
        async def slow_close():
            close_started.set()
            await release_close.wait()
            self.page.closed = True
        self.page.close.side_effect = slow_close
        task = asyncio.create_task(self.submit())
        await close_started.wait()
        task.cancel()
        release_close.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(self.page.closed)

    async def test_native_request_and_outer_session_ids_are_independently_preserved(self):
        argument = captured_argument()
        argument[1][0][12] = "native-request-session"
        argument[1][1][12] = "another-native-request-session"
        argument[4] = ["native-outer-session"]
        native = make_route(body=captured_body(argument))
        self.dispatch_on_submit(native)
        result = await self.submit()
        form = parse_qs(native.continue_.await_args.kwargs["post_data"])
        actual = json.loads(json.loads(form["f.req"][0])[0][0][1])
        self.assertEqual(actual[1][0][12], "native-request-session")
        self.assertEqual(actual[4], ["native-outer-session"])
        self.assertEqual(result["session_id"], "native-outer-session")
        self.assertEqual(actual[1][0][7], argument[1][0][7])
        native.abort.assert_not_awaited()

    async def test_unrecognized_schema_is_aborted_without_admitting_later_retry(self):
        invalid = captured_argument()
        invalid[1][0].insert(12, None)  # The incompatible older 15-field builder.
        first = make_route(body=captured_body(invalid))
        retry = make_route()

        async def submit_requests():
            await asyncio.gather(self.page.dispatch(first), self.page.dispatch(retry))

        self.page.on_submit = submit_requests
        with self.assertRaises(BrowserCaptchaError) as raised:
            await self.submit()
        self.assertEqual(raised.exception.reason, "request_shape_invalid")
        self.browser._record_captcha_stage.assert_any_call(
            "native_request_parse", "request_shape_invalid"
        )
        for route in (first, retry):
            route.abort.assert_awaited_once()
            route.continue_.assert_not_awaited()
        self.assertTrue(self.page.closed)

    async def test_context_session_and_multi_rpc_mismatch_fail_closed(self):
        bodies = []
        context_mismatch = captured_argument()
        context_mismatch[3][5] = "different-account-project"
        bodies.append(captured_body(context_mismatch))
        session_mismatch = captured_argument()
        session_mismatch[1][0][12] = None
        bodies.append(captured_body(session_mismatch))
        batch = json.loads(parse_qs(captured_body())["f.req"][0])
        batch[0].append(["YhhmEf", "[]", None, "generic"])
        bodies.append(urlencode({"f.req": json.dumps(batch), "at": "secret"}))
        bodies.append("f.req=invalid-secret-json&at=secret")
        for body in bodies:
            with self.subTest(body_kind=len(body)):
                self.setUp()
                route = make_route(body=body)
                async def submit_request():
                    await self.page.dispatch(route)
                self.page.on_submit = submit_request
                with self.assertRaises(BrowserCaptchaError) as raised:
                    await self.submit()
                route.abort.assert_awaited_once()
                route.continue_.assert_not_awaited()
                self.assertNotIn("secret", str(raised.exception))
                self.assertTrue(self.page.closed)

    async def test_continue_failure_never_retries_and_returns_safe_error(self):
        native = make_route()
        native.continue_.side_effect = RuntimeError("secret-cookie and private URL")
        self.dispatch_on_submit(native)
        with self.assertRaises(BrowserCaptchaError) as raised:
            await self.submit()
        self.assertEqual(raised.exception.reason, "request_continue_failed")
        self.assertNotIn("secret", str(raised.exception))
        native.abort.assert_awaited_once()
        native.request.response.assert_not_awaited()
        self.page.on_submit.assert_awaited_once()
        self.assertTrue(self.page.closed)

    async def test_abort_failure_closes_page_and_never_continues(self):
        native = make_route(body="f.req=invalid&at=secret")
        native.abort.side_effect = RuntimeError("sensitive failure")
        self.dispatch_on_submit(native)
        with self.assertRaises(BrowserCaptchaError) as raised:
            await self.submit()
        self.assertEqual(raised.exception.reason, "request_abort_failed")
        native.continue_.assert_not_awaited()
        self.assertTrue(self.page.closed)

    async def test_response_timeout_keeps_generation_blocked_during_cleanup(self):
        native = make_route()
        late = make_route()
        response_started = asyncio.Event()

        async def delayed_response():
            response_started.set()
            await asyncio.Event().wait()

        native.request.response.side_effect = delayed_response
        self.dispatch_on_submit(native)
        self.page.on_close = lambda: self.page.dispatch(late)
        with self.assertRaises(BrowserCaptchaError) as raised:
            await self.submit(timeout=0.05)
        self.assertTrue(response_started.is_set())
        self.assertEqual(raised.exception.stage, "native_response")
        self.assertEqual(raised.exception.reason, "timeout")
        late.abort.assert_awaited_once()
        late.continue_.assert_not_awaited()
        self.assertTrue(self.page.closed)

    async def test_cancelled_submission_closes_owned_page(self):
        clicked = asyncio.Event()
        self.page.on_submit = AsyncMock(side_effect=clicked.set)
        task = asyncio.create_task(self.submit())
        await clicked.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(self.page.closed)

    async def test_http_failure_is_not_returned_as_success_or_exposes_response_body(self):
        native = make_route(response_text="sensitive upstream response")
        response = native.request.response.return_value
        response.status = 403
        self.dispatch_on_submit(native)
        with self.assertRaises(BrowserCaptchaError) as raised:
            await self.submit()
        self.assertEqual(raised.exception.stage, "native_response")
        self.assertEqual(raised.exception.reason, "upstream_http_403")
        self.assertNotIn("sensitive", str(raised.exception))
        response.text.assert_not_awaited()
        self.page.on_submit.assert_awaited_once()
        self.assertTrue(self.page.closed)

    async def test_preparation_failure_closes_owned_page_without_clicking(self):
        self.browser._prepare_flow_runtime_page.side_effect = RuntimeError("private credentials")
        with self.assertRaises(BrowserCaptchaError) as raised:
            await self.submit()
        self.assertEqual(raised.exception.reason, "browser_operation_failed")
        self.assertNotIn("private", str(raised.exception))
        self.assertTrue(self.page.closed)
        self.page.on_submit.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
