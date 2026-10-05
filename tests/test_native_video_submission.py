"""Video validation exercises the native page path without a real browser."""

import asyncio
import copy
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import urlencode

from src.services.captcha_errors import BrowserCaptchaError
from src.services.native_video_submission import _payload_shape, submit_native_video
from tests.test_native_image_submission import FakePage, FLOW_ROUTE, make_route


VIDEO_URL = "https://flow.google.com/_/AiSandboxAngularFrontend/data/batchexecute?rpcids=YhhmEf&f.sid=original"


def video_argument(prompt="a real prompt", model="abra_t2v_4s", aspect=2):
    context = [None, 22, None, None, None, "project", None, None, None, None, ["secret-captcha", 1]]
    # Metadata is deliberately unlike the old builder and has independent IDs.
    metadata = ["native-metadata-id", None, [1, "opaque"], {"native": True}]
    request = [[None, None, [[[prompt]]]], model, aspect, None, metadata, None, ["native-output"], 2]
    return [[request], context, ["native-submission-id", 2]]


def video_body(argument):
    return urlencode({
        "f.req": json.dumps([[["YhhmEf", json.dumps(argument), None, "generic"]]]),
        "at": "native-xsrf&secret", "extra": "keep + & exactly",
    })


def observed_video_argument():
    """Redacted shape from native-video-wire-diagnostics.json, captured on wire."""
    argument = video_argument()
    argument[0][0] = argument[0][0][:5]
    argument[0][0][4] = [None, None, None, None, "native-metadata-id", "native-other-id"]
    return argument


class NativeVideoSubmissionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.page = FakePage()
        self.context = SimpleNamespace(new_page=AsyncMock(return_value=self.page))
        self.configure = self.enterContext(patch(
            "src.services.native_image_submission._configure_generation", new_callable=AsyncMock
        ))

        async def prepare(page, *args, **kwargs):
            await page.route(FLOW_ROUTE, AsyncMock())
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
            "website_key": "site-key", "prompt": "a real prompt",
            "model_key": "abra_t2v_4s", "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        }

    def route_on_submit(self, body):
        route = make_route(url=VIDEO_URL, body=body)
        async def dispatch():
            await self.page.dispatch(route)
        self.page.on_submit = dispatch
        return route

    async def submit(self):
        return await submit_native_video(self.browser, self.context, "project", self.spec, 1)

    async def test_submission_creates_page_through_browser_factory(self):
        route = self.route_on_submit(video_body(video_argument()))
        self.context.new_page.side_effect = AssertionError("foreground page creation is forbidden")
        self.browser._new_page.side_effect = None
        self.browser._new_page.return_value = self.page

        result = await self.submit()

        self.assertEqual(result["rpc"], "YhhmEf")
        self.browser._new_page.assert_awaited_once_with(self.context)
        self.context.new_page.assert_not_awaited()
        route.continue_.assert_awaited_once_with()

    async def test_matching_video_continues_original_request_without_any_overrides(self):
        body = video_body(video_argument())
        route = self.route_on_submit(body)
        result = await self.submit()
        route.continue_.assert_awaited_once_with()
        route.abort.assert_not_awaited()
        self.assertEqual(route.request.post_data, body)
        self.assertEqual(result, {
            "rpc": "YhhmEf", "response_text": "native-response", "session_id": "native-submission-id",
        })
        self.configure.assert_awaited_once_with(
            self.page, kind="VIDEO", aspect_ratio=self.spec["aspect_ratio"], model_key="abra_t2v_4s",
        )
        self.assertTrue(self.page.closed)

    async def test_observed_five_field_request_preserves_original_wire_body(self):
        argument = observed_video_argument()
        self.assertEqual(
            _payload_shape(argument),
            "a3[a1[a5[a3[z,z,a1[a1]],s,n,z,a6[z,z,z,z,s,s]]],"
            "a11[z,n,z,z,z,s,z,z,z,z,a2[s,n]],a2[s,n]]",
        )
        body = video_body(argument)
        route = self.route_on_submit(body)
        result = await self.submit()
        route.continue_.assert_awaited_once_with()
        route.abort.assert_not_awaited()
        self.assertEqual(route.request.post_data, body)
        self.assertEqual(result["session_id"], "native-submission-id")
        self.assertTrue(self.page.closed)

    async def test_unobserved_request_lengths_remain_blocked(self):
        for length in (0, 4, 6, 7, 9):
            with self.subTest(length=length):
                self.setUp()
                argument = video_argument()
                argument[0][0] = (argument[0][0] + [None])[:length]
                route = self.route_on_submit(video_body(argument))
                with self.assertRaises(BrowserCaptchaError) as raised:
                    await self.submit()
                self.assertEqual(raised.exception.reason, "video_request_shape_invalid")
                route.abort.assert_awaited_once()
                route.continue_.assert_not_awaited()

    async def test_observed_request_still_requires_matching_business_fields_and_context(self):
        for field, reason in (
            ("model", "video_model_mismatch"), ("aspect", "video_aspect_mismatch"),
            ("prompt", "video_prompt_mismatch"), ("count", "video_count_mismatch"),
            ("context", "video_context_invalid"),
        ):
            with self.subTest(field=field):
                self.setUp()
                argument = observed_video_argument()
                if field == "model":
                    argument[0][0][1] = "abra_t2v_8s"
                elif field == "aspect":
                    argument[0][0][2] = 1
                elif field == "prompt":
                    argument[0][0][0][2] = [[["another prompt"]]]
                elif field == "count":
                    argument[0].append(copy.deepcopy(argument[0][0]))
                else:
                    argument[1][5] = "other-project"
                route = self.route_on_submit(video_body(argument))
                with self.assertRaises(BrowserCaptchaError) as raised:
                    await self.submit()
                self.assertEqual(raised.exception.reason, reason)
                route.abort.assert_awaited_once()
                route.continue_.assert_not_awaited()

    async def test_wrong_model_aspect_prompt_or_count_is_aborted_with_safe_shape(self):
        for field, expected_reason in (
            ("model", "video_model_mismatch"), ("aspect", "video_aspect_mismatch"),
            ("prompt", "video_prompt_mismatch"), ("count", "video_count_mismatch"),
            ("schema", "video_request_shape_invalid"),
        ):
            with self.subTest(field=field):
                self.setUp()
                argument = video_argument()
                if field == "model":
                    argument[0][0][1] = "abra_t2v_8s"
                elif field == "aspect":
                    argument[0][0][2] = 1
                elif field == "prompt":
                    argument[0][0][0][2] = [[["a different private prompt"]]]
                elif field == "count":
                    argument[0].append(copy.deepcopy(argument[0][0]))
                else:
                    argument[0][0].append(None)
                route = self.route_on_submit(video_body(argument))
                with self.assertRaises(BrowserCaptchaError) as raised:
                    await self.submit()
                self.assertEqual(raised.exception.reason, expected_reason)
                route.abort.assert_awaited_once()
                route.continue_.assert_not_awaited()
                diagnostic = next(
                    call for call in self.browser._record_captcha_stage.call_args_list
                    if call.args == ("native_request_parse", expected_reason)
                )
                shape = diagnostic.kwargs["payload_shape"]
                self.assertRegex(shape, r"^[abnosz?:0-9,\[\].]+$")
                self.assertLessEqual(len(shape), 600)
                self.assertNotIn("private", str(raised.exception))
                self.assertNotIn("secret", shape)
                self.assertTrue(self.page.closed)

    async def test_one_video_request_is_admitted_when_native_ui_retries(self):
        first = make_route(url=VIDEO_URL, body=video_body(video_argument()))
        duplicate = make_route(url=VIDEO_URL, body=video_body(video_argument()))
        async def dispatch():
            await asyncio.gather(self.page.dispatch(first), self.page.dispatch(duplicate))
        self.page.on_submit = dispatch
        await self.submit()
        first.continue_.assert_awaited_once_with()
        duplicate.abort.assert_awaited_once()
        duplicate.continue_.assert_not_awaited()

    async def test_multiline_wire_prompt_must_still_match_every_newline_exactly(self):
        prompt = 'Preserve this line.\n\n第二段。'
        for actual in (prompt, prompt.replace('\n\n', '\n'), prompt.replace('\n', ' '), prompt + '\n'):
            with self.subTest(exact=actual == prompt):
                self.setUp()
                self.spec['prompt'] = prompt
                route = self.route_on_submit(video_body(video_argument(prompt=actual)))
                if actual == prompt:
                    await self.submit()
                    route.continue_.assert_awaited_once_with()
                    route.abort.assert_not_awaited()
                else:
                    with self.assertRaises(BrowserCaptchaError) as failure:
                        await self.submit()
                    self.assertEqual(failure.exception.reason, 'video_prompt_mismatch')
                    route.abort.assert_awaited_once()
                    route.continue_.assert_not_awaited()

    async def test_ui_configuration_failure_never_fills_prompt_or_submits(self):
        self.configure.side_effect = BrowserCaptchaError("native_generation_setup", "configuration_failed")
        with self.assertRaises(BrowserCaptchaError):
            await self.submit()
        self.assertNotIn("fill", self.page.events)
        self.assertNotIn("click", self.page.events)
        self.assertTrue(self.page.closed)

    async def test_portrait_and_each_supported_duration_are_verified_from_native_model(self):
        for duration in (4, 6, 8, 10):
            with self.subTest(duration=duration):
                self.setUp()
                model = f"abra_t2v_{duration}s"
                self.spec.update(model_key=model, aspect_ratio="9:16")
                route = self.route_on_submit(video_body(video_argument(model=model, aspect=1)))
                await self.submit()
                route.continue_.assert_awaited_once_with()


if __name__ == "__main__":
    unittest.main()
