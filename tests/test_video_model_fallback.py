"""Short Veo fallback preserves request semantics and generation admission guards."""

import asyncio
import contextvars
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import parse_qs

from src.services.flow_client import FlowClient
from src.services.flow_frontend import FlowRPCRejected


PROJECT = "01234567-89ab-cdef-0123-456789abcdef"
OPERATION = "11111111-2222-3333-4444-555555555555"
MEDIA = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
START = "22222222-3333-4444-5555-666666666666"
END = "33333333-4444-5555-6666-777777777777"
BOOTSTRAP = 'boq_labs-ai-sandbox-frontend_test "FdrFJe":"123" "SNlM0e":"fixture"'
RPC_URL = "https://flow.google.com/_/AiSandboxAngularFrontend/data/batchexecute?rpcids="
LANDSCAPE = "VIDEO_ASPECT_RATIO_LANDSCAPE"
PORTRAIT = "VIDEO_ASPECT_RATIO_PORTRAIT"


def _response(rpc="YhhmEf", *, error=None, status=200):
    frame = (
        ["wrb.fr", rpc, None, None, None, error]
        if error is not None
        else ["wrb.fr", rpc, json.dumps([[OPERATION, PROJECT, MEDIA]])]
    )
    return SimpleNamespace(status_code=status, headers={}, text=json.dumps([frame]))


def _argument(call):
    fields = parse_qs(call.kwargs["data"])
    rpc = json.loads(fields["f.req"][0])[0][0]
    return rpc[0], json.loads(rpc[1])


class _Session:
    def __init__(self, post):
        self.post = post
        self.get = AsyncMock(side_effect=AssertionError("unexpected HTTP GET"))

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class VideoModelFallbackTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.enterContext(patch("src.services.flow_client.debug_logger"))
        self.enterContext(patch("src.services.flow_current.debug_logger"))
        cfg = self.enterContext(patch("src.services.flow_current.config"))
        cfg.captcha_method = "yescaptcha"
        self.enterContext(patch(
            "src.services.flow_client.AsyncSession",
            side_effect=lambda **kwargs: _Session(self.post),
        ))
        self.new_request()

    def tearDown(self):
        self.client.clear_generation_sent_callback()

    def new_request(self, *, max_retries=3):
        if hasattr(self, "client"):
            self.client.clear_generation_sent_callback()
        self.client = FlowClient(proxy_manager=None)
        self.observer = AsyncMock()
        self.client.set_generation_sent_callback(self.observer)
        self.client._resolve_flow_frontend_cookie_storage = AsyncMock(return_value="SID=fixture")
        self.client._frontend_cookie = AsyncMock(return_value="SID=fixture")
        self.client._get_recaptcha_token = AsyncMock(return_value=("fixture-captcha", None))
        self.client._notify_browser_captcha_request_finished = AsyncMock()
        self.client._load_flow_frontend_bootstrap = AsyncMock(return_value=BOOTSTRAP)
        self.client._resolve_batchexecute_captcha_override = Mock(return_value=None)
        self.client._get_runtime_config = Mock(return_value=SimpleNamespace(
            flow_max_retries=max_retries, video_timeout=120,
        ))
        self.post = AsyncMock(return_value=_response())

    async def generate(self, *, model="veo_3_1_t2v_fast_4s_relaxed", aspect=LANDSCAPE, mode="text"):
        kwargs = dict(
            at="fixture-at", project_id=PROJECT, prompt="a copper teapot", model_key=model,
            aspect_ratio=aspect, token_id=7, google_cookies="SID=fixture",
        )
        if mode == "start":
            return await self.client.generate_video_start_image(**kwargs, start_media_id=START)
        if mode == "start_end":
            return await self.client.generate_video_start_end(
                **kwargs, start_media_id=START, end_media_id=END,
            )
        if mode == "extend":
            return await self.client.generate_video_extend(**kwargs, video_media_id=MEDIA)
        return await self.client.generate_video_text(**kwargs)

    async def assert_replay_blocked(self):
        before = self.post.await_count
        with self.assertRaisesRegex(Exception, "already sent|replay disabled"):
            await self.client._make_text_request("POST", RPC_URL + "ogiZ0b", raw_body="fixture")
        self.assertEqual(self.post.await_count, before)
        self.observer.assert_awaited_once()

    async def test_exact_refusal_falls_back_without_changing_duration_mode_or_orientation(self):
        for seconds in (4, 6):
            for aspect, aspect_value in ((LANDSCAPE, 2), (PORTRAIT, 1)):
                for mode, rpc, family in (
                    ("text", "YhhmEf", "t2v"),
                    ("start", "eb1hJf", "i2v_s"),
                    ("start_end", "nprQif", "i2v_s"),
                ):
                    for refusal in (5, [5], "NOT_FOUND"):
                        with self.subTest(seconds=seconds, aspect=aspect, mode=mode, refusal=refusal):
                            self.new_request(max_retries=1)
                            suffix = "_fl" if mode == "start_end" else ""
                            model = f"veo_3_1_{family}_fast_{seconds}s{suffix}_relaxed"
                            self.post.side_effect = [_response(rpc, error=refusal), _response(rpc)]

                            result = await self.generate(model=model, aspect=aspect, mode=mode)

                            self.assertEqual(self.post.await_count, 2)
                            before, after = map(_argument, self.post.await_args_list)
                            self.assertEqual((before[0], after[0]), (rpc, rpc))
                            first, second = before[1][0][0], after[1][0][0]
                            self.assertEqual(first[1], model)
                            self.assertEqual(second[1], model.removesuffix("_relaxed"))
                            self.assertEqual(first[:1] + first[2:4], second[:1] + second[2:4])
                            self.assertEqual(second[2], aspect_value)
                            if mode in {"start", "start_end"}:
                                self.assertEqual(first[4], second[4])
                            if mode == "start_end":
                                self.assertEqual(first[5], second[5])
                            operation = result["operations"][0]
                            self.assertEqual(operation["modelKey"], model.removesuffix("_relaxed"))
                            self.assertEqual(operation["name"], OPERATION)
                            self.assertEqual(operation["aspectRatio"], aspect)
                            self.observer.assert_awaited_once()
                            self.assertTrue(self.client._generation_request_was_sent())
                            await self.assert_replay_blocked()

    async def test_bound_callback_remains_counted_once_across_fallback(self):
        bound = self.client.get_generation_sent_callback()
        self.post.side_effect = [_response(error=[5]), _response()]
        await self.generate()
        await bound()
        await self.client._notify_generation_sent()
        self.observer.assert_awaited_once()
        self.assertEqual(self.post.await_count, 2)
        await self.assert_replay_blocked()

    async def test_concurrent_requests_have_independent_fallback_allowances(self):
        barrier = asyncio.Event()
        arrived = 0
        observers = [AsyncMock(), AsyncMock()]

        async def respond(url, **kwargs):
            nonlocal arrived
            call = SimpleNamespace(kwargs=kwargs)
            rpc, argument = _argument(call)
            if argument[0][0][1].endswith("_relaxed"):
                arrived += 1
                if arrived == 2:
                    barrier.set()
                await barrier.wait()
                return _response(rpc, error=[5])
            return _response(rpc)

        async def account(index):
            token = self.client.set_generation_sent_callback(observers[index])
            try:
                result = await self.generate(model=f"veo_3_1_t2v_fast_{4 + 2 * index}s_relaxed")
                self.assertTrue(self.client._generation_request_was_sent())
                with self.assertRaisesRegex(Exception, "already sent|replay disabled"):
                    await self.client._make_text_request("POST", RPC_URL + "ogiZ0b", raw_body="fixture")
                return result
            finally:
                self.client.clear_generation_sent_callback(token)

        self.post.side_effect = respond
        results = await asyncio.gather(account(0), account(1))
        self.assertEqual(self.post.await_count, 4)
        self.assertEqual(
            [result["operations"][0]["modelKey"] for result in results],
            ["veo_3_1_t2v_fast_4s", "veo_3_1_t2v_fast_6s"],
        )
        for observer in observers:
            observer.assert_awaited_once()
        self.observer.assert_not_awaited()

    async def test_fallback_also_works_without_an_installed_observer(self):
        self.client.clear_generation_sent_callback()
        self.post.side_effect = [_response(error=[5]), _response()]
        result = await self.generate()
        self.assertEqual(result["operations"][0]["modelKey"], "veo_3_1_t2v_fast_4s")
        self.assertEqual(self.post.await_count, 2)
        self.observer.assert_not_awaited()

    async def test_fallback_xsrf_challenge_cannot_replay_with_or_without_observer(self):
        for observed in (True, False):
            with self.subTest(observed=observed):
                self.new_request()
                if not observed:
                    self.client.clear_generation_sent_callback()
                challenge = SimpleNamespace(status_code=200, headers={}, text='[["xsrf","renewed"]]')
                self.post.side_effect = [_response(error=[5]), challenge, _response()]
                with self.assertRaisesRegex(Exception, "replay disabled"):
                    await self.generate()
                self.assertEqual(self.post.await_count, 2)
                if observed:
                    self.observer.assert_awaited_once()
                    await self.assert_replay_blocked()
                else:
                    self.observer.assert_not_awaited()

    async def test_retry_allowance_only_admits_the_matching_rpc_and_project_once(self):
        await self.client._notify_generation_sent()
        refusal = FlowRPCRejected("explicit model refusal", "YhhmEf", [5])
        matching = RPC_URL + f"YhhmEf&source-path=/project/{PROJECT}"
        with self.client._allow_rejected_video_model_retry(
            refusal, rpc_id="YhhmEf", project_id=PROJECT,
        ):
            for wrong in (
                RPC_URL + f"eb1hJf&source-path=/project/{PROJECT}",
                RPC_URL + "YhhmEf&source-path=/project/some-other-project",
            ):
                with self.subTest(wrong=wrong):
                    with self.assertRaisesRegex(Exception, "replay disabled"):
                        await self.client._make_text_request("POST", wrong, raw_body="fixture")
                    self.post.assert_not_awaited()
            await self.client._make_text_request("POST", matching, raw_body="fixture")
            with self.assertRaisesRegex(Exception, "replay disabled"):
                await self.client._make_text_request("POST", matching, raw_body="fixture")
        with self.assertRaisesRegex(Exception, "replay disabled"):
            await self.client._make_text_request("POST", matching, raw_body="fixture")
        self.post.assert_awaited_once()
        self.observer.assert_awaited_once()

    async def test_copied_context_cannot_use_an_expired_unused_retry_allowance(self):
        await self.client._notify_generation_sent()
        refusal = FlowRPCRejected("explicit model refusal", "YhhmEf", [5])
        with self.client._allow_rejected_video_model_retry(
            refusal, rpc_id="YhhmEf", project_id=PROJECT,
        ):
            copied = contextvars.copy_context()
        matching = RPC_URL + f"YhhmEf&source-path=/project/{PROJECT}"
        with self.assertRaisesRegex(Exception, "replay disabled"):
            await asyncio.create_task(
                self.client._make_text_request("POST", matching, raw_body="fixture"),
                context=copied,
            )
        self.post.assert_not_awaited()
        self.observer.assert_awaited_once()

    async def test_fallback_on_last_attempt_after_presend_failures(self):
        self.client._load_flow_frontend_bootstrap.side_effect = [
            RuntimeError("bootstrap unavailable"), RuntimeError("bootstrap unavailable"),
            BOOTSTRAP, BOOTSTRAP,
        ]
        self.post.side_effect = [_response(error=[5]), _response()]
        result = await self.generate()
        self.assertEqual(result["operations"][0]["modelKey"], "veo_3_1_t2v_fast_4s")
        self.assertEqual(self.post.await_count, 2)
        self.observer.assert_awaited_once()
        self.assertEqual(self.client._get_recaptcha_token.await_count, 4)
        await self.assert_replay_blocked()

    async def test_second_explicit_refusal_cannot_trigger_another_fallback(self):
        self.post.side_effect = [_response(error=[5]), _response(error=[5]), _response()]
        with self.assertRaises(FlowRPCRejected) as raised:
            await self.generate()
        self.assertTrue(raised.exception.submission_rejected)
        self.assertEqual(self.post.await_count, 2)
        self.observer.assert_awaited_once()
        await self.assert_replay_blocked()

    async def test_second_post_lost_response_remains_unknown_without_replay(self):
        self.post.side_effect = [_response(error=5), RuntimeError("connection lost after send"), _response()]
        with self.assertRaisesRegex(Exception, "connection lost"):
            await self.generate()
        self.assertEqual(self.post.await_count, 2)
        self.observer.assert_awaited_once()
        await self.assert_replay_blocked()

    async def test_fallback_presend_failure_retains_original_explicit_refusal(self):
        for failure_stage in ("captcha", "bootstrap"):
            with self.subTest(failure_stage=failure_stage):
                self.new_request()
                self.post.return_value = _response(error=[5])
                if failure_stage == "captcha":
                    self.client._get_recaptcha_token.side_effect = [
                        ("fixture-captcha", None), RuntimeError("fallback captcha unavailable"),
                    ]
                else:
                    self.client._load_flow_frontend_bootstrap.side_effect = [
                        BOOTSTRAP, RuntimeError("fallback bootstrap unavailable"),
                    ]
                with self.assertRaises(FlowRPCRejected) as raised:
                    await self.generate()
                self.assertEqual(raised.exception.error_code, "[5]")
                self.assertTrue(raised.exception.submission_rejected)
                self.post.assert_awaited_once()
                self.observer.assert_awaited_once()
                await self.assert_replay_blocked()

    async def test_network_failure_after_sent_does_not_fallback(self):
        self.post.side_effect = RuntimeError("connection lost after send; NOT_FOUND code=5")
        with self.assertRaisesRegex(Exception, "connection lost"):
            await self.generate()
        self.post.assert_awaited_once()
        self.observer.assert_awaited_once()
        await self.assert_replay_blocked()

    async def test_http_failure_is_not_a_model_refusal_even_with_misleading_rpc_body(self):
        for mode, rpc, model in (
            ("text", "YhhmEf", "veo_3_1_t2v_fast_4s_relaxed"),
            ("start", "eb1hJf", "veo_3_1_i2v_s_fast_4s_relaxed"),
            ("start_end", "nprQif", "veo_3_1_i2v_s_fast_4s_fl_relaxed"),
        ):
            for status in (401, 403, 503):
                for after_fallback in (False, True):
                    with self.subTest(rpc=rpc, status=status, after_fallback=after_fallback):
                        self.new_request()
                        self.post.side_effect = (
                            [_response(rpc, error=[5])] if after_fallback else []
                        ) + [_response(rpc, error=[5], status=status), _response(rpc)]
                        with self.assertRaises(Exception) as raised:
                            await self.generate(model=model, mode=mode)
                        if status in (401, 403):
                            self.assertIsInstance(raised.exception, FlowRPCRejected)
                            self.assertEqual(raised.exception.error_code, str(status))
                            self.assertEqual(raised.exception.rpc_id, rpc)
                            self.assertTrue(raised.exception.submission_rejected)
                            self.assertFalse(raised.exception.video_model_not_found)
                        else:
                            self.assertNotIsInstance(raised.exception, FlowRPCRejected)
                            self.assertFalse(getattr(raised.exception, "submission_rejected", False))
                        self.assertEqual(self.post.await_count, 2 if after_fallback else 1)
                        self.observer.assert_awaited_once()
                        await self.assert_replay_blocked()

    async def test_error_codes_containing_digit_five_do_not_fallback(self):
        for code in (503, [503], 50, [50], 15, [15], "NOT_FOUND_EXTRA", "[5, 503]"):
            with self.subTest(code=code):
                self.new_request()
                self.post.return_value = _response(error=code)
                with self.assertRaises(FlowRPCRejected):
                    await self.generate()
                self.post.assert_awaited_once()
                self.observer.assert_awaited_once()
                await self.assert_replay_blocked()

    async def test_model_access_denied_never_falls_back(self):
        self.post.return_value = _response(error=["MODEL_ACCESS_DENIED", 5])
        with self.assertRaisesRegex(FlowRPCRejected, "MODEL_ACCESS_DENIED"):
            await self.generate()
        self.post.assert_awaited_once()
        self.observer.assert_awaited_once()

    async def test_nonrelaxed_or_unrelated_model_never_changes(self):
        for model in (
            "veo_3_1_t2v_fast_4s", "veo_3_1_t2v_fast_6s", "veo_3_1_t2v_fast",
            "veo_3_1_t2v_quality_4s", "abra_t2v_4s", "veo_3_1_t2v_fast_8s_relaxed",
        ):
            with self.subTest(model=model):
                self.new_request()
                self.post.return_value = _response(error=[5])
                with self.assertRaises(FlowRPCRejected):
                    await self.generate(model=model)
                self.post.assert_awaited_once()
                self.assertEqual(_argument(self.post.await_args)[1][0][0][1], model)

    async def test_legacy_relaxed_or_extend_keys_never_fall_back(self):
        for model, mode, rpc in (
            ("veo_3_1_t2v_fast_ultra_relaxed", "text", "YhhmEf"),
            ("veo_3_1_i2v_s_fast_ultra_relaxed", "start", "eb1hJf"),
            ("veo_3_1_extend_fast_landscape_ultra_relaxed", "extend", "fZytfe"),
            ("veo_3_1_t2v_fast_4s_relaxed", "start", "eb1hJf"),
        ):
            with self.subTest(model=model, mode=mode):
                self.new_request()
                self.post.return_value = _response(rpc, error=[5])
                with self.assertRaises(FlowRPCRejected):
                    await self.generate(model=model, mode=mode)
                self.post.assert_awaited_once()

    async def test_other_rpc_error_frame_cannot_be_attributed_to_video_request(self):
        wrong_frame = ["er", "ogiZ0b", None, None, None, [5]]
        for with_success in (False, True):
            with self.subTest(with_success=with_success):
                self.new_request()
                frames = [wrong_frame]
                if with_success:
                    frames += json.loads(_response().text)
                self.post.return_value = SimpleNamespace(status_code=200, headers={}, text=json.dumps(frames))
                if with_success:
                    result = await self.generate()
                    self.assertEqual(result["operations"][0]["modelKey"], "veo_3_1_t2v_fast_4s_relaxed")
                else:
                    with self.assertRaisesRegex(RuntimeError, "no payload"):
                        await self.generate()
                self.post.assert_awaited_once()
                self.observer.assert_awaited_once()

    async def test_untyped_error_text_does_not_authorize_model_fallback(self):
        for message in (
            "Flow frontend RPC rejected: rpc=YhhmEf, code=5",
            "Flow frontend RPC rejected: rpc=YhhmEf, code=[5]",
            "Flow frontend RPC rejected: rpc=YhhmEf, code=503",
            "model NOT_FOUND", "arbitrary object not found",
        ):
            with self.subTest(message=message):
                self.new_request(max_retries=1)
                self.client._current_rpc = AsyncMock(side_effect=RuntimeError(message))
                with self.assertRaises(RuntimeError) as raised:
                    await self.generate()
                self.assertEqual(str(raised.exception), message)
                self.client._current_rpc.assert_awaited_once()
                self.observer.assert_not_awaited()
                self.post.assert_not_awaited()

    async def test_typed_error_from_another_rpc_does_not_authorize_fallback(self):
        for rpc in ("ogiZ0b", "nzlxg", "eb1hJf"):
            with self.subTest(rpc=rpc):
                self.new_request(max_retries=1)
                error = FlowRPCRejected("unrelated RPC code=[5]", rpc, "[5]")
                self.client._current_rpc = AsyncMock(side_effect=error)
                with self.assertRaises(FlowRPCRejected) as raised:
                    await self.generate()
                self.assertIs(raised.exception, error)
                self.client._current_rpc.assert_awaited_once()
                self.post.assert_not_awaited()

    async def test_uncertain_or_access_denied_typed_errors_do_not_fallback(self):
        for flag in ("outcome_unknown", "submission_uncertain", "MODEL_ACCESS_DENIED"):
            with self.subTest(flag=flag):
                self.new_request(max_retries=1)
                error = FlowRPCRejected(f"refusal {flag}", "YhhmEf", "[5]")
                if flag != "MODEL_ACCESS_DENIED":
                    setattr(error, flag, True)
                self.client._current_rpc = AsyncMock(side_effect=error)
                with self.assertRaises(FlowRPCRejected) as raised:
                    await self.generate()
                self.assertIs(raised.exception, error)
                if flag != "MODEL_ACCESS_DENIED":
                    self.assertFalse(raised.exception.submission_rejected)
                self.client._current_rpc.assert_awaited_once()
                self.post.assert_not_awaited()

    def test_exact_not_found_is_a_known_rejection_for_the_submission_ledger(self):
        for rpc in ("YhhmEf", "eb1hJf", "nprQif"):
            for code in (5, [5], "NOT_FOUND"):
                with self.subTest(rpc=rpc, code=code):
                    self.assertTrue(FlowRPCRejected("explicit refusal", rpc, code).submission_rejected)
        for rpc, code in (("YhhmEf", 503), ("YhhmEf", [503]), ("nzlxg", 5)):
            with self.subTest(rpc=rpc, code=code):
                self.assertFalse(FlowRPCRejected("not a known refusal", rpc, code).submission_rejected)


if __name__ == "__main__":
    unittest.main()
