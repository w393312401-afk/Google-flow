"""Count actual generation admission using fake pages and HTTP sessions only."""

import asyncio
import contextvars
import json
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import urlencode

from src.services.captcha_errors import BrowserCaptchaError
from src.services.flow_client import FlowClient
from src.services.native_image_submission import submit_native_image
from src.services.native_video_submission import submit_native_video
from tests.test_browser_captcha_native import BrowserCaptchaService
from tests.test_native_image_submission import FakePage, captured_body, make_route
from tests.test_native_video_submission import VIDEO_URL, video_argument, video_body


BOOTSTRAP = 'boq_labs-ai-sandbox-frontend_test "FdrFJe":"123" "SNlM0e":"fixture"'
RPC_URL = "https://flow.google.com/_/AiSandboxAngularFrontend/data/batchexecute?rpcids="


class _Session:
    def __init__(self, post):
        self.post = post
        self.get = AsyncMock(return_value=SimpleNamespace(status_code=200, headers={}, text="fixture"))

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class NativeSentHookTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.page = FakePage()
        self.context = SimpleNamespace(new_page=AsyncMock(return_value=self.page))
        self.browser = SimpleNamespace(
            _record_captcha_stage=Mock(),
            _apply_browser_environment_patch=AsyncMock(),
            _prepare_flow_runtime_page=AsyncMock(return_value=True),
            _dismiss_flow_overlays=AsyncMock(),
        )
        async def new_page(context):
            return await context.new_page()
        self.browser._new_page = AsyncMock(side_effect=new_page)
        self.spec = {
            "prompt": "a real prompt", "model_name": "BELUGA",
            "aspect_ratio": "IMAGE_ASPECT_RATIO_PORTRAIT", "website_key": "fixture-key",
        }
        self.configure = self.enterContext(patch(
            "src.services.native_image_submission._configure_generation", new_callable=AsyncMock,
        ))
        self.observer = AsyncMock()

    def dispatch_on_submit(self, *routes):
        async def dispatch():
            await asyncio.gather(*(self.page.dispatch(route) for route in routes))
        self.page.on_submit = dispatch

    async def submit(self):
        return await submit_native_image(
            self.browser, self.context, "project", self.spec, 1,
            on_generation_sent=self.observer,
        )

    async def test_one_admitted_post_not_duplicate_or_control_plane(self):
        native, duplicate = make_route(), make_route()
        credits = make_route(url=RPC_URL + "nzlxg", body=captured_body(rpc="nzlxg"))
        other = make_route(url=RPC_URL + "MZZa6b", body=captured_body(rpc="MZZa6b"))
        order = []
        self.observer.side_effect = lambda: order.append("count")
        native.continue_.side_effect = lambda **kwargs: order.append("post")
        self.dispatch_on_submit(native, duplicate, credits, other)
        await self.submit()
        self.assertEqual(order, ["count", "post"])
        self.observer.assert_awaited_once()
        native.continue_.assert_awaited_once()
        credits.continue_.assert_awaited_once()
        duplicate.abort.assert_awaited_once()
        other.abort.assert_awaited_once()

    async def test_invalid_native_request_is_aborted_without_count(self):
        native = make_route(body="f.req=bad&at=fixture")
        self.dispatch_on_submit(native)
        with self.assertRaises(BrowserCaptchaError):
            await self.submit()
        self.observer.assert_not_awaited()
        native.continue_.assert_not_awaited()
        native.abort.assert_awaited_once()

    async def test_page_preparation_failure_is_not_counted(self):
        self.browser._prepare_flow_runtime_page.side_effect = BrowserCaptchaError("prepare", "login_required")
        with self.assertRaises(BrowserCaptchaError):
            await self.submit()
        self.observer.assert_not_awaited()
        self.assertNotIn("click", self.page.events)

    async def test_prompt_mismatch_is_not_counted(self):
        with patch("src.services.native_image_submission.read_native_prompt", new=AsyncMock(return_value="wrong")):
            with self.assertRaises(BrowserCaptchaError):
                await self.submit()
        self.observer.assert_not_awaited()
        self.assertNotIn("click", self.page.events)

    async def test_callback_failure_cannot_allow_native_replay(self):
        native, duplicate = make_route(), make_route()
        self.observer.side_effect = RuntimeError("observer failed")
        self.dispatch_on_submit(native, duplicate)
        with self.assertRaises(BrowserCaptchaError):
            await self.submit()
        self.observer.assert_awaited_once()
        native.continue_.assert_not_awaited()
        duplicate.continue_.assert_not_awaited()
        native.abort.assert_awaited_once()
        duplicate.abort.assert_awaited_once()

    async def test_failed_continue_is_counted_once_and_not_replayed(self):
        native, duplicate = make_route(), make_route()
        native.continue_.side_effect = RuntimeError("connection lost")
        self.dispatch_on_submit(native, duplicate)
        with self.assertRaises(BrowserCaptchaError):
            await self.submit()
        self.observer.assert_awaited_once()
        native.continue_.assert_awaited_once()
        duplicate.continue_.assert_not_awaited()

    async def test_text_video_and_frame_video_use_same_admission_hook(self):
        # Fake frame preparation binds media IDs; it uploads no real images.
        for mode in ("text", "start", "start_end"):
            with self.subTest(mode=mode):
                self.page = FakePage()
                self.context.new_page.return_value = self.page
                model = "abra_t2v_4s" if mode == "text" else "abra_i2v_4s"
                spec = {
                    "website_key": "fixture", "prompt": "a real prompt",
                    "model_key": model, "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
                    "mode": mode,
                }
                argument = video_argument(model=model)
                rpc = {"text": "YhhmEf", "start": "eb1hJf", "start_end": "nprQif"}[mode]
                if mode != "text":
                    request = argument[0][0]
                    refs = ["first"] if mode == "start" else ["first", "last"]
                    argument[0][0] = request[:4] + [[None, ref] for ref in refs] + [request[4]]
                    spec["frame_images"] = [b"fixture"] * len(refs)

                    async def prepare_frames(page, validated, **kwargs):
                        validated["frame_media_ids"] = refs
                else:
                    prepare_frames = AsyncMock()
                body = urlencode({"f.req": json.dumps([[[rpc, json.dumps(argument), None, "generic"]]]), "at": "fixture"})
                native = make_route(url=RPC_URL + rpc, body=body)
                self.dispatch_on_submit(native)
                callback = AsyncMock()
                with patch("src.services.native_video_submission.validate_frame_images", return_value=[]), \
                     patch("src.services.native_video_submission.upload_native_frames", side_effect=prepare_frames), \
                     patch("src.services.native_video_submission._record_wire_shape"):
                    await submit_native_video(
                        self.browser, self.context, "project", spec, 1, on_generation_sent=callback,
                    )
                callback.assert_awaited_once()
                native.continue_.assert_awaited_once()

    async def test_client_service_and_route_bind_callback_explicitly_across_contexts(self):
        client = FlowClient(proxy_manager=None)
        self.browser._semaphore = asyncio.Semaphore(1)
        self.browser._solve_inflight = self.browser._solve_count = self.browser._error_count = 0
        self.browser._consecutive_browser_failures = 0
        self.browser._get_or_create_shared_browser = AsyncMock(return_value=(None, None, self.context))
        self.browser.note_idle = Mock()
        self.browser.get_last_fingerprint = Mock(return_value={})
        service = BrowserCaptchaService.__new__(BrowserCaptchaService)
        service._check_available = Mock()
        service._stats = {"req_total": 0, "gen_ok": 0, "gen_fail": 0}
        service._token_semaphore = None
        service.website_key = "fixture-key"
        service._select_browser_id = AsyncMock(return_value=0)
        service._get_or_create_browser = AsyncMock(return_value=self.browser)
        service._resolve_token_proxy_url = AsyncMock(return_value=None)
        service._release_slot_reservation = AsyncMock()
        service._log_stats = Mock()
        fake_module = SimpleNamespace(BrowserCaptchaService=SimpleNamespace(get_instance=AsyncMock(return_value=service)))
        for kind in ("image", "video"):
            with self.subTest(kind=kind):
                self.page = FakePage()
                self.context.new_page.return_value = self.page
                native = make_route() if kind == "image" else make_route(
                    url=VIDEO_URL, body=video_body(video_argument()),
                )

                async def dispatch_from_foreign_context():
                    await asyncio.create_task(self.page.dispatch(native), context=contextvars.Context())
                self.page.on_submit = dispatch_from_foreign_context
                observer = AsyncMock()
                token = client.set_generation_sent_callback(observer)
                try:
                    with patch.dict(sys.modules, {"src.services.browser_captcha": fake_module}):
                        if kind == "image":
                            await client._submit_browser_native_image(
                                project_id="project", token_id=1, prompt="a real prompt",
                                model_name="BELUGA", aspect_ratio="IMAGE_ASPECT_RATIO_PORTRAIT",
                            )
                        else:
                            await client._submit_browser_native_video(
                                project_id="project", token_id=1, prompt="a real prompt",
                                model_key="abra_t2v_4s", aspect_ratio="VIDEO_ASPECT_RATIO_LANDSCAPE",
                            )
                    observer.assert_awaited_once()
                    self.assertTrue(client._generation_request_was_sent())
                finally:
                    client.clear_generation_sent_callback(token)
                self.assertIsNone(client.get_generation_sent_callback())


class HttpSentHookTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.client = FlowClient(proxy_manager=None)
        self.observer = AsyncMock()
        self.client.set_generation_sent_callback(self.observer)
        self.client._resolve_flow_frontend_cookie_storage = AsyncMock(return_value="SID=fixture")
        self.client._frontend_cookie = AsyncMock(return_value="SID=fixture")
        self.client._get_recaptcha_token = AsyncMock(return_value=("fixture-captcha", None))
        self.client._notify_browser_captcha_request_finished = AsyncMock()
        self.client._load_flow_frontend_bootstrap = AsyncMock(return_value=BOOTSTRAP)
        self.client._normalize_frontend_image_generation_response = Mock(return_value={"media": []})
        self.client._normalize_frontend_video_submission = Mock(return_value={"operations": []})
        self.client._resolve_batchexecute_captcha_override = Mock(return_value=None)
        self.client._get_runtime_config = Mock(return_value=SimpleNamespace(
            flow_max_retries=3, image_timeout=120, flow_image_request_timeout=90,
        ))
        response = SimpleNamespace(status_code=200, headers={}, text=json.dumps([["wrb.fr", "ogiZ0b", "[1]"]]))
        self.post = AsyncMock(return_value=response)
        self.enterContext(patch("src.services.flow_client.AsyncSession", return_value=_Session(self.post)))
        self.enterContext(patch("src.services.flow_client.debug_logger"))

    async def image(self):
        with patch("src.services.flow_current.config") as cfg:
            cfg.captcha_method = "yescaptcha"
            return await self.client.generate_image(
                "at", "project", "a real prompt", "BELUGA", "IMAGE_ASPECT_RATIO_PORTRAIT",
                google_cookies="SID=fixture",
            )

    async def test_nonnative_image_counts_at_actual_post_once(self):
        order = []
        self.observer.side_effect = lambda: order.append("count")
        response = self.post.return_value
        self.post.side_effect = lambda *args, **kwargs: order.append("post") or response
        await self.image()
        self.assertEqual(order, ["count", "post"])
        self.observer.assert_awaited_once()
        self.post.assert_awaited_once()
        self.assertEqual(self.client._get_recaptcha_token.await_count, 1)

    async def test_ambiguous_post_failure_cannot_retry_generation(self):
        self.post.side_effect = RuntimeError("connection lost after send")
        with self.assertRaisesRegex(Exception, "connection lost"):
            await self.image()
        self.observer.assert_awaited_once()
        self.post.assert_awaited_once()
        self.client._get_recaptcha_token.assert_awaited_once()

    async def test_callback_failure_cannot_send_or_retry_generation(self):
        self.observer.side_effect = RuntimeError("observer unavailable")
        with self.assertRaisesRegex(Exception, "observer unavailable"):
            await self.image()
        self.observer.assert_awaited_once()
        self.post.assert_not_awaited()
        self.client._get_recaptcha_token.assert_awaited_once()

    async def test_bootstrap_failure_never_counts_a_post(self):
        self.client._load_flow_frontend_bootstrap.side_effect = RuntimeError("bootstrap unavailable")
        with self.assertRaisesRegex(RuntimeError, "bootstrap unavailable"):
            await self.image()
        self.observer.assert_not_awaited()
        self.post.assert_not_awaited()

    async def test_xsrf_challenge_does_not_replay_generation(self):
        self.post.return_value.text = '[["xsrf","refreshed"]]'
        with self.assertRaisesRegex(Exception, "replay disabled"):
            await self.image()
        self.observer.assert_awaited_once()
        self.post.assert_awaited_once()
        self.client._get_recaptcha_token.assert_awaited_once()

    async def test_nonnative_video_failure_counts_once_without_retry(self):
        self.post.side_effect = RuntimeError("video connection lost")
        with patch("src.services.flow_current.config") as cfg:
            cfg.captcha_method = "yescaptcha"
            with self.assertRaisesRegex(Exception, "video connection lost"):
                await self.client.generate_video_text(
                    "at", "project", "a real prompt", "abra_t2v_4s", "VIDEO_ASPECT_RATIO_LANDSCAPE",
                    google_cookies="SID=fixture",
                )
        self.observer.assert_awaited_once()
        self.post.assert_awaited_once()
        self.client._get_recaptcha_token.assert_awaited_once()

    async def test_control_plane_and_upsample_posts_are_not_counted(self):
        for rpc in ("nzlxg", "maseQ", "as29s", "SPrCad"):
            await self.client._make_text_request("POST", RPC_URL + rpc, raw_body="fixture")
        await self.client._make_text_request("GET", RPC_URL + "ogiZ0b")
        self.observer.assert_not_awaited()
        self.assertEqual(self.post.await_count, 4)

    async def test_callback_scopes_are_isolated_for_concurrent_accounts(self):
        self.client.clear_generation_sent_callback()
        observers = [AsyncMock(), AsyncMock()]
        barrier = asyncio.Event()

        async def account(index):
            token = self.client.set_generation_sent_callback(observers[index])
            bound = self.client.get_generation_sent_callback()
            try:
                await barrier.wait()
                await asyncio.create_task(bound(), context=contextvars.Context())
                await self.client._notify_generation_sent()
                self.assertTrue(self.client._generation_request_was_sent())
            finally:
                self.client.clear_generation_sent_callback(token)
            self.assertIsNone(self.client.get_generation_sent_callback())

        tasks = [asyncio.create_task(account(index)) for index in range(2)]
        barrier.set()
        await asyncio.gather(*tasks)
        for observer in observers:
            observer.assert_awaited_once()
        self.assertIsNone(self.client.get_generation_sent_callback())

    async def test_cleanup_from_foreign_context_does_not_raise_or_change_owner_scope(self):
        self.client.clear_generation_sent_callback()
        owner_observer = AsyncMock()
        token = self.client.set_generation_sent_callback(owner_observer)
        bound = self.client.get_generation_sent_callback()
        foreign = contextvars.Context()
        foreign.run(self.client.set_generation_sent_callback, AsyncMock())
        foreign.run(self.client.clear_generation_sent_callback, token)
        self.assertIsNone(foreign.run(self.client.get_generation_sent_callback))
        await asyncio.create_task(bound(), context=foreign)
        await asyncio.create_task(bound(), context=foreign)
        owner_observer.assert_awaited_once()
        self.assertTrue(self.client._generation_request_was_sent())
        self.client.clear_generation_sent_callback(token)
        self.assertIsNone(self.client.get_generation_sent_callback())


if __name__ == "__main__":
    unittest.main()
