import io
import json
import unittest
from unittest.mock import AsyncMock, Mock, patch
from types import SimpleNamespace
from urllib.parse import urlencode

from PIL import Image

from src.services.captcha_errors import BrowserCaptchaError
from src.services.native_frame_upload import validate_frame_images
from src.services.native_video_submission import _validate_video_spec, _verify_video_request
from src.services.flow_client import FlowClient
from src.services.generation_handler import GenerationHandler, MODEL_CONFIG
from src.core.models import Token
from tests.test_native_video_submission import video_argument


def png_bytes(color):
    output = io.BytesIO()
    Image.new('RGB', (32, 48), color).save(output, format='PNG')
    return output.getvalue()


class NativeFrameValidationTests(unittest.TestCase):
    def setUp(self):
        self.images = [png_bytes('red'), png_bytes('blue')]
        self.spec = _validate_video_spec({
            'website_key': 'key', 'model_key': 'abra_i2v_10s', 'prompt': 'a real prompt',
            'aspect_ratio': '9:16', 'mode': 'start_end', 'frame_images': self.images,
        })
        self.spec['frame_media_ids'] = ['first-media-id', 'last-media-id']

    def body(self, *, reverse=False):
        argument = video_argument(model='abra_i2v_10s', aspect=1)
        base = argument[0][0]
        refs = self.spec['frame_media_ids'][::-1] if reverse else self.spec['frame_media_ids']
        argument[0][0] = base[:4] + [[None, ref] for ref in refs] + [base[4]]
        return urlencode({'f.req': json.dumps([[['nprQif', json.dumps(argument), None, 'generic']]]), 'at': 'fixture'})

    def test_original_frame_request_preserves_exact_semantic_order(self):
        with patch('src.services.native_video_submission._record_wire_shape'):
            self.assertEqual(_verify_video_request(self.body(), 'project', self.spec), (None, 'native-submission-id'))
            with self.assertRaises(BrowserCaptchaError) as error:
                _verify_video_request(self.body(reverse=True), 'project', self.spec)
        self.assertEqual(error.exception.reason, 'video_frame_binding_mismatch')

    def test_same_bytes_can_be_used_for_both_roles_without_collapsing_uploads(self):
        files = validate_frame_images([self.images[0], self.images[0]], 'start_end')
        self.assertEqual(len(files), 2)
        self.assertNotEqual(files[0]['name'], files[1]['name'])
        self.assertEqual(files[0]['buffer'], files[1]['buffer'])

    def test_malformed_image_wrong_count_and_text_fallback_are_rejected(self):
        for images, mode in (([b'not-an-image'], 'start'), ([self.images[0]], 'start_end'), (self.images, 'text')):
            with self.assertRaises(BrowserCaptchaError):
                validate_frame_images(images, mode)
        with self.assertRaises(BrowserCaptchaError):
            _validate_video_spec({**self.spec, 'model_key': 'abra_t2v_10s'})

    def test_observed_360p_dual_frame_model_crop_and_identity_are_preserved(self):
        argument = video_argument(model='omni_flash_i2v_10s_first_last_360p', aspect=1)
        request = argument[0][0]
        argument[0][0] = request[:4] + [
            [None, 'first-media-id', None, None, None, [0.0003, None, 0.9997, 1]],
            [None, 'last-media-id', None, None, None, [None, 0.0002, 1, 0.9998]],
            request[4],
        ]
        def body():
            return urlencode({'f.req': json.dumps([[['nprQif', json.dumps(argument), None, 'generic']]]), 'at': 'fixture'})
        with patch('src.services.native_video_submission._record_wire_shape'):
            result = _verify_video_request(body(), 'project', {**self.spec, 'resolution': '360p'})
            self.assertEqual(result, (None, 'native-submission-id'))
            argument[0][0][5][1] = 'first-media-id'
            with self.assertRaises(BrowserCaptchaError) as error:
                _verify_video_request(body(), 'project', {**self.spec, 'resolution': '360p'})
            self.assertEqual(error.exception.reason, 'video_frame_binding_mismatch')
            # Even a regressed uploader supplying duplicate expected IDs must
            # not let different input bytes become the same frame twice.
            with self.assertRaises(BrowserCaptchaError):
                _verify_video_request(body(), 'project', {**self.spec, 'resolution': '360p',
                    'frame_media_ids': ['first-media-id', 'first-media-id']})

    def test_observed_single_frame_360p_request_keeps_crop_and_resolution_tail(self):
        argument = video_argument(model='abra_i2v_10s_360p', aspect=1)
        request = argument[0][0]
        argument[0][0] = request[:4] + [[None, 'first-media-id', None, None, None,
            [0.0003, None, 0.9997, 1]], request[4], None, None, None, [4]]
        spec = {**self.spec, 'mode': 'start', 'resolution': '360p',
                'frame_images': self.images[:1], 'frame_media_ids': ['first-media-id']}
        def body():
            return urlencode({'f.req': json.dumps([[['eb1hJf', json.dumps(argument), None, 'generic']]]), 'at': 'fixture'})
        with patch('src.services.native_video_submission._record_wire_shape'):
            self.assertEqual(_verify_video_request(body(), 'project', spec), (None, 'native-submission-id'))
            argument[0][0][9] = 1
            with self.assertRaises(BrowserCaptchaError) as error:
                _verify_video_request(body(), 'project', spec)
            self.assertEqual(error.exception.reason, 'video_resolution_shape_mismatch')

    def test_observed_text_360p_request_requires_encoded_key_and_array_tail(self):
        argument = video_argument(model='abra_t2v_10s_360p', aspect=1)
        argument[0][0][5:] = [None, None, [4]]
        spec = {**self.spec, 'model_key': 'abra_t2v_10s', 'mode': 'text', 'resolution': '360p',
                'frame_images': [], 'frame_media_ids': []}
        def body():
            return urlencode({'f.req': json.dumps([[['YhhmEf', json.dumps(argument), None, 'generic']]]), 'at': 'fixture'})
        with patch('src.services.native_video_submission._record_wire_shape'):
            self.assertEqual(_verify_video_request(body(), 'project', spec), (None, 'native-submission-id'))
            argument[0][0][7] = 1
            with self.assertRaises(BrowserCaptchaError) as error:
                _verify_video_request(body(), 'project', spec)
            self.assertEqual(error.exception.reason, 'video_resolution_shape_mismatch')

    def test_unproven_360p_tail_is_rejected_instead_of_silently_using_720p(self):
        with patch('src.services.native_video_submission._record_wire_shape'):
            with self.assertRaises(BrowserCaptchaError) as error:
                _verify_video_request(self.body(), 'project', {**self.spec, 'resolution': '360p'})
        self.assertEqual(error.exception.reason, 'video_model_mismatch')


class NativeFrameChainTests(unittest.IsolatedAsyncioTestCase):
    async def test_browser_frames_send_bytes_and_parse_matching_rpc(self):
        client = FlowClient(proxy_manager=None)
        client._frontend_cookie = AsyncMock(return_value='SID=fixture')
        client._get_recaptcha_token = AsyncMock()
        client.upload_image = AsyncMock()
        client._current_rpc = AsyncMock()
        client._submit_browser_native_video = AsyncMock(return_value={
            'rpc': 'nprQif', 'response_text': json.dumps([['wrb.fr','nprQif',json.dumps([[['operation','project','media']]])]])
        })
        client._normalize_frontend_video_submission = Mock(return_value={'operations': [{'name': 'operation'}]})
        frames = [png_bytes('red'), png_bytes('blue')]
        with patch('src.services.flow_current.config') as cfg:
            cfg.captcha_method = 'browser'
            await client.generate_video_frames(project_id='project', prompt='prompt', model_key='abra_i2v_10s',
                aspect_ratio='9:16', frame_images=frames, resolution='360p', token_id=1)
        client.upload_image.assert_not_awaited()
        client._get_recaptcha_token.assert_not_awaited()
        client._current_rpc.assert_not_awaited()
        params = client._submit_browser_native_video.await_args.kwargs
        self.assertEqual(params['frame_images'], frames)
        self.assertEqual(params['mode'], 'start_end')
        self.assertEqual(params['resolution'], '360p')
        self.assertEqual(client._normalize_frontend_video_submission.call_args.kwargs['rpc_id'], 'nprQif')

    async def test_handler_native_frames_never_calls_http_upload_or_text_generation(self):
        token = Token(id=1, st='session', at='access', email='test@example.com')
        handler = GenerationHandler.__new__(GenerationHandler)
        failure = BrowserCaptchaError('native_frame_upload', 'test_stop_after_dispatch')
        handler.flow_client = SimpleNamespace(
            generate_video_frames=AsyncMock(side_effect=failure), upload_image=AsyncMock(), generate_video_text=AsyncMock())
        handler._update_request_log_progress = AsyncMock()
        handler._resolve_video_model_key_for_tier = Mock(return_value=('abra_i2v_10s', None))
        config = MODEL_CONFIG['omni-1.1-flash-frames-10s-portrait-360p']
        frames = [png_bytes('red'), png_bytes('blue')]
        with patch('src.services.generation_handler.config') as runtime:
            runtime.captcha_method = 'browser'
            with self.assertRaises(BrowserCaptchaError):
                async for _ in handler._handle_video_generation(token, 'project', config, 'prompt', frames, False):
                    pass
        handler.flow_client.upload_image.assert_not_awaited()
        handler.flow_client.generate_video_text.assert_not_awaited()
        self.assertEqual(handler.flow_client.generate_video_frames.await_args.kwargs['frame_images'], frames)
        self.assertEqual(handler.flow_client.generate_video_frames.await_args.kwargs['resolution'], '360p')


if __name__ == '__main__':
    unittest.main()
