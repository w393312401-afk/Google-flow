import asyncio
import json
import tempfile
import hashlib
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from src.core.database import Database
from src.services.flow_frontend import FlowFrontendMixin, FlowRPCRejected
from src.services.submission_ledger import SubmissionLedger
from src.api import routes
from fastapi import FastAPI
from fastapi.testclient import TestClient
from src.services.generation_handler import MODEL_CONFIG


class SubmissionLedgerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(str(Path(self.tmp.name) / 'receipts.db'))
        self.ledger = SubmissionLedger(self.db)
        self.sid = '5d46919d-6041-4a6a-b1a6-d0f861fb0264'

    async def asyncTearDown(self):
        self.tmp.cleanup()

    async def test_atomic_reservation_prevents_concurrent_and_restart_duplicates(self):
        result = await asyncio.gather(*(self.ledger.reserve(self.sid, 'same') for _ in range(8)))
        self.assertEqual(sum(created for created, _ in result), 1)
        restarted = SubmissionLedger(Database(self.db.db_path))
        self.assertEqual(await restarted.reserve(self.sid, 'same'), (False, True))
        self.assertEqual(await restarted.reserve(self.sid, 'different'), (False, False))

    async def test_unknown_and_missing_receipts_remain_unresolved(self):
        handler = SimpleNamespace(flow_client=SimpleNamespace(check_video_status=AsyncMock()))
        missing = await self.ledger.observe(self.sid, handler)
        self.assertTrue(missing['submission_pending'])
        self.assertIsNone(missing['upstream_accepted'])
        await self.ledger.reserve(self.sid, 'same')
        await self.ledger.capture(self.sid, {'error': {'code': 'generation_failed'}})
        pending = await self.ledger.observe(self.sid, handler)
        self.assertEqual(pending['state'], 'pending')
        handler.flow_client.check_video_status.assert_not_awaited()

    async def test_original_operation_is_recovered_without_any_submit(self):
        await self.ledger.reserve(self.sid, 'same')
        operations = [{'operation': {'name': 'original'}, 'projectId': 'project'}]
        await self.ledger.accepted(self.sid, 2, 'project', operations)
        token = SimpleNamespace(id=2, at='fixture', google_cookies='fixture')
        self.db.get_token = AsyncMock(return_value=token)
        self.db.update_task = AsyncMock()
        client = SimpleNamespace(
            check_video_status=AsyncMock(return_value={'operations': [{'name': 'original', 'status': 'MEDIA_GENERATION_STATUS_SUCCESSFUL'}]}),
            _find_flow_content_url=lambda *_: 'https://flow-content.google/video/original',
            generate_video=AsyncMock(),
        )
        recovered = await self.ledger.observe(self.sid, SimpleNamespace(flow_client=client))
        self.assertEqual(recovered['state'], 'confirmed')
        self.assertFalse(recovered['submission_pending'])
        self.assertEqual(recovered['operation_id'], 'original')
        client.check_video_status.assert_awaited_once_with('fixture', operations, token_id=2, google_cookies='fixture')
        client.generate_video.assert_not_awaited()

    async def test_poll_auth_error_preserves_paid_original(self):
        await self.ledger.reserve(self.sid, 'same')
        await self.ledger.accepted(self.sid, 2, 'project', [{'name': 'original'}])
        self.db.get_token = AsyncMock(return_value=SimpleNamespace(id=2, at='fixture', google_cookies='fixture'))
        client = SimpleNamespace(check_video_status=AsyncMock(side_effect=RuntimeError('401')))
        result = await self.ledger.observe(self.sid, SimpleNamespace(flow_client=client))
        self.assertEqual(result['state'], 'pending')
        self.assertTrue(result['upstream_accepted'])
        self.assertEqual(result['error']['reason'], 'poll_auth_failed')

    async def test_false_unsubmitted_after_accepted_does_not_clear_paid_receipt(self):
        await self.ledger.reserve(self.sid, 'same')
        await self.ledger.accepted(self.sid, 2, 'project', [{'name': 'original'}])
        await self.ledger.capture(self.sid, {'error': {
            'code': 'submission_not_started', 'submission_pending': False, 'upstream_accepted': False,
        }})
        result = self.ledger.public(self.sid, await self.ledger.get(self.sid))
        self.assertEqual(result['state'], 'pending')
        self.assertTrue(result['submission_pending'])

    async def test_explicit_refusal_and_confirmed_terminal_failure_are_distinct(self):
        await self.ledger.reserve(self.sid, 'same')
        await self.ledger.capture(self.sid, {'error': {'code': 'submission_rejected', 'submission_pending': False, 'upstream_accepted': False}})
        self.assertEqual((await self.ledger.get(self.sid))['state'], 'refused')
        await self.ledger.accepted(self.sid, 2, 'project', [{'name': 'original'}])
        await self.ledger.capture(self.sid, {'error': {'code': 'video_generation_failed', 'submission_pending': False, 'upstream_accepted': True}})
        self.assertEqual((await self.ledger.get(self.sid))['state'], 'failed')

    async def test_generic_false_flag_is_not_non_submission_proof(self):
        await self.ledger.reserve(self.sid, 'same')
        await self.ledger.capture(self.sid, {'error': {'code': 'generation_failed', 'submission_pending': False}})
        self.assertEqual((await self.ledger.get(self.sid))['state'], 'pending')

    async def test_wrong_original_operation_cannot_confirm_receipt(self):
        await self.ledger.reserve(self.sid, 'same')
        await self.ledger.accepted(self.sid, 2, 'project', [{'name': 'original'}])
        self.db.get_token = AsyncMock(return_value=SimpleNamespace(id=2, at='fixture', google_cookies='fixture'))
        client = SimpleNamespace(
            check_video_status=AsyncMock(return_value={'operations': [{'name': 'other', 'status': 'MEDIA_GENERATION_STATUS_SUCCESSFUL'}]}),
            _find_flow_content_url=lambda *_: 'https://example.test/other.mp4',
        )
        result = await self.ledger.observe(self.sid, SimpleNamespace(flow_client=client))
        self.assertEqual(result['state'], 'pending')
        self.assertNotIn('video_url', result)

    async def test_expired_original_delivery_url_is_refreshed_without_resubmission(self):
        await self.ledger.reserve(self.sid, 'same')
        await self.ledger.accepted(self.sid, 2, 'project', [{'name': 'original'}])
        await self.ledger.update(self.sid, state='confirmed', video_url='https://flow-content.google/video/original?Expires=1')
        self.db.get_token = AsyncMock(return_value=SimpleNamespace(id=2, at='fixture', google_cookies='fixture'))
        self.db.update_task = AsyncMock()
        client = SimpleNamespace(
            check_video_status=AsyncMock(return_value={'operations': [{'name': 'original', 'status': 'MEDIA_GENERATION_STATUS_SUCCESSFUL'}]}),
            _find_flow_content_url=lambda *_: 'https://flow-content.google/video/original?Expires=9999999999',
        )
        result = await self.ledger.observe(self.sid, SimpleNamespace(flow_client=client))
        self.assertIn('9999999999', result['video_url'])
        client.check_video_status.assert_awaited_once()

    async def test_refresh_auth_failure_does_not_unsettle_confirmed_paid_task(self):
        await self.ledger.reserve(self.sid, 'same')
        await self.ledger.accepted(self.sid, 2, 'project', [{'name': 'original'}])
        await self.ledger.update(self.sid, state='confirmed', video_url='https://flow-content.google/video/original?Expires=1')
        self.db.get_token = AsyncMock(return_value=SimpleNamespace(id=2, at='fixture', google_cookies='fixture'))
        client = SimpleNamespace(check_video_status=AsyncMock(side_effect=RuntimeError('401')))
        result = await self.ledger.observe(self.sid, SimpleNamespace(flow_client=client))
        self.assertEqual(result['state'], 'confirmed')
        self.assertFalse(result['submission_pending'])
        self.assertTrue(result['delivery_pending'])
        self.assertIsNone(result['video_url'])

    async def test_stream_capture_persists_completion_before_yield(self):
        await self.ledger.reserve(self.sid, 'same')
        payload = {'choices': [{'delta': {'content': "<video src='https://example.test/original.mp4' controls></video>"}}]}
        await self.ledger.capture(self.sid, payload)
        self.assertEqual((await self.ledger.get(self.sid))['state'], 'confirmed')
        await self.ledger.capture(self.sid, {'error': {'code': 'generation_failed', 'message': 'local logging failed'}})
        self.assertEqual((await self.ledger.get(self.sid))['state'], 'confirmed')

    async def test_legacy_backfill_requires_unique_exact_prompt_evidence(self):
        prompt = 'exact original fixture prompt'
        fingerprint = hashlib.sha256(prompt.encode()).hexdigest()
        async with self.db._connect(write=True) as con:
            await con.execute('CREATE TABLE request_logs (id INTEGER, token_id INTEGER, request_body TEXT, response_body TEXT)')
            await con.execute('INSERT INTO request_logs VALUES (219,2,?,?)', (
                json.dumps({'model': 'fixture-model', 'prompt': prompt}),
                json.dumps({'error': '生成失败: Flow frontend RPC rejected: rpc=nprQif, error=PUBLIC_ERROR_UNUSUAL_ACTIVITY'}),
            ))
            await con.commit()
        result = await self.ledger.backfill_legacy(self.sid, 219, fingerprint)
        self.assertEqual(result['state'], 'refused')
        self.assertEqual(result['api_model'], 'fixture-model')
        other = '77777777-7777-4777-8777-777777777777'
        async with self.db._connect(write=True) as con:
            await con.execute('INSERT INTO request_logs SELECT 220,token_id,request_body,response_body FROM request_logs WHERE id=219')
            await con.commit()
        with self.assertRaises(ValueError):
            await self.ledger.backfill_legacy(other, 219, fingerprint)
        self.assertIsNone(await self.ledger.get(other))


class ExplicitRPCRejectionTests(unittest.TestCase):
    def test_native_generation_refusal_has_structured_provenance(self):
        frames = [[['wrb.fr', 'nprQif', None, None, None, ['PUBLIC_ERROR_UNUSUAL_ACTIVITY']]]]
        with self.assertRaises(FlowRPCRejected) as caught:
            FlowFrontendMixin._raise_batchexecute_error(frames, 'nprQif')
        self.assertTrue(caught.exception.submission_rejected)
        self.assertEqual(caught.exception.error_code, 'PUBLIC_ERROR_UNUSUAL_ACTIVITY')

    def test_poll_rejection_does_not_mean_original_submission_rejected(self):
        error = FlowRPCRejected('unauthorized', 'jwpduf', '401')
        self.assertFalse(error.submission_rejected)
        self.assertFalse(FlowRPCRejected('server error', 'nprQif', '500').submission_rejected)
        self.assertFalse(FlowRPCRejected('unknown', 'nprQif', 'unknown').submission_rejected)


class SubmissionRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(str(Path(self.tmp.name) / 'route.db'))
        self.calls = []
        self.old_handler = routes.generation_handler
        self.model = next(name for name, config in MODEL_CONFIG.items() if config['type'] == 'video' and config.get('video_type') == 't2v')
        async def generate(**kwargs):
            self.calls.append(kwargs)
            yield json.dumps({'error': {
                'code': 'submission_rejected', 'message': 'fixture refusal', 'reason': 'unusual_activity',
                'status_code': 500, 'submission_pending': False, 'upstream_accepted': False,
            }})
        self.handler = SimpleNamespace(db=self.db, handle_generation=generate)
        routes.set_generation_handler(self.handler)
        app = FastAPI()
        app.include_router(routes.router)
        app.dependency_overrides[routes.verify_api_key_flexible] = lambda: 'fixture'
        self.client = TestClient(app)
        self.sid = '5d46919d-6041-4a6a-b1a6-d0f861fb0264'

    def tearDown(self):
        routes.set_generation_handler(self.old_handler)
        self.client.close()
        self.tmp.cleanup()

    def test_header_is_forwarded_and_duplicate_never_generates(self):
        body = {'model': self.model, 'messages': [{'role': 'user', 'content': 'same original prompt'}]}
        headers = {'X-SPARK-Submission-ID': self.sid}
        first = self.client.post('/v1/chat/completions', json=body, headers=headers)
        self.assertEqual(first.status_code, 500)
        self.assertEqual(first.json()['error']['client_submission_id'], self.sid)
        observation = self.client.get('/v1/submissions/' + self.sid).json()
        self.assertEqual(observation['state'], 'refused')
        self.assertEqual(observation['api_model'], self.model)
        second = self.client.post('/v1/chat/completions', json=body, headers=headers)
        self.assertEqual(second.status_code, 409)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0]['client_submission_id'], self.sid)
        body['messages'][0]['content'] = 'different prompt'
        changed = self.client.post('/v1/chat/completions', json=body, headers=headers)
        self.assertEqual(changed.json()['error']['code'], 'submission_identity_conflict')
        self.assertEqual(len(self.calls), 1)

    def test_unknown_submission_does_not_create_or_generate(self):
        result = self.client.get('/v1/submissions/' + self.sid).json()
        self.assertEqual(result['state'], 'not_found')
        self.assertTrue(result['submission_pending'])
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
