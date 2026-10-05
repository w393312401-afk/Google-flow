"""Inactive account staging checks; all services and browser reads are mocked."""
import copy
import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import AsyncMock


PATH = Path(__file__).resolve().parents[1] / 'local/sync_adspower_cookies.py'
SPEC = importlib.util.spec_from_file_location('sync_staged_adspower_cookies', PATH)
sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync)


class StagedSyncTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        directory = Path(self.temporary.name)
        self.database = directory / 'flow.db'
        with sqlite3.connect(self.database) as db:
            db.execute('CREATE TABLE tasks(token_id INTEGER,status TEXT)')
            db.execute('CREATE TABLE request_logs(token_id INTEGER,status_code INTEGER,status_text TEXT)')
            db.execute("INSERT INTO tasks VALUES(2,'processing')")
            db.execute("INSERT INTO request_logs VALUES(2,102,'submitted')")
        spark_config = directory / 'spark.json'
        sync.save_private(spark_config, {})
        self.config = sync.validate_config(dict(
            profile_id='new-profile', expected_email='new@example.test', token_id=None,
            adspower_base='http://127.0.0.1:50325', flow_base='http://127.0.0.1:38000',
            enable_on_create=False, stage_inactive_create=True,
            flow_db_path=str(self.database), spark_config_path=str(spark_config)))
        self.cookies = [{'name': 'SID', 'value': 'TEST_VALUE', 'domain': '.google.com',
                         'path': '/', 'secure': True}]
        self.profile = {'ws': 'ws://127.0.0.1:1234/devtools/browser/test',
                        'proxy': 'http://proxy.example.test:3128'}
        self.validator = AsyncMock(return_value={'email': 'new@example.test', 'credits': 100})
        self.tasks = {'tasks': [{'status': 'running', 'dimensions': {
            'type': 'videos', 'video_provider': 'flow2api', 'fx_capable': False}}], 'total_count': 1}
        self.board = {'status': 'ok', 'board': {'leases': [], 'waiting': []}}
        self.rows = [dict(id=2, email='existing@example.test', login_account='existing@example.test',
                         remark='original', is_active=True, google_cookies='existing')]
        self.gateway = sync.Gateway(self.config, None, {})
        self.gateway.profile = AsyncMock(side_effect=lambda: copy.deepcopy(self.profile))
        self.gateway.tokens = AsyncMock(side_effect=lambda: copy.deepcopy(self.rows))
        self.gateway.cookies = AsyncMock(return_value=self.cookies)

        async def request(method, base, path, **kwargs):
            self.assertEqual(method, 'GET')
            if path == '/api/tasks':
                return copy.deepcopy(self.tasks)
            self.assertEqual(path, '/api/google-fx/board')
            return copy.deepcopy(self.board)

        async def write(token_id, payload):
            if token_id is None:
                self.rows.append(dict(payload, id=3, email=payload['login_account']))
            else:
                next(row for row in self.rows if row['id'] == token_id)['google_cookies'] = payload['google_cookies']

        self.gateway.request = AsyncMock(side_effect=request)
        self.gateway.write = AsyncMock(side_effect=write)
        self.gateway.busy = AsyncMock(wraps=self.gateway.busy)

    async def run_sync(self):
        return await sync.synchronize(self.config, {}, self.gateway, validator=self.validator, now=1000)

    def assert_no_write(self):
        self.gateway.write.assert_not_awaited()

    async def test_staging_ignores_other_owned_flow_work_without_mutating_it(self):
        database_before, existing_before = self.database.read_bytes(), copy.deepcopy(self.rows[0])
        result = await self.run_sync()
        self.assertEqual(result['status'], 'created')
        token_id, payload = self.gateway.write.await_args.args
        self.assertIsNone(token_id)
        self.assertTrue(all(payload[key] is False for key in ('is_active', 'image_enabled', 'video_enabled')))
        self.assertEqual(payload['proxy_url'], self.profile['proxy'])
        self.assertEqual(payload['captcha_proxy_url'], self.profile['proxy'])
        self.assertEqual(self.rows[0], existing_before)
        self.assertEqual(self.database.read_bytes(), database_before)
        self.assertEqual(self.gateway.busy.await_count, 2)
        self.assertTrue(all(call.kwargs == {'stage_inactive_create': True}
                            for call in self.gateway.busy.await_args_list))
        self.assertEqual(self.gateway.profile.await_count, 2)
        self.validator.assert_awaited_once_with(self.cookies, 'new@example.test', self.profile['proxy'])

    async def test_no_opt_in_keeps_global_flow_busy_check(self):
        self.config.pop('stage_inactive_create')
        self.assertEqual((await self.run_sync())['reason'], 'generation_busy')
        self.assert_no_write()

    async def test_existing_account_keeps_its_busy_check_and_flags(self):
        self.rows[0].update(email='new@example.test', login_account='new@example.test',
            remark='adspower-sync:new-profile', proxy_url=self.profile['proxy'],
            captcha_proxy_url=self.profile['proxy'], image_enabled=True, video_enabled=True)
        self.assertEqual((await self.run_sync())['reason'], 'generation_busy')
        self.gateway.busy.assert_awaited_once_with(2)
        self.assert_no_write()

    async def test_invalid_opt_in_fails_before_external_reads(self):
        for stage, enabled in [(True, True), ('true', False), (1, False), (None, False)]:
            with self.subTest(stage=stage, enabled=enabled):
                self.config.update(stage_inactive_create=stage, enable_on_create=enabled)
                with self.assertRaisesRegex(sync.SyncError, 'invalid_inactive_staging'):
                    await self.run_sync()
        self.gateway.profile.assert_not_awaited()
        self.assert_no_write()

    async def test_unowned_live_flow_request_still_blocks_staging(self):
        with sqlite3.connect(self.database) as db:
            db.execute("INSERT INTO request_logs VALUES(NULL,102,'started')")
        self.assertEqual((await self.run_sync())['reason'], 'generation_busy')
        self.assert_no_write()

    async def test_unowned_live_flow_task_still_blocks_staging(self):
        with sqlite3.connect(self.database) as db:
            db.execute("INSERT INTO tasks VALUES(NULL,'processing')")
        self.assertEqual((await self.run_sync())['reason'], 'generation_busy')
        self.assert_no_write()

    async def test_cancelled_spark_task_with_lease_still_blocks_staging(self):
        self.tasks['tasks'][0]['status'] = 'cancelled'
        self.board['board']['leases'] = [{'user_id': 'new-profile'}]
        self.assertEqual((await self.run_sync())['reason'], 'generation_busy')
        self.assert_no_write()

    async def test_active_spark_profile_task_still_blocks_staging(self):
        self.tasks['tasks'][0]['dimensions'] = {'video_fixed_user_id': 'new-profile'}
        self.assertEqual((await self.run_sync())['reason'], 'generation_busy')
        self.assert_no_write()

    async def test_unknown_board_is_fail_closed(self):
        self.board = {'status': 'ok', 'board': {}}
        with self.assertRaisesRegex(sync.SyncError, 'spark_lease_inventory_invalid'):
            await self.run_sync()
        self.assert_no_write()

    async def test_final_spark_check_prevents_racing_write(self):
        async def validate(*_):
            self.board['board']['waiting'] = [{'account_pin': 'new-profile'}]
            return {'email': 'new@example.test', 'credits': 100}
        self.validator.side_effect = validate
        self.assertEqual((await self.run_sync())['reason'], 'generation_busy')
        self.assertEqual(self.gateway.busy.await_count, 2)
        self.assert_no_write()

    async def test_binding_or_proxy_change_before_write_still_stops(self):
        for changed in ('binding', 'proxy'):
            with self.subTest(changed=changed):
                self.setUp()
                async def validate(*_):
                    if changed == 'binding':
                        self.rows.append(dict(id=3, email='new@example.test', login_account='new@example.test',
                                              remark='adspower-sync:new-profile'))
                    else:
                        self.profile['proxy'] = 'http://changed.example.test:3128'
                    return {'email': 'new@example.test', 'credits': 100}
                self.validator.side_effect = validate
                with self.assertRaises(sync.SyncError):
                    await self.run_sync()
                self.assert_no_write()

    async def test_identity_rejection_still_stops_staging(self):
        self.validator.return_value['email'] = 'other@example.test'
        with self.assertRaisesRegex(sync.SyncError, 'google_identity_mismatch'):
            await self.run_sync()
        self.assert_no_write()


if __name__ == '__main__':
    unittest.main()
