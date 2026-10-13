"""Offline tests: never connect to AdsPower, Flow, or any browser."""
import copy
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
from unittest.mock import AsyncMock, patch
import tempfile
import unittest

import httpx

PATH = Path(__file__).resolve().parents[1] / 'local/sync_adspower_cookies.py'
spec = importlib.util.spec_from_file_location('sync_adspower_cookies', PATH)
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


def config(**values):
    return sync.validate_config(dict(profile_id='fixed-profile', expected_email='fixed@example.test',
        token_id=None, adspower_base='http://127.0.0.1:50325', flow_base='http://127.0.0.1:38000', **values))


def cookies(value='AUTH_SECRET'):
    return [{'name': 'SID', 'value': value, 'domain': '.google.com', 'path': '/', 'secure': True},
            {'name': 'PREF', 'value': 'NON_AUTH', 'domain': '.google.com', 'path': '/', 'secure': True}]


def account(value='OLD_SECRET', **fields):
    row = dict(id=2, email='fixed@example.test', login_account='fixed@example.test',
                remark='adspower-sync:fixed-profile', proxy_url='http://u:p@proxy.test:3128',
                captcha_proxy_url='http://u:p@proxy.test:3128', google_cookies=json.dumps(cookies(value)),
                st='synthetic-session', at='synthetic-access', at_expires='2099-01-01T00:00:00Z',
                is_active=False, image_enabled=False, video_enabled=False)
    row.update(fields)
    return row


def expiry(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


class FakeGateway:
    def __init__(self, rows=None, busy=(False, False)):
        self.rows = copy.deepcopy(rows or [])
        self.busy_value = busy
        self.profile_value = {'ws': 'ws://127.0.0.1:1234/devtools/browser/test', 'proxy': 'http://u:p@proxy.test:3128'}
        self.profile = AsyncMock(side_effect=lambda: copy.deepcopy(self.profile_value))
        self.tokens = AsyncMock(side_effect=lambda: copy.deepcopy(self.rows))
        self.cookies = AsyncMock(return_value=cookies())
        self.busy = AsyncMock(side_effect=lambda _: self.busy_value)
        self.writes = []
        self.renewed_expiry = '2099-01-01T00:00:00Z'

    async def write(self, token_id, payload):
        self.writes.append((token_id, copy.deepcopy(payload)))
        if token_id is None:
            self.rows.append(dict(payload, email=payload['login_account'], id=2,
                                  at_expires=self.renewed_expiry))
        else:
            row = next(t for t in self.rows if t['id'] == token_id)
            if 'google_cookies' in payload:
                row['google_cookies'] = payload['google_cookies']
            else:
                row['at_expires'] = self.renewed_expiry


def validator():
    return AsyncMock(return_value={'email': 'fixed@example.test', 'credits': 925})


async def check_create_is_independent_and_only_uses_original_profile_proxy(enabled):
    old = dict(account(), id=1, email='other@example.test', login_account='other@example.test', remark='original')
    gateway = FakeGateway([old])
    state = {}
    check = validator()
    result = await sync.synchronize(config(enable_on_create=enabled), state, gateway, validator=check, now=1000)
    assert result == {'status': 'created', 'reason': 'sync_complete', 'token_id': 2}
    assert gateway.rows[0] == old
    token_id, payload = gateway.writes[0]
    assert token_id is None
    assert payload['proxy_url'] == payload['captcha_proxy_url'] == gateway.profile_value['proxy']
    assert all(payload[k] is enabled for k in ('is_active', 'image_enabled', 'video_enabled'))
    assert payload['auto_refresh_enabled'] is False
    assert payload['image_concurrency'] == payload['video_concurrency'] == 1
    assert state['token_id'] == 2
    check.assert_awaited_once_with(cookies(), 'fixed@example.test', gateway.profile_value['proxy'])
    assert 'AUTH_SECRET' not in json.dumps(state)


async def check_update_only_cookie_and_no_auto_enable():
    row = account()
    row.update(is_active=False, image_enabled=True, video_enabled=False, auto_refresh_enabled=True)
    gateway = FakeGateway([row])
    result = await sync.synchronize(config(enable_on_create=True), {}, gateway, validator=validator(), now=1000)
    assert result['status'] == 'updated'
    assert set(gateway.writes[0][1]) == {'google_cookies', 'auto_enable_on_update'}
    assert gateway.writes[0][1]['auto_enable_on_update'] is False
    assert all(gateway.rows[0][k] == row[k] for k in row if k != 'google_cookies')


async def check_existing_binding_or_proxy_mismatch_never_reads_cookies_or_writes(changed):
    row, conf = account(), config()
    if changed == 'remark': row['remark'] = 'original-other-profile'
    if changed == 'email': row['email'] = 'different@example.test'
    if changed == 'token_id': conf['token_id'] = 9
    if changed == 'proxy': row['proxy_url'] = 'http://another.test:3128'
    gateway = FakeGateway([row])
    with _CASE.assertRaises(sync.SyncError):
        await sync.synchronize(conf, {}, gateway, validator=validator())
    gateway.cookies.assert_not_awaited()
    assert not gateway.writes


async def check_profile_proxy_drift_stops_before_cookie_read():
    gateway = FakeGateway([account()])
    state = {'proxy_hash': sync.digest(sync.proxy_identity('http://old.test:80'))}
    with _CASE.assertRaisesRegex(sync.SyncError, 'profile_proxy_changed'):
        await sync.synchronize(config(), state, gateway, validator=validator())
    gateway.cookies.assert_not_awaited()
    assert not gateway.writes


async def check_busy_defers_creation_and_updates(existing, busy):
    gateway = FakeGateway([account()] if existing else [], busy=busy)
    check = validator()
    result = await sync.synchronize(config(enable_on_create=True), {}, gateway, validator=check)
    assert result == {'status': 'deferred', 'reason': 'generation_busy'}
    assert not gateway.writes
    check.assert_awaited_once()


async def check_final_busy_check_prevents_racing_write():
    gateway = FakeGateway([account()])
    gateway.busy.side_effect = [(False, False), (True, False)]
    result = await sync.synchronize(config(), {}, gateway, validator=validator())
    assert result['reason'] == 'generation_busy'
    assert not gateway.writes


async def check_unchanged_cookie_revalidates_every_thirty_minutes():
    gateway, check, state = FakeGateway([account('AUTH_SECRET')]), validator(), {}
    assert (await sync.synchronize(config(), state, gateway, validator=check, now=1000))['status'] == 'unchanged'
    # Identical values AND sending metadata can use a <= 30-minute validation.
    assert (await sync.synchronize(config(), state, gateway, validator=check, now=2799))['reason'] == 'validated_recently'
    assert (await sync.synchronize(config(), state, gateway, validator=check, now=2800))['reason'] == 'identity_validated'
    assert check.await_count == 2
    assert not gateway.writes


async def check_auth_failure_same_cookie_backoff_and_changed_cookie_may_validate():
    class Rejected(Exception):
        category = 'authentication_required'
    check, gateway, state = validator(), FakeGateway([account()]), {}
    check.side_effect = Rejected('SECRET_RAW_RESPONSE')
    with _CASE.assertRaisesRegex(sync.SyncError, 'google_session_requires_attention'):
        await sync.synchronize(config(), state, gateway, validator=check, now=1000)
    assert state['auth_retry_after'] == 4600
    assert 'SECRET_RAW_RESPONSE' not in json.dumps(state)
    assert (await sync.synchronize(config(), state, gateway, validator=check, now=4599))['reason'] == 'authentication_backoff'
    assert check.await_count == 1
    gateway.cookies.return_value = cookies('NEW_AUTH')
    check.side_effect = None
    result = await sync.synchronize(config(), state, gateway, validator=check, now=2000)
    assert result['status'] == 'updated'
    assert 'auth_retry_after' not in state


async def check_identity_mismatch_never_changes_account():
    gateway, check = FakeGateway([account()]), validator()
    check.return_value = {'email': 'different@example.test', 'credits': 925}
    with _CASE.assertRaisesRegex(sync.SyncError, 'google_identity_mismatch'):
        await sync.synchronize(config(), {}, gateway, validator=check)
    assert not gateway.writes


async def check_unknown_post_outcome_is_not_retried_and_next_run_adopts_by_marker():
    gateway, state = FakeGateway(), {}
    real_write = gateway.write
    async def uncertain(token_id, payload):
        await real_write(token_id, payload)
        raise sync.SyncError('local_transport_failed', 'network')
    gateway.write = uncertain
    with _CASE.assertRaises(sync.SyncError):
        await sync.synchronize(config(), state, gateway, validator=validator(), now=1000)
    gateway.write = real_write
    assert (await sync.synchronize(config(), state, gateway, validator=validator(), now=2800))['status'] == 'unchanged'
    assert len(gateway.writes) == 1
    assert state['token_id'] == 2


def check_non_loopback_or_credential_endpoints_rejected(url):
    with _CASE.assertRaises(sync.SyncError): sync.loopback_url(url)


def check_spark_busy_uses_exact_profile_and_unknown_is_fail_closed():
    def tasks(dims, status='running'):
        return {'tasks': [{'status': status, 'dimensions': dims}], 'total_count': 1}
    assert sync.spark_busy(tasks({'video_fixed_user_id': 'fixed-profile'}), 'fixed-profile')
    assert sync.spark_busy(tasks({}), 'fixed-profile')
    assert not sync.spark_busy(tasks({'userId': 'other-profile'}), 'fixed-profile')
    assert not sync.spark_busy(tasks({'fx_capable': False}), 'fixed-profile')
    assert not sync.spark_busy(tasks({}, 'completed'), 'fixed-profile')
    with _CASE.assertRaises(sync.SyncError): sync.spark_busy({'tasks': [], 'total_count': 2}, 'fixed-profile')


def check_flow_status_checks_are_readonly_and_unknown_pending_block(tmp_path):
    path = tmp_path / 'flow.db'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE tasks(token_id INTEGER,status TEXT)')
        db.execute('CREATE TABLE request_logs(token_id INTEGER,status_code INTEGER,status_text TEXT)')
        db.execute("INSERT INTO tasks VALUES(2,'completed')")
        db.execute("INSERT INTO request_logs VALUES(2,200,'completed')")
    assert not sync.flow_busy(path, 2)
    before = path.read_bytes()
    assert not sync.flow_busy(path, 2)
    assert path.read_bytes() == before
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO tasks VALUES(2,'status_unknown')")
    assert not sync.flow_busy(path, 2)
    assert sync.flow_busy(path, None)
    assert not sync.flow_busy(path, 3)
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO request_logs VALUES(NULL,102,'started')")
    assert sync.flow_busy(path, 3)
    with _CASE.assertRaises(sync.SyncError): sync.flow_busy(tmp_path / 'missing.db', 2)
    assert not (tmp_path / 'missing.db').exists()


async def check_admin_cookie_never_sent_to_other_loopback_service():
    seen = []
    def transport(request):
        seen.append(request)
        if request.url.path == '/api/admin/login':
            return httpx.Response(200, json={'success': True, 'token': 'ADMIN_SECRET'},
                                  headers={'set-cookie': 'admin_cookie=SECRET; Path=/'})
        if request.url.path == '/api/tokens': return httpx.Response(200, json=[])
        return httpx.Response(200, json={'code': 0})
    async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
        gateway = sync.Gateway(config(), client, {'username': 'admin', 'password': 'PASSWORD'})
        await gateway.tokens()
        await gateway.request('GET', config()['adspower_base'], '/test')
    assert seen[-1].headers.get('cookie') is None
    assert seen[-1].headers.get('authorization') is None
    assert seen[1].headers['authorization'] == 'Bearer ADMIN_SECRET'


def check_private_state_atomic_permissions_and_process_lock(tmp_path):
    path = tmp_path / 'state.json'
    sync.save_private(path, {'safe': True})
    assert path.stat().st_mode & 0o777 == 0o600
    assert sync.private_json(path) == {'safe': True}
    lock = tmp_path / 'sync.lock'
    with sync.process_lock(lock):
        with _CASE.assertRaisesRegex(sync.SyncError, 'already_running'):
            with sync.process_lock(lock): pass
    path.chmod(0o644)
    with _CASE.assertRaises(sync.SyncError): sync.private_json(path)


async def check_network_failure_saves_five_minute_backoff_without_secrets(tmp_path):
    conf_path = tmp_path / 'sync.json'
    sync.save_private(conf_path, config())
    (tmp_path / 'local').mkdir()
    sync.save_private(tmp_path / 'local/credentials.json', {'username': 'admin', 'password': 'PASSWORD'})
    gateway = FakeGateway()
    gateway.profile.side_effect = sync.SyncError('local_transport_failed', 'network')
    result = await sync.run_once(conf_path, gateway_factory=lambda *_: gateway, validator=validator())
    assert result == {'status': 'error', 'reason': 'local_transport_failed'}
    state = sync.private_json(tmp_path / 'sync.state.json')
    assert state['network_retry_after'] == 1300
    assert state['network_failed_reason'] == 'local_transport_failed'
    assert state['network_failed_at'] == 1000
    gateway.profile.reset_mock()
    for now in (1000, 1001, 1299):
        with patch.object(sync.time, 'time', return_value=now):
            result = await sync.run_once(conf_path, gateway_factory=lambda *_: gateway, validator=validator())
        assert result == {'status': 'deferred', 'reason': 'network_backoff',
                          'prior_reason': 'local_transport_failed', 'retry_after': 1300}
        state = sync.private_json(tmp_path / 'sync.state.json')
        assert state['network_retry_after'] == 1300
        assert state['network_failed_at'] == 1000
        assert state['network_failed_reason'] == 'local_transport_failed'
        gateway.profile.assert_not_awaited()
    assert 'PASSWORD' not in json.dumps(state)
    gateway.profile.side_effect = lambda: copy.deepcopy(gateway.profile_value)
    gateway.rows = [account('AUTH_SECRET')]
    with patch.object(sync.time, 'time', return_value=1300):
        result = await sync.run_once(conf_path, gateway_factory=lambda *_: gateway, validator=validator())
    assert result['status'] == 'unchanged'
    gateway.profile.assert_awaited_once()
    assert not gateway.writes
    state = sync.private_json(tmp_path / 'sync.state.json')
    assert all(key not in state for key in sync.NETWORK_STATE_FIELDS)


_CASE = unittest.TestCase()


class SparkBusyTests(unittest.TestCase):
    def tasks(self, *tasks):
        return {'tasks': list(tasks), 'total_count': len(tasks)}

    def board(self, *, leases=(), waiting=()):
        return {'status': 'ok', 'board': {'leases': list(leases), 'waiting': list(waiting)}}

    def test_empty_browser_board_allows_active_frames_and_flow2api_orchestration(self):
        for status in sync.ACTIVE:
            with self.subTest(status=status):
                tasks = self.tasks(
                    {'id': 'frames', 'status': status,
                     'dimensions': {'type': 'frames', 'userId': 'fixed-profile'}},
                    {'id': 'videos', 'status': status,
                     'dimensions': {'type': 'videos', 'video_provider': 'flow2api'}},
                    {'id': 'video-chain', 'status': status,
                     'dimensions': {'type': 'video_chain', 'video_provider': 'flow2api',
                                    'video_fixed_user_id': 'fixed-profile'}})
                self.assertFalse(sync.spark_busy(tasks, 'fixed-profile', board=self.board()))
                # Callers without a browser inventory must retain the old guard.
                self.assertTrue(sync.spark_busy(tasks, 'fixed-profile'))

    def test_other_live_browser_lease_or_waiter_still_blocks(self):
        tasks = self.tasks({'id': 'cancelled', 'status': 'cancelled'})
        for board in (
                self.board(leases=[{'task_id': 'cancelled', 'user_id': 'fixed-profile'}]),
                self.board(leases=[{'task_id': 'other', 'user_id': 'other-profile'}]),
                self.board(waiting=[{'task_id': 'next', 'user_id': 'fixed-profile'}]),
                self.board(waiting=[{'task_id': 'other', 'user_id': 'other-profile'}])):
            with self.subTest(board=board):
                self.assertTrue(sync.spark_busy(tasks, 'fixed-profile', board=board))

    def test_active_cookie_login_blocks_even_before_a_browser_lease_is_reported(self):
        for marker in ({'maintenance': 'cookie_login'}, {'_cookie_login': True},
                       {'id': 'cookie_login_other'}, {'task_id': 'cookie_login_other'},
                       {'dimensions': {'type': 'auto_login'}}):
            for status in sync.ACTIVE:
                with self.subTest(marker=marker, status=status):
                    task = dict({'id': 'other', 'status': status, 'profile_id': 'other-profile'}, **marker)
                    self.assertTrue(sync.spark_busy(self.tasks(task), 'fixed-profile', board=self.board()))

    def test_finished_cookie_login_does_not_block_an_empty_browser_board(self):
        for status in sync.TERMINAL:
            with self.subTest(status=status):
                task = {'id': 'cookie_login_finished', 'status': status,
                        'maintenance': 'cookie_login', 'profile_id': 'fixed-profile'}
                self.assertFalse(sync.spark_busy(self.tasks(task), 'fixed-profile', board=self.board()))

    def test_entire_task_inventory_is_validated_before_a_busy_result(self):
        first_tasks = (
            {'status': 'running', 'dimensions': {'userId': 'fixed-profile'}},
            {'id': 'cookie_login_other', 'status': 'running'},
        )
        for first in first_tasks:
            for board in (None, self.board(), self.board(leases=[{'task_id': 'other'}])):
                with self.subTest(first=first, board=board):
                    tasks = self.tasks(first, {'status': 'new_unknown_status'})
                    with self.assertRaisesRegex(sync.SyncError, 'spark_task_state_unknown'):
                        sync.spark_busy(tasks, 'fixed-profile', board=board)
        with self.assertRaisesRegex(sync.SyncError, 'spark_inventory_incomplete'):
            sync.spark_busy({'tasks': [], 'total_count': 1}, 'fixed-profile', board=self.board())

    def test_invalid_browser_inventory_is_rejected_even_with_a_busy_login_task(self):
        task = {'id': 'cookie_login_other', 'status': 'running'}
        for board in ({}, {'status': 'error', 'board': {'leases': [], 'waiting': []}},
                      {'status': 'ok', 'board': {'leases': []}},
                      {'status': 'ok', 'board': {'leases': [], 'waiting': None}}):
            with self.subTest(board=board), self.assertRaisesRegex(sync.SyncError, 'spark_lease_inventory_invalid'):
                sync.spark_busy(self.tasks(task), 'fixed-profile', board=board)


class GatewayBusyTests(unittest.IsolatedAsyncioTestCase):
    async def test_cookie_write_delegates_maintenance_in_a_header_without_changing_the_account_payload(self):
        gateway = sync.Gateway(config(), None, {})
        gateway.authorization = {'Authorization': 'Bearer SYNTHETIC_ADMIN'}
        gateway.maintenance_capability = 'c' * 64
        gateway.request = AsyncMock(return_value={'success': True})
        payload = {'auto_enable_on_update': False, 'google_cookies': 'SYNTHETIC_COOKIES'}
        await gateway.write(2, payload)
        request = gateway.request.await_args
        self.assertEqual(request.args[0], 'PUT')
        self.assertEqual(request.kwargs['body'], payload)
        self.assertEqual(request.kwargs['headers'], {
            'Authorization': 'Bearer SYNTHETIC_ADMIN', 'X-Flow-Maintenance-Capability': 'c' * 64})

    async def test_malformed_maintenance_capability_never_reaches_account_write(self):
        gateway = sync.Gateway(config(), None, {})
        gateway.maintenance_capability = 'PRIVATE'
        gateway.request = AsyncMock(return_value={'success': True})
        with self.assertRaisesRegex(sync.SyncError, 'busy_state_unknown'):
            await gateway.write(2, {'auto_enable_on_update': False})
        gateway.request.assert_not_awaited()

    async def busy(self, directory, *, tasks, board, active_token=None):
        root = Path(directory)
        path = root / 'flow.db'
        with sqlite3.connect(path) as db:
            db.execute('CREATE TABLE tasks(token_id INTEGER,status TEXT)')
            db.execute('CREATE TABLE request_logs(token_id INTEGER,status_code INTEGER,status_text TEXT)')
            if active_token is not None:
                db.execute('INSERT INTO tasks VALUES(?,?)', (active_token, 'processing'))
                db.execute('INSERT INTO request_logs VALUES(?,?,?)', (active_token, 102, 'video_polling'))
        before = path.read_bytes()
        spark_config = root / 'spark.json'
        sync.save_private(spark_config, {})
        conf = config(spark_config_path=str(spark_config), flow_db_path=str(path))
        seen = []

        def transport(request):
            seen.append(request)
            if request.url.path == '/api/tasks':
                self.assertEqual(request.url.params.get('limit'), '0')
                return httpx.Response(200, json=tasks)
            if request.url.path == '/api/google-fx/board':
                return httpx.Response(200, json=board)
            raise AssertionError('Unexpected offline request route')

        async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
            gateway = sync.Gateway(conf, client, {})
            result = await gateway.busy(2)
        self.assertEqual([request.url.path for request in seen], ['/api/tasks', '/api/google-fx/board'])
        self.assertTrue(all(request.headers.get('authorization') is None for request in seen))
        self.assertEqual(path.read_bytes(), before)
        return result

    async def test_empty_board_and_another_flow_account_allow_target_cookie_recovery(self):
        tasks = {'tasks': [
            {'id': 'frames', 'status': 'running', 'dimensions': {'type': 'frames', 'userId': 'fixed-profile'}},
            {'id': 'video', 'status': 'running', 'dimensions': {'type': 'videos', 'video_provider': 'flow2api'}},
        ], 'total_count': 2}
        board = {'status': 'ok', 'board': {'leases': [], 'waiting': []}}
        for active_token, expected in ((None, (False, False)), (3, (False, False)), (2, (False, True))):
            with self.subTest(active_token=active_token), tempfile.TemporaryDirectory() as directory:
                self.assertEqual(await self.busy(directory, tasks=tasks, board=board, active_token=active_token), expected)

    async def test_cookie_login_and_browser_board_each_block_with_an_idle_target_flow_account(self):
        empty = {'status': 'ok', 'board': {'leases': [], 'waiting': []}}
        cases = (
            ({'tasks': [{'id': 'cookie_login_other', 'status': 'queued'}], 'total_count': 1}, empty),
            ({'tasks': [], 'total_count': 0},
             {'status': 'ok', 'board': {'leases': [{'task_id': 'other'}], 'waiting': []}}),
            ({'tasks': [], 'total_count': 0},
             {'status': 'ok', 'board': {'leases': [], 'waiting': [{'task_id': 'other'}]}}),
        )
        for tasks, board in cases:
            with self.subTest(tasks=tasks, board=board), tempfile.TemporaryDirectory() as directory:
                self.assertEqual(await self.busy(directory, tasks=tasks, board=board), (True, False))


class SyncCookieTests(unittest.IsolatedAsyncioTestCase):
    async def test_same_cookie_renews_expired_unknown_and_soon_expiring_credentials_only(self):
        for old_expiry in (None, '', 'invalid', 1300, expiry(999), expiry(1200), expiry(1300),
                           '1970-01-01T00:20:00', '1970-01-01T08:20:00+08:00'):
            with self.subTest(old_expiry=old_expiry):
                row = account('AUTH_SECRET', at_expires=old_expiry,
                              image_enabled=True, auto_refresh_enabled=False,
                              ban_reason='manual-test', image_concurrency=2)
                gateway, state, check = FakeGateway([row]), {}, validator()
                gateway.renewed_expiry = expiry(4300)
                result = await sync.synchronize(config(), state, gateway, validator=check, now=1000)
                self.assertEqual(result, {'status': 'updated', 'reason': 'sync_complete', 'token_id': 2})
                self.assertEqual(gateway.writes, [(2, {'auto_enable_on_update': False})])
                self.assertEqual({k: v for k, v in gateway.rows[0].items() if k != 'at_expires'},
                                 {k: v for k, v in row.items() if k != 'at_expires'})
                self.assertEqual(state['synced_cookie_hash'], sync.auth_hash(cookies()))
                self.assertEqual(gateway.profile.await_count, 2)
                self.assertEqual(gateway.busy.await_count, 2)
                check.assert_awaited_once_with(cookies(), row['email'], row['proxy_url'])

    async def test_same_cookie_with_more_than_five_minutes_remains_unchanged(self):
        gateway = FakeGateway([account('AUTH_SECRET', at_expires=expiry(1301))])
        result = await sync.synchronize(config(), {}, gateway, validator=validator(), now=1000)
        self.assertEqual(result['reason'], 'identity_validated')
        self.assertEqual(gateway.writes, [])

    async def test_same_cookie_expiry_refresh_can_use_recent_identity_validation(self):
        gateway, state, check = FakeGateway([account('AUTH_SECRET')]), {}, validator()
        await sync.synchronize(config(), state, gateway, validator=check, now=1000)
        gateway.rows[0]['at_expires'] = expiry(1001)
        gateway.renewed_expiry = expiry(4300)
        result = await sync.synchronize(config(), state, gateway, validator=check, now=1001)
        self.assertEqual(result['status'], 'updated')
        self.assertEqual(check.await_count, 1)
        self.assertEqual(gateway.writes, [(2, {'auto_enable_on_update': False})])

    async def test_expiry_refresh_busy_checks_and_identity_failure_prevent_write(self):
        for activity in ([(True, False)], [(False, True)], [(False, False), (True, False)],
                         [(False, False), (False, True)]):
            with self.subTest(activity=activity):
                gateway = FakeGateway([account('AUTH_SECRET', at_expires=expiry(999))])
                gateway.busy.side_effect = activity
                result = await sync.synchronize(config(), {}, gateway, validator=validator(), now=1000)
                self.assertEqual(result['reason'], 'generation_busy')
                self.assertEqual(gateway.writes, [])
        gateway, check = FakeGateway([account('AUTH_SECRET', at_expires=expiry(999))]), validator()
        check.return_value['email'] = 'different@example.test'
        with self.assertRaisesRegex(sync.SyncError, 'google_identity_mismatch'):
            await sync.synchronize(config(), {}, gateway, validator=check, now=1000)
        self.assertEqual(gateway.writes, [])

    async def test_expiry_refresh_rechecks_session_proxy_flags_binding_and_deadline_before_write(self):
        changes = {'google_cookies': json.dumps(cookies('changed')), 'st': 'changed-session',
                   'proxy_url': 'http://changed.test:3128', 'captcha_proxy_url': 'http://changed.test:3128',
                   'is_active': True, 'auto_refresh_enabled': True, 'remark': 'changed-binding',
                   'at_expires': expiry(4300)}
        for field, value in changes.items():
            with self.subTest(field=field):
                gateway = FakeGateway([account('AUTH_SECRET', at_expires=expiry(999),
                                               auto_refresh_enabled=False)])
                async def changed(*_):
                    gateway.rows[0][field] = value
                    return {'email': 'fixed@example.test', 'credits': 100}
                with self.assertRaises(sync.SyncError):
                    await sync.synchronize(config(), {}, gateway, validator=AsyncMock(side_effect=changed), now=1000)
                self.assertEqual(gateway.writes, [])

    async def test_expiry_refresh_requires_a_confirmed_new_unexpired_deadline(self):
        for new_expiry in (None, 'invalid', expiry(900), expiry(1000), expiry(1100), expiry(1200)):
            with self.subTest(new_expiry=new_expiry):
                gateway, state = FakeGateway([account('AUTH_SECRET', at_expires=expiry(1200))]), {}
                gateway.renewed_expiry = new_expiry
                with self.assertRaisesRegex(sync.SyncError, 'account_write_unconfirmed'):
                    await sync.synchronize(config(), state, gateway, validator=validator(), now=1000)
                self.assertNotIn('synced_at', state)
                self.assertNotIn('synced_cookie_hash', state)
                self.assertEqual(len(gateway.writes), 1)

    async def test_deadline_window_and_write_confirmation_account_for_elapsed_validation_time(self):
        gateway = FakeGateway([account('AUTH_SECRET', at_expires=expiry(1301))])
        gateway.renewed_expiry = expiry(4300)
        with patch.object(sync.time, 'monotonic', side_effect=[100, 102, 103]):
            result = await sync.synchronize(config(), {}, gateway, validator=validator(), now=1000)
        self.assertEqual(result['status'], 'updated')
        self.assertEqual(gateway.writes, [(2, {'auto_enable_on_update': False})])

        gateway = FakeGateway([account('AUTH_SECRET', at_expires=expiry(999))])
        gateway.renewed_expiry = expiry(1002)
        with patch.object(sync.time, 'monotonic', side_effect=[100, 101, 103]):
            with self.assertRaisesRegex(sync.SyncError, 'account_write_unconfirmed'):
                await sync.synchronize(config(), {}, gateway, validator=validator(), now=1000)

    async def test_expiry_refresh_verifies_preserved_session_proxy_binding_and_switches_after_write(self):
        changes = {'google_cookies': json.dumps(cookies('changed')), 'st': 'changed-session',
                   'proxy_url': 'http://changed.test:3128', 'captcha_proxy_url': 'http://changed.test:3128',
                   'is_active': True, 'video_enabled': True, 'auto_refresh_enabled': True,
                   'email': 'different@example.test', 'ban_reason': 'changed'}
        for field, value in changes.items():
            with self.subTest(field=field):
                gateway = FakeGateway([account('AUTH_SECRET', at_expires=expiry(999),
                                               auto_refresh_enabled=False, ban_reason='manual-test')])
                real_write = gateway.write
                async def changed(token_id, payload):
                    await real_write(token_id, payload)
                    gateway.rows[0][field] = value
                gateway.write = changed
                with self.assertRaises(sync.SyncError):
                    await sync.synchronize(config(), {}, gateway, validator=validator(), now=1000)
                self.assertEqual(len(gateway.writes), 1)

    async def test_expiry_refresh_unknown_write_outcome_is_never_retried(self):
        gateway = FakeGateway([account('AUTH_SECRET', at_expires=expiry(999))])
        gateway.write = AsyncMock(side_effect=sync.SyncError('local_transport_failed', 'network'))
        with self.assertRaisesRegex(sync.SyncError, 'local_transport_failed'):
            await sync.synchronize(config(), {}, gateway, validator=validator(), now=1000)
        gateway.write.assert_awaited_once_with(2, {'auto_enable_on_update': False})

    async def test_ended_unknown_operation_allows_cookie_recovery_but_live_polling_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'flow.db'
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE tasks(token_id INTEGER,status TEXT)')
                db.execute('CREATE TABLE request_logs(token_id INTEGER,status_code INTEGER,status_text TEXT)')
                db.execute("INSERT INTO tasks VALUES(2,'status_unknown')")
                db.execute("INSERT INTO request_logs VALUES(2,502,'video_status_unknown')")
            before = path.read_bytes()
            gateway = FakeGateway([account()])
            gateway.busy.side_effect = lambda token_id: (False, sync.flow_busy(path, token_id))
            result = await sync.synchronize(config(), {}, gateway, validator=validator(), now=1000)
            self.assertEqual(result['status'], 'updated')
            self.assertEqual(set(gateway.writes[0][1]), {'google_cookies', 'auto_enable_on_update'})
            self.assertEqual(path.read_bytes(), before)
            with sqlite3.connect(path) as db:
                db.execute("INSERT INTO request_logs VALUES(2,102,'video_polling')")
            gateway = FakeGateway([account()])
            gateway.busy.side_effect = lambda token_id: (False, sync.flow_busy(path, token_id))
            result = await sync.synchronize(config(), {}, gateway, validator=validator(), now=1000)
            self.assertEqual(result['reason'], 'generation_busy')
            self.assertEqual(gateway.writes, [])

    async def test_cancelled_task_with_live_lease_still_defers(self):
        with tempfile.TemporaryDirectory() as directory:
            spark_config = Path(directory) / 'server_config.json'
            sync.save_private(spark_config, {})
            conf = config(spark_config_path=str(spark_config))
            gateway = sync.Gateway(conf, None, {})
            gateway.request = AsyncMock(side_effect=[
                {'tasks': [{'status': 'cancelled', 'dimensions': {'userId': 'fixed-profile'}}], 'total_count': 1},
                {'status': 'ok', 'board': {'leases': [{'user_id': 'fixed-profile'}], 'waiting': []}},
            ])
            with patch.object(sync, 'flow_busy', return_value=False):
                self.assertEqual(await gateway.busy(2), (True, False))
            self.assertEqual(gateway.request.await_count, 2)
            self.assertIsNone(gateway.request.await_args.kwargs['headers'])

    def test_unknown_lease_schema_is_fail_closed(self):
        for board in ({}, {'status': 'ok', 'board': {}}, {'status': 'ok', 'board': {'leases': []}}):
            with self.subTest(board=board), self.assertRaises(sync.SyncError):
                sync.spark_board_busy(board)

    async def test_rts_and_next_auth_only_changes_are_not_skipped(self):
        for name in ('__Secure-1PSIDRTS', '__Secure-3PSIDRTS', '__Secure-next-auth.session-token'):
            with self.subTest(name=name):
                old = cookies() + [dict(cookies()[0], name=name, value='old')]
                row = account()
                row['google_cookies'] = json.dumps(old)
                gateway = FakeGateway([row])
                new = copy.deepcopy(old)
                new[-1]['value'] = 'new'
                gateway.cookies.return_value = new
                result = await sync.synchronize(config(), {}, gateway, validator=validator(), now=1000)
                self.assertEqual(result['status'], 'updated')
                self.assertEqual(len(gateway.writes), 1)

    async def test_expiry_only_renewal_updates_cookie_storage(self):
        gateway, state = FakeGateway([account('AUTH_SECRET')]), {}
        refreshed = cookies()
        refreshed[0].update(expires=9999999, httpOnly=True, sameSite='None')
        gateway.cookies.return_value = refreshed
        result = await sync.synchronize(config(), state, gateway, validator=validator(), now=1000)
        self.assertEqual(result['status'], 'updated')
        self.assertEqual(json.loads(gateway.writes[0][1]['google_cookies'])[0]['expires'], 9999999)

    async def test_create_flags_and_original_account_untouched(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                await check_create_is_independent_and_only_uses_original_profile_proxy(enabled)

    async def test_update_preserves_all_flags(self):
        await check_update_only_cookie_and_no_auto_enable()

    async def test_binding_fail_closed(self):
        for changed in ('remark', 'email', 'token_id', 'proxy'):
            with self.subTest(changed=changed):
                await check_existing_binding_or_proxy_mismatch_never_reads_cookies_or_writes(changed)
        await check_profile_proxy_drift_stops_before_cookie_read()

    async def test_busy_before_creation_and_update(self):
        for existing in (False, True):
            for busy in ((True, False), (False, True)):
                with self.subTest(existing=existing, busy=busy):
                    await check_busy_defers_creation_and_updates(existing, busy)
        await check_final_busy_check_prevents_racing_write()

    async def test_periodic_validation_without_rewriting_unchanged_auth(self):
        await check_unchanged_cookie_revalidates_every_thirty_minutes()

    async def test_one_hour_auth_backoff(self):
        await check_auth_failure_same_cookie_backoff_and_changed_cookie_may_validate()

    async def test_real_identity_mismatch_is_rejected(self):
        await check_identity_mismatch_never_changes_account()

    async def test_unknown_creation_outcome_never_duplicates(self):
        await check_unknown_post_outcome_is_not_retried_and_next_run_adopts_by_marker()

    async def test_loopback_admin_auth_is_not_sent_to_ads(self):
        await check_admin_cookie_never_sent_to_other_loopback_service()

    async def test_network_backoff_is_five_minutes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            with patch.object(sync, 'ROOT', path), patch.object(sync.time, 'time', return_value=1000):
                await check_network_failure_saves_five_minute_backoff_without_secrets(path)

    async def test_network_backoff_reports_only_a_trusted_token_binding(self):
        conf = config()
        bound_hash = sync.digest({k: conf[k] for k in
                                 ('profile_id', 'expected_email', 'adspower_base', 'flow_base')})
        for configured_id, state_id, known_binding, expected_id in (
                (2, None, False, 2), (2, 2, True, 2),
                (None, 2, True, 2), (None, 2, False, None),
                (None, True, True, None),
                (None, 'PRIVATE', True, None)):
            with self.subTest(configured_id=configured_id, state_id=state_id,
                              known_binding=known_binding):
                current = dict(conf, token_id=configured_id)
                state = {'network_retry_after': 1300, 'token_id': state_id,
                         'network_failed_reason': 'identity_validation_unavailable'}
                if known_binding:
                    state['binding_hash'] = bound_hash
                gateway = FakeGateway()
                result = await sync.synchronize(current, state, gateway,
                                                validator=validator(), now=1000)
                self.assertEqual(result.get('token_id'), expected_id)
                self.assertEqual(result['prior_reason'], 'identity_validation_unavailable')
                self.assertEqual(result['retry_after'], 1300)
                gateway.profile.assert_not_awaited()
                self.assertFalse(gateway.writes)

    async def test_network_backoff_cannot_hide_a_changed_token_binding(self):
        state = {'network_retry_after': 1300, 'token_id': 3,
                 'network_failed_reason': 'local_transport_failed', 'network_failed_at': 1000}
        gateway = FakeGateway()
        with self.assertRaisesRegex(sync.SyncError, 'token_binding_changed'):
            await sync.synchronize(dict(config(), token_id=2), state, gateway,
                                   validator=validator(), now=1001)
        self.assertEqual(state['network_retry_after'], 1300)
        self.assertEqual(state['network_failed_reason'], 'local_transport_failed')
        gateway.profile.assert_not_awaited()
        self.assertFalse(gateway.writes)

    async def test_network_backoff_omits_unsafe_diagnostics(self):
        for prior_reason in ('PRIVATE', ['PRIVATE'], None):
            with self.subTest(prior_reason=prior_reason):
                result = await sync.synchronize(config(),
                    {'network_retry_after': float('inf'), 'network_failed_reason': prior_reason},
                    FakeGateway(), validator=validator(), now=1000)
                self.assertEqual(result, {'status': 'deferred', 'reason': 'network_backoff'})

    def test_network_failure_metadata_contains_only_whitelisted_codes(self):
        for reason in (*sync.NETWORK_FAILURE_REASONS, 'PRIVATE', ['PRIVATE']):
            with self.subTest(reason=reason):
                state = {}
                sync.record_network_failure(state, reason, 1000)
                expected = reason if isinstance(reason, str) and reason in sync.NETWORK_FAILURE_REASONS else 'sync_failed_safe'
                self.assertEqual(state, {'network_retry_after': 1300,
                                        'network_failed_reason': expected, 'network_failed_at': 1000})
                self.assertNotIn('PRIVATE', json.dumps(state))

    def test_endpoints_must_be_loopback(self):
        for url in ('http://example.com:80', 'http://127.0.0.1:80/path',
                    'http://u:p@127.0.0.1:80', 'http://127.0.0.1:80?key=x', 'file:///tmp/test'):
            with self.subTest(url=url):
                check_non_loopback_or_credential_endpoints_rejected(url)

    def test_busy_inventory_is_complete_and_profile_scoped(self):
        check_spark_busy_uses_exact_profile_and_unknown_is_fail_closed()

    def test_database_status_checks_cannot_mutate(self):
        with tempfile.TemporaryDirectory() as directory:
            check_flow_status_checks_are_readonly_and_unknown_pending_block(Path(directory))

    def test_private_files_and_exclusive_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            check_private_state_atomic_permissions_and_process_lock(Path(directory))


if __name__ == '__main__':
    unittest.main()
