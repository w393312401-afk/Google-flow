"""Offline external audit coverage; no real account, browser or network calls."""
import contextlib
import asyncio
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import AsyncMock, Mock, patch

import httpx


ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'local' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sync = load('audit_test_sync', 'sync_adspower_cookies.py')
pool = load('audit_test_pool', 'sync_adspower_cookie_pool.py')
host = load('audit_test_host', 'sync_adspower_login_host.py')


class AdsPowerAuditTests(unittest.IsolatedAsyncioTestCase):
    async def test_pool_cancellation_is_logged_without_becoming_a_normal_result(self):
        with patch.object(pool, '_audit_pool') as recorder, \
             patch.object(pool, '_run_pool', AsyncMock(side_effect=asyncio.CancelledError)):
            with self.assertRaises(asyncio.CancelledError):
                await pool.run_pool('/unread/test/manifest')
        self.assertEqual(recorder.call_args_list[0].args, ('started', 'pool_sync_requested'))
        self.assertEqual(recorder.call_args_list[-1].args, ('skipped', 'pool_interrupted'))

    async def test_backoff_and_busy_events_keep_fixed_account_without_changing_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local = root / 'local'
            local.mkdir()
            path = local / 'one.json'
            config = sync.validate_config({'profile_id': 'one', 'expected_email': 'owner@example.test',
                'token_id': 2, 'adspower_base': 'http://127.0.0.1:50325', 'flow_base': 'http://127.0.0.1:38000'})
            sync.save_private(path, config)
            sync.save_private(local / 'credentials.json', {'username': 'admin', 'password': 'PASSWORD_SECRET'})
            for reason, stage in [('generation_busy', 'preflight'), ('network_backoff', 'network'),
                                  ('authentication_backoff', 'auth')]:
                result = {'status': 'deferred', 'reason': reason, 'token_id': 2}
                recorder = Mock()
                gateway = types.SimpleNamespace()
                if reason == 'generation_busy':
                    gateway._audit_cookie_source = 'cdp'
                with patch.object(sync, 'ROOT', root), patch.object(sync, '_audit', recorder), \
                     patch.object(sync, 'synchronize', AsyncMock(return_value=result)):
                    actual = await sync.run_once(path, gateway_factory=lambda *_: gateway)
                self.assertEqual(actual, result)
                self.assertEqual(recorder.call_args_list[0].args[1:3], ('cookie_sync', 'started'))
                last = next(call for call in recorder.call_args_list if call.args[1:3] == ('cookie_sync', 'deferred'))
                self.assertEqual(last.args[1:3], ('cookie_sync', 'deferred'))
                self.assertEqual(last.kwargs['stage'], stage)
                self.assertEqual(last.args[0]['token_id'], 2)
                sources = [call for call in recorder.call_args_list if call.kwargs.get('stage') == 'source']
                if reason == 'generation_busy':
                    self.assertEqual(len(sources), 1)
                    self.assertEqual(sources[0].kwargs['reason'], 'cookie_source_observed')
                    self.assertEqual(sources[0].kwargs['details'], {'cookie_source': 'live'})
                else:
                    self.assertEqual(sources, [])
                self.assertNotIn('PASSWORD_SECRET', repr(recorder.call_args_list))

    async def test_source_header_is_copied_and_only_sent_to_flow(self):
        seen = []

        def transport(request):
            seen.append(request)
            return httpx.Response(200, json={'code': 0})

        config = {'flow_base': 'http://127.0.0.1:38000', 'adspower_base': 'http://127.0.0.1:50325'}
        original = {'Authorization': 'Bearer PRIVATE'}
        async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
            gateway = sync.Gateway(config, client, {})
            await gateway.request('GET', config['flow_base'], '/test', headers=original)
            await gateway.request('GET', config['adspower_base'], '/test')
        self.assertEqual(original, {'Authorization': 'Bearer PRIVATE'})
        self.assertEqual(seen[0].headers['X-Account-Operation-Source'], 'cookie_sync')
        self.assertEqual(seen[0].headers['Authorization'], 'Bearer PRIVATE')
        self.assertNotIn('X-Account-Operation-Source', seen[1].headers)
        self.assertNotIn('Authorization', seen[1].headers)

    async def test_login_proof_hashes_are_never_forwarded_to_audit(self):
        result = {'status': 'ok', 'reason': 'login_verified', 'token_id': 2, 'credits': 50,
                  'verified_cookie_hash': 'COOKIE_HASH_SECRET', 'verified_proxy_hash': 'PROXY_HASH_SECRET'}
        with patch.object(sync, '_audit') as recorder:
            sync._audit_result({'token_id': 2}, result, operation='auto_login')
        self.assertNotIn('HASH_SECRET', repr(recorder.call_args_list))
        self.assertEqual(recorder.call_args.kwargs['result'], {'token_id': 2, 'credits': 50})

    async def test_binding_failure_reports_the_state_recheck_after_successful_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'one.json'
            state_path = root / 'one.state.json'
            config = sync.validate_config({'profile_id': 'one', 'expected_email': 'owner@example.test',
                'token_id': 2, 'adspower_base': 'http://127.0.0.1:50325', 'flow_base': 'http://127.0.0.1:38000'})
            proxy = 'http://proxy.test:80'
            state = {'token_id': 2, 'proxy_hash': sync.digest(sync.proxy_identity(proxy))}
            sync.save_private(state_path, state)
            token = {'id': 2, 'email': 'owner@example.test', 'login_account': 'owner@example.test',
                     'remark': 'adspower-sync:one', 'proxy_url': proxy, 'captcha_proxy_url': proxy,
                     'google_cookies': 'COOKIE_SECRET', 'st': 'ST_SECRET'}
            profile = {'source': 'cdp', 'ws': 'ws://127.0.0.1:9222/devtools/browser/test', 'proxy': proxy}
            gateway = types.SimpleNamespace(profile=AsyncMock(return_value=profile),
                                             tokens=AsyncMock(return_value=[token]))
            board = {'leases': [], 'waiting': []}

            @contextlib.contextmanager
            def slot(*_args, **_kwargs):
                board['leases'] = [{'task_id': 'own', 'kind': 'auto_login', 'user_id': 'one', 'state': 'running'}]
                try:
                    yield
                finally:
                    board['leases'] = []

            async def worker(_payload, _check):
                sync.save_private(state_path, dict(state, changed=True))
                return {'ok': True, 'code': 'not_needed'}

            presence = lambda: {'one': {'user_id': 'one', 'email': 'owner@example.test',
                'has_password': True, 'auto_login_blocked': False}}
            recorder = Mock()
            with patch.object(host, '_audit_host', recorder), \
                 patch.object(host, '_configured', return_value=(path, config)), \
                 patch.object(sync, 'flow_busy', return_value=False):
                with self.assertRaises(host.LoginError) as caught:
                    await host._login_reserved(dict(config), path, config, state, sync,
                        types.SimpleNamespace(_read_private=sync.private_json), gateway, slot,
                        lambda: {'queue': {'mode': 'accepting'}, 'board': board, 'tasks': []},
                        worker, None, root, presence, AsyncMock(), 'own', False)
            self.assertEqual(caught.exception.code, 'login_binding_mismatch')
            self.assertEqual(caught.exception.audit_stage, 'state_recheck')
            self.assertIn('login_already_authenticated', repr(recorder.call_args_list))
            self.assertNotIn('COOKIE_SECRET', repr(recorder.call_args_list))
            self.assertNotIn('ST_SECRET', repr(recorder.call_args_list))


if __name__ == '__main__':
    unittest.main()
