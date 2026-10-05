"""Offline Cookie sync compatibility with registered Flow2API exit rotation."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch


PATH = Path(__file__).resolve().parents[1] / 'local/sync_adspower_cookies.py'
SPEC = importlib.util.spec_from_file_location('sync_exit_rotation', PATH)
sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync)

SOURCE = 'http://source-user:source-password@source.example.test:3128'
TARGET = 'http://rotate%40user:rotate%3Apassword@target.example.test:8080'


def cookies(value):
    return [{'name': 'SID', 'value': value, 'domain': '.google.com', 'path': '/', 'secure': True}]


class SyncExitRotationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.patch = patch.object(sync, 'ROOT', self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.config = sync.validate_config(dict(
            profile_id='fixed-profile', expected_email='fixed@example.test', token_id=2,
            adspower_base='http://127.0.0.1:50325', flow_base='http://127.0.0.1:38000'))
        self.row = dict(id=2, email='fixed@example.test', login_account='fixed@example.test',
                        remark='adspower-sync:fixed-profile', proxy_url=TARGET, captcha_proxy_url=TARGET,
                        google_cookies=json.dumps(cookies('old-cookie')), is_active=True,
                        image_enabled=False, video_enabled=True, image_concurrency=1,
                        video_concurrency=2, auto_refresh_enabled=False)
        self.row['at_expires'] = '2099-01-01T00:00:00Z'
        self.profile = dict(source='cdp', ws='ws://127.0.0.1:1234/devtools/browser/fixed', proxy=SOURCE)
        self.state = {'proxy_hash': sync.digest(sync.proxy_identity(SOURCE)), 'token_id': 2}
        self.policy = {'enabled': True, 'token_ids': [2], 'threshold': 5,
                       'pool_path': str(self.root / 'proxy-pool.json')}
        self.rotation_state = {'version': 1, 'accounts': {'2': {'count': 0, 'current_proxy_id': 'exit-2'}}}
        self.pool = {'proxies': {'exit-2': {'host': 'target.example.test', 'port': 8080,
                                         'proxy_type': 'http', 'user': 'rotate@user',
                                         'password': 'rotate:password', 'disabled': False}}}
        self.save_registration()
        self.gateway = sync.Gateway(self.config, None, {})
        self.gateway.profile = AsyncMock(side_effect=lambda: copy.deepcopy(self.profile))
        self.gateway.tokens = AsyncMock(side_effect=lambda: [copy.deepcopy(self.row)])
        self.gateway.cookies = AsyncMock(return_value=cookies('new-cookie'))
        self.gateway.busy = AsyncMock(return_value=(False, False))
        self.validator = AsyncMock(return_value={'email': 'fixed@example.test', 'credits': 100})

        async def write(token_id, payload):
            self.assertEqual(token_id, 2)
            self.assertEqual(set(payload), {'google_cookies', 'auto_enable_on_update'})
            self.row['google_cookies'] = payload['google_cookies']
        self.gateway.write = AsyncMock(side_effect=write)

    def save_registration(self):
        sync.save_private(self.root / 'local/exit-ip-rotation.json', self.policy)
        sync.save_private(self.root / 'local/exit-ip-rotation.state.json', self.rotation_state)
        sync.save_private(self.root / 'proxy-pool.json', self.pool)

    async def run_sync(self, now=1000):
        return await sync.synchronize(self.config, self.state, self.gateway,
                                      validator=self.validator, now=now)

    async def assert_rejected(self, reason='account_proxy_mismatch'):
        with self.assertRaisesRegex(sync.SyncError, reason):
            await self.run_sync()
        self.gateway.cookies.assert_not_awaited()
        self.validator.assert_not_awaited()
        self.gateway.write.assert_not_awaited()

    async def test_registered_route_validates_via_target_and_preserves_account_settings(self):
        original = copy.deepcopy(self.row)
        self.assertEqual((await self.run_sync())['status'], 'updated')
        self.validator.assert_awaited_once_with(cookies('new-cookie'), 'fixed@example.test', TARGET)
        self.assertEqual({k: v for k, v in self.row.items() if k != 'google_cookies'},
                         {k: v for k, v in original.items() if k != 'google_cookies'})
        self.assertEqual(self.state['proxy_hash'], sync.digest(sync.proxy_identity(SOURCE)))
        output = json.dumps(self.state)
        for secret in ('rotate@user', 'rotate:password', 'source-password', 'new-cookie'):
            self.assertNotIn(secret, output)

    async def test_missing_or_disabled_policy_rejects_divergent_routes(self):
        for enabled in (False, 'true', 1, None):
            with self.subTest(enabled=enabled):
                self.policy['enabled'] = enabled
                self.save_registration()
                await self.assert_rejected()
        (self.root / 'local/exit-ip-rotation.json').unlink()
        await self.assert_rejected()

    async def test_token_must_be_explicitly_registered_in_policy_and_state(self):
        for token_ids in ([3], [], ['2'], [True], None):
            with self.subTest(token_ids=token_ids):
                self.policy['token_ids'] = token_ids
                self.save_registration()
                await self.assert_rejected()
        self.policy['token_ids'] = [2]
        self.rotation_state['accounts'] = {'3': {'current_proxy_id': 'exit-2'}}
        self.save_registration()
        await self.assert_rejected()
        self.rotation_state['accounts'] = {'2': {'current_proxy_id': 'exit-2', 'token_id': 3}}
        self.save_registration()
        await self.assert_rejected()

    async def test_state_version_current_id_and_enabled_pool_entry_are_required(self):
        for field, value in (('version', 2), ('version', True), ('accounts', {})):
            with self.subTest(field=field, value=value):
                initial = copy.deepcopy(self.rotation_state)
                self.rotation_state[field] = value
                self.save_registration()
                await self.assert_rejected()
                self.rotation_state = initial
        for proxy_id in ('missing', '', None):
            with self.subTest(proxy_id=proxy_id):
                self.rotation_state['accounts']['2']['current_proxy_id'] = proxy_id
                self.save_registration()
                await self.assert_rejected()
        self.rotation_state['accounts']['2']['current_proxy_id'] = 'exit-2'
        self.pool['proxies']['exit-2']['disabled'] = True
        self.save_registration()
        await self.assert_rejected()

    async def test_request_and_captcha_routes_must_both_match_registered_exit(self):
        for field, value in (('captcha_proxy_url', SOURCE), ('proxy_url', SOURCE),
                             ('proxy_url', 'http://other.example.test:8080')):
            with self.subTest(field=field):
                original = copy.deepcopy(self.row)
                self.row[field] = value
                await self.assert_rejected()
                self.row = original
        self.row['proxy_url'] = self.row['captcha_proxy_url'] = 'http://other.example.test:8080'
        await self.assert_rejected()

    async def test_source_proxy_hash_and_account_binding_remain_strict(self):
        self.profile['proxy'] = 'http://changed-source.example.test:3128'
        await self.assert_rejected('profile_proxy_changed')
        self.profile['proxy'] = SOURCE
        self.row['remark'] = 'adspower-sync:other-profile'
        await self.assert_rejected('account_binding_mismatch')

    async def test_route_change_requires_fresh_validation_for_same_cookie(self):
        self.row['google_cookies'] = json.dumps(cookies('new-cookie'))
        self.row['proxy_url'] = self.row['captcha_proxy_url'] = SOURCE
        self.assertEqual((await self.run_sync())['reason'], 'identity_validated')
        self.row['proxy_url'] = self.row['captcha_proxy_url'] = TARGET
        self.assertEqual((await self.run_sync(now=1001))['reason'], 'identity_validated')
        self.assertEqual(self.validator.await_count, 2)
        self.assertEqual(self.validator.await_args.args[2], TARGET)
        self.assertEqual((await self.run_sync(now=1002))['reason'], 'validated_recently')
        self.assertEqual(self.validator.await_count, 2)

    async def test_authentication_backoff_applies_only_to_the_failed_route(self):
        self.row['proxy_url'] = self.row['captcha_proxy_url'] = SOURCE
        self.validator.side_effect = sync.SyncError('google_identity_mismatch', 'auth')
        with self.assertRaisesRegex(sync.SyncError, 'google_identity_mismatch'):
            await self.run_sync()
        self.assertEqual((await self.run_sync(now=1001))['reason'], 'authentication_backoff')
        self.assertEqual(self.validator.await_count, 1)
        self.row['proxy_url'] = self.row['captcha_proxy_url'] = TARGET
        self.validator.side_effect = None
        self.assertEqual((await self.run_sync(now=1002))['status'], 'updated')
        self.assertEqual(self.validator.await_count, 2)
        self.assertEqual(self.validator.await_args.args[2], TARGET)
        self.assertNotIn('auth_failed_proxy_hash', self.state)

    async def test_legacy_authentication_backoff_is_bound_to_original_source_route(self):
        self.state.update(auth_failed_hash=sync.auth_hash(cookies('new-cookie')), auth_retry_after=4600)
        self.assertEqual((await self.run_sync(now=1001))['status'], 'updated')
        self.validator.assert_awaited_once_with(cookies('new-cookie'), 'fixed@example.test', TARGET)

    async def test_revoked_registration_and_changed_target_abort_before_write(self):
        async def revoked(*_):
            self.policy['enabled'] = False
            self.save_registration()
            return {'email': 'fixed@example.test', 'credits': 100}
        self.validator.side_effect = revoked
        with self.assertRaisesRegex(sync.SyncError, 'account_proxy_mismatch'):
            await self.run_sync()
        self.gateway.write.assert_not_awaited()
        self.policy['enabled'] = True
        self.save_registration()
        self.state = {'proxy_hash': sync.digest(sync.proxy_identity(SOURCE)), 'token_id': 2}

        async def changed(*_):
            self.row['proxy_url'] = self.row['captcha_proxy_url'] = SOURCE
            return {'email': 'fixed@example.test', 'credits': 100}
        self.validator.side_effect = changed
        with self.assertRaisesRegex(sync.SyncError, 'account_changed_during_sync'):
            await self.run_sync()
        self.gateway.write.assert_not_awaited()


if __name__ == '__main__':
    unittest.main()
