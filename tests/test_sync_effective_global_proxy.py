"""Offline recovery authority for an existing account's pinned global fallbacks."""

import copy
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import AsyncMock, patch


PATH = Path(__file__).resolve().parents[1] / 'local/sync_adspower_cookies.py'
SPEC = importlib.util.spec_from_file_location('sync_effective_global_proxy', PATH)
sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync)

SOURCE = 'socks5://source-user:source-password@source.example.test:1080'
TARGET = 'http://target%40user:target%3Apassword@target.example.test:8080'
EMAIL = 'fixed@example.test'
COOKIES = [{'name': 'SID', 'value': 'SYNTHETIC_FRESH_SESSION', 'domain': '.google.com',
            'path': '/', 'secure': True}]


class EffectiveGlobalProxyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.database = self.root / 'flow.db'
        with sqlite3.connect(self.database) as conn:
            conn.execute('CREATE TABLE proxy_config (id INTEGER PRIMARY KEY,enabled INTEGER,proxy_url TEXT)')
            conn.execute('CREATE TABLE captcha_config (id INTEGER PRIMARY KEY,captcha_method TEXT,'
                         'browser_proxy_enabled INTEGER,browser_proxy_url TEXT)')
            conn.execute('INSERT INTO proxy_config VALUES (1,1,?)', (TARGET,))
            conn.execute("INSERT INTO captcha_config VALUES (1,'browser',1,?)", (TARGET,))
        self.config = sync.validate_config(dict(
            profile_id='fixed', expected_email=EMAIL, token_id=15,
            adspower_base='http://127.0.0.1:50325', flow_base='http://127.0.0.1:38000',
            flow_db_path=str(self.database), effective_global_proxy_hash=sync.digest(sync.proxy_identity(TARGET))))
        self.row = dict(id=15, email=EMAIL, login_account=EMAIL, remark='adspower-sync:fixed',
                        proxy_url='', captcha_proxy_url='', google_cookies=json.dumps([
                            dict(COOKIES[0], value='SYNTHETIC_OLD_SESSION')]),
                        at_expires='2099-01-01T00:00:00Z', is_active=True,
                        image_enabled=False, video_enabled=True)
        self.profile = dict(source='cdp', ws='ws://127.0.0.1:9222/devtools/browser/fixed', proxy=SOURCE)
        self.state = dict(proxy_hash=sync.digest(sync.proxy_identity(SOURCE)), token_id=15)
        self.gateway = sync.Gateway(self.config, None, {})
        self.gateway.profile = AsyncMock(side_effect=lambda: copy.deepcopy(self.profile))
        self.gateway.tokens = AsyncMock(side_effect=lambda: [copy.deepcopy(self.row)])
        self.gateway.cookies = AsyncMock(return_value=copy.deepcopy(COOKIES))
        self.gateway.busy = AsyncMock(return_value=(False, False))

        async def write(token_id, payload):
            self.assertEqual(token_id, 15)
            self.assertEqual(set(payload), {'google_cookies', 'auto_enable_on_update'})
            self.row['google_cookies'] = payload['google_cookies']

        async def disable(token_id):
            self.assertEqual(token_id, 15)
            self.row['is_active'] = False

        self.gateway.write = AsyncMock(side_effect=write)
        self.gateway.disable = AsyncMock(side_effect=disable)
        self.validator = AsyncMock(return_value=dict(email=EMAIL, credits=100))

    def resolve(self, token=None, config=None):
        return sync.authorized_target_proxy(
            self.row if token is None else token, SOURCE, self.config if config is None else config)

    async def run_sync(self):
        return await sync.synchronize(self.config, self.state, self.gateway,
                                      validator=self.validator, now=1000)

    def change(self, table, values):
        fields = ','.join(key + '=?' for key in values)
        with sqlite3.connect(self.database) as conn:
            conn.execute('UPDATE ' + table + ' SET ' + fields + ' WHERE id=1', tuple(values.values()))

    def assert_resolution_rejected(self, token=None, config=None):
        with self.assertRaisesRegex(sync.SyncError, '^account_proxy_mismatch$') as caught:
            self.resolve(token, config)
        self.assertNotIn('password', str(caught.exception))
        self.assertNotIn(str(self.database), str(caught.exception))

    async def test_pinned_fallback_preserves_both_token_and_database_routes(self):
        before = copy.deepcopy(self.row)
        db_before = self.database.read_bytes()
        self.assertEqual(self.resolve(), TARGET)
        self.assertEqual((await self.run_sync())['status'], 'updated')
        self.validator.assert_awaited_once_with(COOKIES, EMAIL, TARGET)
        self.assertEqual({k: v for k, v in self.row.items() if k != 'google_cookies'},
                         {k: v for k, v in before.items() if k != 'google_cookies'})
        self.assertEqual(self.database.read_bytes(), db_before)
        self.assertEqual(self.state['proxy_hash'], sync.digest(sync.proxy_identity(SOURCE)))
        for secret in ('source-password', 'target@user', 'target:password', 'SYNTHETIC_FRESH_SESSION'):
            self.assertNotIn(secret, json.dumps(self.state))

    def test_no_opt_in_preserves_original_authority_without_reading_database(self):
        config = {key: value for key, value in self.config.items() if key != 'effective_global_proxy_hash'}
        config['flow_db_path'] = str(self.root / 'does-not-exist.db')
        with patch.object(sync, 'ROOT', self.root):
            self.assert_resolution_rejected(config=config)
        self.assertEqual(self.resolve(token=dict(self.row, proxy_url=SOURCE, captcha_proxy_url=SOURCE),
                                      config=config), SOURCE)
        self.assertFalse(Path(config['flow_db_path']).exists())

    def test_pin_requires_the_fixed_existing_account_and_empty_overrides(self):
        for token in (dict(self.row, id=16), dict(self.row, proxy_url=TARGET),
                      dict(self.row, captcha_proxy_url=TARGET),
                      dict(self.row, proxy_url=SOURCE, captcha_proxy_url=SOURCE)):
            with self.subTest(token_id=token['id']):
                self.assert_resolution_rejected(token=token)
        with self.assertRaisesRegex(sync.SyncError, 'account_proxy_mismatch'):
            sync.authorized_target_proxy(None, SOURCE, self.config)

    def test_malformed_or_missing_pin_is_rejected_without_weakening_source_authority(self):
        for pin in ('', None, True, 'x' * 64, 'a' * 63, 'A' * 64):
            with self.subTest(pin=pin):
                self.assert_resolution_rejected(config=dict(self.config, effective_global_proxy_hash=pin))
                with self.assertRaisesRegex(sync.SyncError, 'account_proxy_mismatch'):
                    sync.validate_config(dict(self.config, effective_global_proxy_hash=pin))
        with self.assertRaisesRegex(sync.SyncError, 'account_proxy_mismatch'):
            sync.validate_config(dict(self.config, token_id=None))

    def test_disabled_or_changed_global_route_is_rejected(self):
        for table, changes in (
            ('proxy_config', dict(enabled=0)),
            ('captcha_config', dict(browser_proxy_enabled=0)),
            ('captcha_config', dict(captcha_method='personal')),
            ('proxy_config', dict(proxy_url='')),
            ('captcha_config', dict(browser_proxy_url=None)),
            ('proxy_config', dict(proxy_url='http://other.example.test:8080')),
            ('captcha_config', dict(browser_proxy_url='http://other.example.test:8080')),
            ('proxy_config', dict(proxy_url='not-a-proxy')),
        ):
            with self.subTest(table=table, changes=changes):
                self.change(table, changes)
                self.assert_resolution_rejected()
                self.change('proxy_config', dict(enabled=1, proxy_url=TARGET))
                self.change('captcha_config', dict(captcha_method='browser', browser_proxy_enabled=1,
                                                   browser_proxy_url=TARGET))

    def test_missing_database_captcha_table_or_row_is_rejected(self):
        config = dict(self.config, flow_db_path=str(self.root / 'does-not-exist.db'))
        self.assert_resolution_rejected(config=config)
        self.assertFalse(Path(config['flow_db_path']).exists())
        with sqlite3.connect(self.database) as conn:
            conn.execute('DELETE FROM captcha_config')
        self.assert_resolution_rejected()
        with sqlite3.connect(self.database) as conn:
            conn.execute('DROP TABLE captcha_config')
        self.assert_resolution_rejected()

    async def test_source_proxy_still_has_its_independent_strict_pin(self):
        self.profile['proxy'] = 'socks5://changed-source.example.test:1080'
        with self.assertRaisesRegex(sync.SyncError, 'profile_proxy_changed'):
            await self.run_sync()
        self.gateway.cookies.assert_not_awaited()
        self.validator.assert_not_awaited()
        self.gateway.write.assert_not_awaited()

    async def test_global_reconfiguration_during_validation_prevents_cookie_write(self):
        async def change_route(*args):
            self.change('proxy_config', dict(enabled=0))
            return dict(email=EMAIL, credits=100)

        self.validator.side_effect = change_route
        with self.assertRaisesRegex(sync.SyncError, 'account_proxy_mismatch'):
            await self.run_sync()
        self.gateway.write.assert_not_awaited()

    async def test_low_balance_path_rechecks_pinned_target_without_rewriting_routes(self):
        self.config['disable_below_credits'] = 101
        result = await self.run_sync()
        self.assertEqual(result['reason'], 'low_balance_disabled')
        self.gateway.disable.assert_awaited_once_with(15)
        self.gateway.write.assert_not_awaited()
        self.assertEqual((self.row['proxy_url'], self.row['captcha_proxy_url']), ('', ''))
        self.assertEqual(self.resolve(), TARGET)


if __name__ == '__main__':
    unittest.main()
