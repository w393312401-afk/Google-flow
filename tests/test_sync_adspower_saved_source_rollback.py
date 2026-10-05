"""An unchanged saved snapshot must not replace a newer Flow session."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import AsyncMock


PATH = Path(__file__).resolve().parents[1] / 'local/sync_adspower_cookies.py'
SPEC = importlib.util.spec_from_file_location('sync_saved_source_rollback', PATH)
sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync)


def cookies(value):
    return [{'name': 'SID', 'value': value, 'domain': '.google.com', 'path': '/', 'secure': True}]


class SavedSourceRollbackTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.config = sync.validate_config(dict(
            profile_id='saved-profile', expected_email='saved@example.test', token_id=None,
            adspower_base='http://127.0.0.1:50325', flow_base='http://127.0.0.1:38000',
            enable_on_create=False, allow_saved_cookies=True))
        self.state, self.rows = {}, []
        self.source = cookies('initial-snapshot')
        self.profile = {'source': 'saved', 'ws': 'saved:saved-profile', 'proxy': ''}
        self.gateway = sync.Gateway(self.config, None, {})
        self.gateway.profile = AsyncMock(side_effect=lambda: copy.deepcopy(self.profile))
        self.gateway.cookies = AsyncMock(side_effect=lambda _: copy.deepcopy(self.source))
        self.gateway.tokens = AsyncMock(side_effect=lambda: copy.deepcopy(self.rows))
        self.gateway.busy = AsyncMock(return_value=(False, False))
        self.validator = AsyncMock(return_value={'email': 'saved@example.test', 'credits': 100})

        async def write(token_id, payload):
            if token_id is None:
                self.rows.append(dict(payload, id=3, email=payload['login_account'],
                                      at_expires='2099-01-01T00:00:00Z'))
            else:
                self.rows[0]['google_cookies'] = payload['google_cookies']
        self.gateway.write = AsyncMock(side_effect=write)

    async def run_sync(self, now=1000):
        return await sync.synchronize(self.config, self.state, self.gateway,
                                      validator=self.validator, now=now)

    async def create(self):
        self.assertEqual((await self.run_sync())['status'], 'created')
        self.gateway.write.reset_mock()
        self.validator.reset_mock()

    async def test_first_saved_import_records_confirmed_source(self):
        result = await self.run_sync()
        self.assertEqual(result['status'], 'created')
        self.assertEqual(self.state['synced_cookie_hash'], sync.auth_hash(self.source))
        self.gateway.write.assert_awaited_once()
        self.validator.assert_awaited_once()

    async def test_unchanged_saved_source_preserves_rotated_database_without_claiming_validation(self):
        await self.create()
        rotated = json.dumps(cookies('flow-rotated-session'))
        self.rows[0]['google_cookies'] = rotated
        self.rows[0]['at_expires'] = '1970-01-01T00:00:00Z'
        validation_before = (self.state['validated_hash'], self.state['validated_at'])
        self.validator.side_effect = AssertionError('stale snapshot must not be validated')
        result = await self.run_sync(now=5000)
        self.assertEqual(result, {'status': 'unchanged', 'reason': 'saved_source_unchanged', 'token_id': 3})
        self.assertEqual(self.rows[0]['google_cookies'], rotated)
        self.assertEqual((self.state['validated_hash'], self.state['validated_at']), validation_before)
        self.gateway.write.assert_not_awaited()
        self.validator.assert_not_awaited()

    async def test_changed_saved_source_still_validates_and_updates(self):
        await self.create()
        self.rows[0]['google_cookies'] = json.dumps(cookies('flow-rotated-session'))
        self.source = cookies('new-ads-snapshot')
        self.assertEqual((await self.run_sync(now=5000))['status'], 'updated')
        self.assertEqual(json.loads(self.rows[0]['google_cookies']), self.source)
        self.assertEqual(self.state['synced_cookie_hash'], sync.auth_hash(self.source))
        self.gateway.write.assert_awaited_once()
        self.validator.assert_awaited_once()

    async def test_live_cdp_source_keeps_existing_refresh_behavior(self):
        await self.create()
        self.rows[0]['google_cookies'] = json.dumps(cookies('flow-rotated-session'))
        self.profile.update(source='cdp', ws='ws://127.0.0.1:1234/devtools/browser/test')
        self.assertEqual((await self.run_sync(now=5000))['status'], 'updated')
        self.assertEqual(json.loads(self.rows[0]['google_cookies']), self.source)
        self.gateway.write.assert_awaited_once()
        self.validator.assert_awaited_once()

    async def test_confirmed_matching_database_seeds_source_marker_without_write(self):
        await self.create()
        self.state.pop('synced_cookie_hash')
        self.assertEqual((await self.run_sync(now=5000))['reason'], 'identity_validated')
        self.assertEqual(self.state['synced_cookie_hash'], sync.auth_hash(self.source))
        self.gateway.write.assert_not_awaited()

    async def test_legacy_state_without_saved_marker_is_not_assumed_synced(self):
        await self.create()
        self.state.pop('synced_cookie_hash')
        self.rows[0]['google_cookies'] = json.dumps(cookies('different-session'))
        self.assertEqual((await self.run_sync(now=5000))['status'], 'updated')
        self.gateway.write.assert_awaited_once()

    async def test_failed_write_does_not_mark_source_synced(self):
        self.gateway.write.side_effect = sync.SyncError('account_write_unconfirmed')
        with self.assertRaisesRegex(sync.SyncError, 'account_write_unconfirmed'):
            await self.run_sync()
        self.assertNotIn('synced_cookie_hash', self.state)

    async def test_busy_deferral_does_not_mark_validated_source_synced(self):
        self.gateway.busy.return_value = (True, False)
        self.assertEqual((await self.run_sync())['reason'], 'generation_busy')
        self.assertIn('validated_hash', self.state)
        self.assertNotIn('synced_cookie_hash', self.state)
        self.gateway.write.assert_not_awaited()


if __name__ == '__main__':
    unittest.main()
