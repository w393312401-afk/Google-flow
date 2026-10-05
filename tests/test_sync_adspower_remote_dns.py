"""SOCKS DNS compatibility checks; every service and validator is mocked."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch


PATH = Path(__file__).resolve().parents[1] / 'local/sync_adspower_cookies.py'
SPEC = importlib.util.spec_from_file_location('sync_adspower_remote_dns', PATH)
sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync)

SOURCE = 'socks5://user%40test:password%3Atest@proxy.example.test:1080'
REMOTE = SOURCE.replace('socks5:', 'socks5h:', 1)
COOKIES = [{'name': 'SID', 'value': 'TEST_NEW_SESSION', 'domain': '.google.com',
            'path': '/', 'secure': True}]


def config(**values):
    return sync.validate_config(dict(
        profile_id='fixed-profile', expected_email='fixed@example.test', token_id=None,
        adspower_base='http://127.0.0.1:50325', flow_base='http://127.0.0.1:38000',
        enable_on_create=False, **values))


class FakeGateway:
    def __init__(self, rows=None):
        self.rows = copy.deepcopy(rows or [])
        self.source = dict(source='cdp', ws='ws://127.0.0.1:1234/devtools/browser/test',
                           proxy=SOURCE)
        self.profile = AsyncMock(side_effect=lambda: copy.deepcopy(self.source))
        self.tokens = AsyncMock(side_effect=lambda: copy.deepcopy(self.rows))
        self.cookies = AsyncMock(return_value=copy.deepcopy(COOKIES))
        self.busy = AsyncMock(return_value=(False, False))
        self.write = AsyncMock(side_effect=self.save)

    async def save(self, token_id, payload):
        if token_id is None:
            self.rows.append(dict(payload, id=7, email=payload['login_account'],
                                  at_expires='2099-01-01T00:00:00Z'))
        else:
            next(r for r in self.rows if r['id'] == token_id).update(payload)


def account(proxy=SOURCE):
    return dict(id=7, email='fixed@example.test', login_account='fixed@example.test',
                remark='adspower-sync:fixed-profile', proxy_url=proxy, captcha_proxy_url=proxy,
                google_cookies=json.dumps([dict(COOKIES[0], value='TEST_OLD_SESSION')]),
                at_expires='2099-01-01T00:00:00Z', is_active=True, image_enabled=True,
                video_enabled=False, auto_refresh_enabled=False, image_concurrency=2,
                video_concurrency=1, st='frontend-original')


class RemoteDnsTests(unittest.IsolatedAsyncioTestCase):
    def validator(self):
        return AsyncMock(return_value={'email': 'fixed@example.test', 'credits': 1050})

    def test_config_defaults_and_unchanged_transports(self):
        self.assertIs(config()['remote_dns'], False)
        self.assertEqual(sync.validation_proxy_uri(SOURCE), SOURCE)
        self.assertEqual(sync.validation_proxy_uri(REMOTE), REMOTE)
        for proxy in ('', 'http://proxy.example.test:1080', 'https://proxy.example.test:1080'):
            self.assertEqual(sync.validation_proxy_uri(proxy, True), proxy)
        self.assertEqual(sync.validation_proxy_uri(SOURCE, True), REMOTE)
        self.assertEqual(sync.validation_proxy_uri(REMOTE, True), REMOTE)

    async def test_non_bool_remote_dns_rejected_before_external_reads(self):
        for value in ('true', 1, 0, None, [], {}):
            with self.subTest(value=value):
                with self.assertRaisesRegex(sync.SyncError, 'invalid_remote_dns'):
                    config(remote_dns=value)
                gateway = FakeGateway()
                conf = config()
                conf['remote_dns'] = value
                with self.assertRaisesRegex(sync.SyncError, 'invalid_remote_dns'):
                    await sync.synchronize(conf, {}, gateway, validator=self.validator())
                gateway.profile.assert_not_awaited()
                gateway.write.assert_not_awaited()

    def test_alias_identity_keeps_complete_decoded_auth_and_endpoint(self):
        self.assertEqual(sync.proxy_identity(SOURCE), sync.proxy_identity(REMOTE))
        self.assertEqual(sync.proxy_identity(SOURCE)[3:], ('user@test', 'password:test'))
        for changed in (
            REMOTE.replace('proxy.example.test', 'other.example.test'),
            REMOTE.replace(':1080', ':1081'),
            REMOTE.replace('user%40test', 'other%40test'),
            REMOTE.replace('password%3Atest', 'password%3Aother'),
            REMOTE.replace('socks5h:', 'http:'),
            REMOTE.replace('socks5h:', 'https:'),
        ):
            with self.subTest(changed=changed):
                self.assertNotEqual(sync.proxy_identity(SOURCE), sync.proxy_identity(changed))
        self.assertNotEqual(sync.proxy_identity('http://proxy.example.test:1080'),
                            sync.proxy_identity('https://proxy.example.test:1080'))
        self.assertEqual(sync.authorized_target_proxy(account(REMOTE), SOURCE), REMOTE)

    async def test_default_creation_retains_local_dns_and_source_settings(self):
        gateway, check = FakeGateway(), self.validator()
        original = copy.deepcopy(gateway.source)
        self.assertEqual((await sync.synchronize(config(), {}, gateway,
                         validator=check, now=1000))['status'], 'created')
        check.assert_awaited_once_with(COOKIES, 'fixed@example.test', SOURCE)
        payload = gateway.write.await_args.args[1]
        self.assertEqual(payload['proxy_url'], SOURCE)
        self.assertEqual(payload['captcha_proxy_url'], SOURCE)
        self.assertEqual(gateway.source, original)

    async def test_new_staged_account_uses_remote_dns_without_changing_source(self):
        gateway, check, state = FakeGateway(), self.validator(), {}
        original = copy.deepcopy(gateway.source)
        conf = config(remote_dns=True, stage_inactive_create=True)
        self.assertEqual((await sync.synchronize(conf, state, gateway,
                         validator=check, now=1000))['status'], 'created')
        check.assert_awaited_once_with(COOKIES, 'fixed@example.test', REMOTE)
        token_id, payload = gateway.write.await_args.args
        self.assertIsNone(token_id)
        self.assertEqual(payload['proxy_url'], REMOTE)
        self.assertEqual(payload['captcha_proxy_url'], REMOTE)
        self.assertTrue(all(payload[k] is False for k in ('is_active', 'image_enabled', 'video_enabled')))
        self.assertFalse(payload['auto_refresh_enabled'])
        self.assertEqual(payload['image_concurrency'], 1)
        self.assertEqual(payload['video_concurrency'], 1)
        self.assertTrue(all(c.kwargs == {'stage_inactive_create': True}
                            for c in gateway.busy.await_args_list))
        self.assertEqual(gateway.source, original)
        self.assertEqual(state['proxy_hash'], sync.digest(sync.proxy_identity(SOURCE)))
        self.assertEqual(state['validated_proxy_hash'], sync.validation_proxy_hash(REMOTE))
        self.assertNotIn('password', json.dumps(state))

    async def test_existing_account_validation_does_not_overwrite_proxy_or_flags(self):
        row = account()
        gateway, check = FakeGateway([row]), self.validator()
        self.assertEqual((await sync.synchronize(config(remote_dns=True), {}, gateway,
                         validator=check, now=1000))['status'], 'updated')
        check.assert_awaited_once_with(COOKIES, 'fixed@example.test', REMOTE)
        self.assertEqual(set(gateway.write.await_args.args[1]), {'google_cookies', 'auto_enable_on_update'})
        for key in ('proxy_url', 'captcha_proxy_url', 'is_active', 'image_enabled',
                    'video_enabled', 'auto_refresh_enabled', 'st'):
            self.assertEqual(gateway.rows[0][key], row[key])

    async def test_existing_remote_dns_account_keeps_its_transport_by_default(self):
        gateway, check = FakeGateway([account(REMOTE)]), self.validator()
        self.assertEqual((await sync.synchronize(config(), {}, gateway,
                         validator=check, now=1000))['status'], 'updated')
        check.assert_awaited_once_with(COOKIES, 'fixed@example.test', REMOTE)
        self.assertEqual(gateway.rows[0]['proxy_url'], REMOTE)

    async def test_legacy_source_hash_accepts_only_same_endpoint_and_auth(self):
        legacy = sync.digest(('socks5h', *sync.proxy_identity(SOURCE)[1:]))
        state, gateway = {'proxy_hash': legacy}, FakeGateway()
        self.assertEqual((await sync.synchronize(config(remote_dns=True), state, gateway,
                         validator=self.validator(), now=1000))['status'], 'created')
        self.assertEqual(state['proxy_hash'], sync.digest(sync.proxy_identity(SOURCE)))
        for changed in (REMOTE.replace('proxy.example.test', 'other.example.test'),
                        REMOTE.replace('password%3Atest', 'different')):
            gateway = FakeGateway()
            state = {'proxy_hash': sync.validation_proxy_hash(changed)}
            with self.assertRaisesRegex(sync.SyncError, 'profile_proxy_changed'):
                await sync.synchronize(config(remote_dns=True), state, gateway,
                                       validator=self.validator(), now=1000)
            gateway.cookies.assert_not_awaited()
            gateway.write.assert_not_awaited()

    async def test_dns_transport_change_revalidates_and_bypasses_only_old_backoff(self):
        for cached in (True, False):
            with self.subTest(cached=cached):
                state = {'proxy_hash': sync.digest(sync.proxy_identity(SOURCE))}
                if cached:
                    state.update(validated_hash=sync.auth_hash(COOKIES), validated_at=1000,
                                 validated_proxy_hash=sync.validation_proxy_hash(SOURCE))
                else:
                    state.update(auth_failed_hash=sync.auth_hash(COOKIES), auth_retry_after=4600,
                                 auth_failed_proxy_hash=sync.validation_proxy_hash(SOURCE))
                gateway, check = FakeGateway(), self.validator()
                self.assertEqual((await sync.synchronize(config(remote_dns=True), state, gateway,
                                 validator=check, now=1001))['status'], 'created')
                check.assert_awaited_once_with(COOKIES, 'fixed@example.test', REMOTE)
        state = dict(auth_failed_hash=sync.auth_hash(COOKIES), auth_retry_after=4600,
                     auth_failed_proxy_hash=sync.validation_proxy_hash(REMOTE))
        gateway, check = FakeGateway(), self.validator()
        self.assertEqual((await sync.synchronize(config(remote_dns=True), state, gateway,
                         validator=check, now=1001))['reason'], 'authentication_backoff')
        check.assert_not_awaited()
        gateway.write.assert_not_awaited()

    async def test_source_endpoint_or_auth_drift_still_rejects_before_write(self):
        for changed in (SOURCE.replace('proxy.example.test', 'other.example.test'),
                        SOURCE.replace('password%3Atest', 'different')):
            with self.subTest(changed=changed):
                gateway, check = FakeGateway(), self.validator()
                async def drift(*_):
                    gateway.source['proxy'] = changed
                    return {'email': 'fixed@example.test', 'credits': 1050}
                check.side_effect = drift
                with self.assertRaisesRegex(sync.SyncError, 'profile_changed_during_sync'):
                    await sync.synchronize(config(remote_dns=True), {}, gateway,
                                           validator=check, now=1000)
                gateway.write.assert_not_awaited()

    async def test_authorization_rejects_different_endpoint_or_auth(self):
        for changed in (REMOTE.replace('proxy.example.test', 'other.example.test'),
                        REMOTE.replace('password%3Atest', 'different')):
            gateway = FakeGateway([account(changed)])
            with patch.object(sync, 'private_json', side_effect=sync.SyncError('private_file_unavailable')):
                with self.assertRaisesRegex(sync.SyncError, 'account_proxy_mismatch'):
                    await sync.synchronize(config(remote_dns=True), {}, gateway,
                                           validator=self.validator(), now=1000)
            gateway.cookies.assert_not_awaited()
            gateway.write.assert_not_awaited()

    async def test_new_account_with_saved_local_dns_is_not_reported_successful(self):
        gateway = FakeGateway()
        async def wrong_transport(token_id, payload):
            await gateway.save(token_id, payload)
            gateway.rows[-1]['proxy_url'] = SOURCE
        gateway.write.side_effect = wrong_transport
        with self.assertRaisesRegex(sync.SyncError, 'account_write_unconfirmed'):
            await sync.synchronize(config(remote_dns=True), {}, gateway,
                                   validator=self.validator(), now=1000)


if __name__ == '__main__':
    unittest.main()
