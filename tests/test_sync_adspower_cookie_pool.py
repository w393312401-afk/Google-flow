"""Offline pool runner tests: no real configs, services, browsers or Cookie sync."""
import asyncio
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


_SPEC = importlib.util.spec_from_file_location(
    'sync_adspower_cookie_pool', Path(__file__).resolve().parents[1] / 'local/sync_adspower_cookie_pool.py')
pool = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(pool)


class CookiePoolTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.local = self.root / 'local'
        self.local.mkdir()
        self.enterContext(patch.object(pool, 'ROOT', self.root))
        self.enterContext(patch.object(pool, 'LOCAL', self.local))
        self.enterContext(patch.object(pool, '_load_single_runner', side_effect=AssertionError('real sync is forbidden')))
        self.calls = []

    def private(self, name, value):
        path = self.local / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return path

    def manifest(self, entries):
        return self.private('pool.json', {'config_paths': entries})

    async def success(self, path):
        self.calls.append(path)
        await asyncio.sleep(0)
        return {'status': 'unchanged', 'reason': 'identity_validated', 'token_id': len(self.calls)}

    async def test_only_explicit_configs_run_in_order_without_overlap(self):
        first = self.private('first.json', {'profile_id': 'one'})
        second = self.private('nested/second.json', {'profile_id': 'two'})
        unknown = self.private('unreviewed.json', {'profile_id': 'never-run'})
        snapshots = {p: p.read_bytes() for p in (first, second, unknown)}
        active = 0
        async def runner(path):
            nonlocal active
            self.assertEqual(active, 0)
            active += 1
            value = await self.success(path)
            active -= 1
            return value
        result = await pool.run_pool(self.manifest(['first.json', str(second)]), run_once=runner)
        self.assertEqual(self.calls, [first, second])
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['counts']['unchanged'], 2)
        self.assertEqual([r['index'] for r in result['results']], [1, 2])
        self.assertEqual({p: p.read_bytes() for p in snapshots}, snapshots)

    async def test_failure_does_not_retry_or_prevent_following_config(self):
        paths = [self.private(f'{i}.json', {}) for i in range(3)]
        async def runner(path):
            self.calls.append(path)
            if path == paths[1]:
                raise RuntimeError('COOKIE_SECRET proxy://password@host')
            return {'status': 'updated', 'reason': 'sync_complete'}
        result = await pool.run_pool(self.manifest([str(p) for p in paths]), run_once=runner)
        self.assertEqual(self.calls, paths)
        self.assertEqual(result['status'], 'partial_failed')
        self.assertEqual(result['counts']['error'], 1)
        self.assertEqual(result['counts']['updated'], 2)
        self.assertNotIn('SECRET', json.dumps(result))

    async def test_dependency_stdout_stderr_and_unknown_result_fields_are_hidden(self):
        self.private('one.json', {})
        stdout, stderr = io.StringIO(), io.StringIO()
        async def noisy(_):
            import sys
            print('COOKIE_SECRET')
            print('PROXY_SECRET', file=sys.stderr)
            return {'status': 'updated', 'reason': 'SECRET_LOWERCASE', 'token_id': 2,
                    'cookie': 'COOKIE_SECRET', 'email': 'private@example.test'}
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = await pool.run_pool(self.manifest(['one.json']), run_once=noisy)
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(stderr.getvalue(), '')
        self.assertEqual(result['results'][0], {'index': 1, 'status': 'updated',
            'reason': 'sync_result_redacted', 'token_id': 2})
        self.assertNotIn(str(self.local), json.dumps(result))

    async def test_private_config_permission_failure_is_isolated(self):
        invalid = self.private('invalid.json', {})
        invalid.chmod(0o644)
        valid = self.private('valid.json', {})
        result = await pool.run_pool(self.manifest(['invalid.json', 'valid.json']), run_once=self.success)
        self.assertEqual(self.calls, [valid])
        self.assertEqual(result['results'][0]['reason'], 'private_file_permissions')
        self.assertEqual(invalid.stat().st_mode & 0o777, 0o644)

    async def test_manifest_must_be_private_before_any_run(self):
        self.private('one.json', {})
        manifest = self.manifest(['one.json'])
        manifest.chmod(0o644)
        result = await pool.run_pool(manifest, run_once=self.success)
        self.assertEqual(result['reason'], 'private_file_permissions')
        self.assertEqual(self.calls, [])

    async def test_outside_or_traversal_paths_reject_entire_manifest(self):
        self.private('good.json', {})
        for path in (str(self.root / 'outside.json'), '../outside.json', 'nested/../good.json'):
            with self.subTest(path=path):
                result = await pool.run_pool(self.manifest(['good.json', path]), run_once=self.success)
                self.assertEqual(result['status'], 'error')
                self.assertEqual(self.calls, [])

    async def test_symlink_config_and_symlink_parent_rejected(self):
        target = self.private('target.json', {})
        (self.local / 'alias.json').symlink_to(target)
        (self.local / 'aliasdir').symlink_to(self.local, target_is_directory=True)
        for entry in ('alias.json', 'aliasdir/target.json'):
            with self.subTest(entry=entry):
                result = await pool.run_pool(self.manifest([entry]), run_once=self.success)
                self.assertEqual(result['reason'], 'config_symlink_rejected')
                self.assertEqual(self.calls, [])

    async def test_duplicate_paths_and_manifest_as_config_rejected(self):
        config = self.private('one.json', {})
        for paths in (['one.json', str(config)], ['pool.json']):
            with self.subTest(paths=paths):
                result = await pool.run_pool(self.manifest(paths), run_once=self.success)
                self.assertEqual(result['reason'], 'duplicate_or_manifest_config')
                self.assertEqual(self.calls, [])

    async def test_invalid_manifest_shape_never_discovers_files(self):
        self.private('unknown.json', {})
        for value in ({}, {'config_paths': []}, {'config_paths': 'unknown.json'},
                      {'config_paths': ['unknown.json'], 'glob': '*.json'},
                      {'config_paths': ['unknown.json'] * 129}):
            with self.subTest(value=value):
                result = await pool.run_pool(self.private('pool.json', value), run_once=self.success)
                self.assertEqual(result['reason'], 'invalid_pool_manifest')
                self.assertEqual(self.calls, [])

    async def test_global_lock_applies_across_manifests_and_releases(self):
        self.private('one.json', {})
        manifest = self.manifest(['one.json'])
        second = self.private('other-pool.json', {'config_paths': ['one.json']})
        with pool._pool_lock():
            for path in (manifest, second):
                result = await pool.run_pool(path, run_once=self.success)
                self.assertEqual(result, {'status': 'deferred', 'reason': 'pool_already_running', 'results': []})
        self.assertEqual(self.calls, [])
        self.assertEqual((self.local / pool.LOCK_NAME).stat().st_mode & 0o777, 0o600)
        self.assertEqual((await pool.run_pool(second, run_once=self.success))['status'], 'ok')

    async def test_symlink_lock_does_not_touch_its_target(self):
        target = self.private('target.json', {'must': 'stay'})
        original = target.read_bytes()
        target.chmod(0o644)
        (self.local / pool.LOCK_NAME).symlink_to(target)
        result = await pool.run_pool(self.manifest(['target.json']), run_once=self.success)
        self.assertEqual(result['reason'], 'pool_lock_unavailable')
        self.assertEqual(target.read_bytes(), original)
        self.assertEqual(target.stat().st_mode & 0o777, 0o644)

    async def test_helper_deferred_and_safe_errors_are_preserved(self):
        paths = [self.private(f'{i}.json', {}) for i in range(2)]
        class Rejected(Exception):
            reason = 'profile_inactive'
        async def runner(path):
            if path == paths[0]:
                return {'status': 'deferred', 'reason': 'generation_busy'}
            raise Rejected('SECRET detail')
        result = await pool.run_pool(self.manifest([str(p) for p in paths]), run_once=runner)
        self.assertEqual([r['reason'] for r in result['results']], ['generation_busy', 'profile_inactive'])
        self.assertEqual(result['status'], 'partial_failed')

    async def test_network_backoff_diagnostics_survive_the_pool_summary(self):
        self.private('one.json', {})
        async def runner(_):
            return {'status': 'deferred', 'reason': 'network_backoff', 'token_id': 2,
                    'prior_reason': 'identity_validation_unavailable', 'retry_after': 1300,
                    'detail': 'PRIVATE'}
        result = await pool.run_pool(self.manifest(['one.json']), run_once=runner)
        self.assertEqual(result['results'], [{'index': 1, 'status': 'deferred',
            'reason': 'network_backoff', 'token_id': 2,
            'prior_reason': 'identity_validation_unavailable', 'retry_after': 1300}])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_network_backoff_rejects_unsafe_diagnostic_values(self):
        baseline = {'status': 'deferred', 'reason': 'network_backoff'}
        for prior_reason in ('PRIVATE', ['PRIVATE'], None, 'network_backoff', 'generation_busy'):
            with self.subTest(prior_reason=prior_reason):
                self.assertEqual(pool._safe_result(dict(baseline, prior_reason=prior_reason)), baseline)
        for retry_after in ('PRIVATE', None, True, False, 0, -1, float('nan'), float('inf'), 10**12):
            with self.subTest(retry_after=retry_after):
                self.assertEqual(pool._safe_result(dict(baseline, retry_after=retry_after)), baseline)
        for prior_reason in pool.NETWORK_FAILURE_REASONS:
            with self.subTest(prior_reason=prior_reason):
                expected = dict(baseline, prior_reason=prior_reason, retry_after=1300.5)
                self.assertEqual(pool._safe_result(expected), expected)
        normal = {'status': 'unchanged', 'reason': 'identity_validated'}
        self.assertEqual(pool._safe_result(dict(normal, prior_reason='local_transport_failed',
                                               retry_after=1300)), normal)

    def test_saved_cookie_and_inactive_staging_errors_remain_actionable(self):
        for reason in ('invalid_cookie_source_option', 'invalid_inactive_staging',
                       'profile_cookie_source_invalid', 'saved_cookies_unavailable'):
            with self.subTest(reason=reason):
                self.assertEqual(pool._safe_result({'status': 'error', 'reason': reason,
                                                   'detail': 'COOKIE_SECRET'}),
                                 {'status': 'error', 'reason': reason})

    async def test_missing_or_malformed_config_does_not_call_helper(self):
        malformed = self.private('bad.json', {})
        malformed.write_text('{invalid')
        result = await pool.run_pool(self.manifest(['missing.json', 'bad.json']), run_once=self.success)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(self.calls, [])

    async def test_cli_relative_manifest_resolves_from_repository_not_cwd(self):
        config = self.private('one.json', {})
        self.manifest(['one.json'])
        result = await pool.run_pool('local/pool.json', run_once=self.success)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(self.calls, [config])

    def test_main_outputs_only_safe_summary_and_nonzero_partial_failure(self):
        async def fake(_):
            return {'status': 'partial_failed', 'counts': {'error': 1}, 'results': []}
        output = io.StringIO()
        with patch.object(pool, 'run_pool', fake), patch('sys.argv', ['pool', '--manifest', 'local/pool.json']), contextlib.redirect_stdout(output):
            self.assertEqual(pool.main(), 1)
        self.assertEqual(json.loads(output.getvalue())['status'], 'partial_failed')

    async def test_malformed_results_and_exception_reason_do_not_stop_later_configs(self):
        paths = [self.private(f'{i}.json', {}) for i in range(3)]
        class MalformedError(Exception):
            reason = ['SECRET']
        async def runner(path):
            self.calls.append(path)
            if path == paths[0]:
                return {'status': ['SECRET']}
            if path == paths[1]:
                raise MalformedError('SECRET')
            return {'status': 'created', 'reason': 'sync_complete', 'cookie': 'SECRET'}
        result = await pool.run_pool(self.manifest([str(p) for p in paths]), run_once=runner)
        self.assertEqual(self.calls, paths)
        self.assertEqual(result['counts']['error'], 2)
        self.assertEqual(result['counts']['created'], 1)
        self.assertNotIn('SECRET', json.dumps(result))

    def test_main_interruption_has_no_raw_exception_output(self):
        async def interrupted(_):
            raise asyncio.CancelledError('SECRET')
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(pool, 'run_pool', interrupted), patch('sys.argv', ['pool', '--manifest', 'local/pool.json']), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            self.assertEqual(pool.main(), 1)
        self.assertEqual(json.loads(output.getvalue())['reason'], 'pool_interrupted')
        self.assertNotIn('SECRET', output.getvalue() + errors.getvalue())


if __name__ == '__main__':
    unittest.main()
