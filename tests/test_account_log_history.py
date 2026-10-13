"""Dated history ownership, idempotence and credential-free audit writes."""
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

from src.services import account_log_history as history


class AccountLogHistoryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.local = self.root / 'local'
        self.local.mkdir()
        self.path = self.root / 'flow.db'
        self.db = types.SimpleNamespace(db_path=str(self.path))
        with sqlite3.connect(self.path) as connection:
            connection.execute('''CREATE TABLE tokens(id INTEGER PRIMARY KEY, email TEXT,
                login_account TEXT, remark TEXT, protocol_mode TEXT, last_st_refresh_at TEXT,
                last_st_refresh_result TEXT, adspower_serial TEXT)''')
            connection.execute('CREATE TABLE token_health(token_id INTEGER, reason TEXT, checked_at TEXT)')
            connection.execute('INSERT INTO tokens VALUES(?,?,?,?,?,?,?,?)', (
                2, 'owner@example.test', 'owner@example.test', 'adspower-sync:one', 'protocol',
                '2026-10-06 08:11:32+00:00', 'success', '58'))
            connection.execute('INSERT INTO token_health VALUES(?,?,?)', (
                2, 'AT_REFRESH: credentials rejected (UNAUTHENTICATED)', '2026-10-06 08:11:35+00:00'))
        self.state(last_run_at=1791271700, synced_at=1791271700,
                   login_attempted_at=1791270000,
                   last_result={'status': 'updated', 'reason': 'sync_complete', 'token_id': 2,
                                'cookie': 'COOKIE_SECRET', 'verified_cookie_hash': 'HASH_SECRET'})

    def state(self, **fields):
        config = {'token_id': 2, 'profile_id': 'one', 'expected_email': 'owner@example.test',
                  'password': 'PASSWORD_SECRET'}
        (self.local / 'adspower-cookie-sync-one.json').write_text(json.dumps(config))
        state = {'token_id': 2, **fields}
        (self.local / 'adspower-cookie-sync-one.state.json').write_text(json.dumps(state))

    def rows(self):
        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute('SELECT * FROM account_operation_logs ORDER BY id')]

    async def test_history_uses_real_dates_deduplicates_and_labels_legacy_probe(self):
        first = await history.import_account_log_history(self.db, local_dir=self.local)
        rows = self.rows()
        self.assertEqual(first, 4)
        self.assertEqual(await history.import_account_log_history(self.db, local_dir=self.local), 0)
        self.assertEqual(self.rows(), rows)
        refresh = next(row for row in rows if row['operation'] == 'refresh_st')
        self.assertEqual(refresh['status'], 'info')
        self.assertEqual(refresh['reason'], 'frontend_probe_passed')
        self.assertEqual(json.loads(refresh['details'])['category'], 'protocol_probe')
        self.assertEqual(refresh['created_at'], '2026-10-06T08:11:32.000000+00:00')
        health = next(row for row in rows if row['operation'] == 'health_check')
        self.assertEqual((health['stage'], health['reason']), ('AT_REFRESH', 'credentials_rejected'))
        self.assertEqual(health['created_at'], '2026-10-06T08:11:35.000000+00:00')
        raw = json.dumps(rows)
        for secret in ('COOKIE_SECRET', 'HASH_SECRET', 'PASSWORD_SECRET'):
            self.assertNotIn(secret, raw)

    async def test_unowned_state_and_undated_legacy_lines_are_not_assigned_to_account(self):
        path = self.local / 'adspower-cookie-sync-one.json'
        config = json.loads(path.read_text())
        config['expected_email'] = 'someone-else@example.test'
        path.write_text(json.dumps(config))
        (self.local / 'logs.txt').write_text('[TOKEN_HEALTH] 2026-10-06T08:12:00Z credentials rejected')
        await history.import_account_log_history(self.db, local_dir=self.local)
        self.assertEqual({row['operation'] for row in self.rows()}, {'refresh_st', 'health_check'})

    async def test_missing_timestamp_is_not_replaced_with_file_mtime(self):
        self.state(last_result={'status': 'error', 'reason': 'cookies_unavailable'})
        await history.import_account_log_history(self.db, local_dir=self.local)
        self.assertEqual(len(self.rows()), 2)

    async def test_failure_cannot_change_account_or_state(self):
        state = self.local / 'adspower-cookie-sync-one.state.json'
        before = state.read_bytes()
        with patch.object(history, 'audit_local_operation', side_effect=RuntimeError('PASSWORD_SECRET')):
            self.assertEqual(await history.import_account_log_history(self.db, local_dir=self.local), 0)
        self.assertEqual(state.read_bytes(), before)
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute('SELECT last_st_refresh_result FROM tokens WHERE id=2').fetchone()[0], 'success')

    async def test_runtime_queue_does_not_wait_for_sqlite_and_records_event_time(self):
        entered, release = threading.Event(), threading.Event()
        captured = []

        def slow_writer(*args, **event):
            captured.append(event)
            entered.set()
            release.wait(3)
            return 1

        with patch.object(history, 'audit_local_operation', slow_writer):
            future = history.queue_local_operation(history.ROOT, self.path, 2,
                operation='cookie_sync', status='started', reason='cookie_sync_requested')
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 1))
                self.assertFalse(future.done())
                self.assertIsInstance(captured[0]['created_at'], datetime)
                self.assertEqual(captured[0]['created_at'].tzinfo, timezone.utc)
            finally:
                release.set()
                await asyncio.wrap_future(future)


if __name__ == '__main__':
    unittest.main()
