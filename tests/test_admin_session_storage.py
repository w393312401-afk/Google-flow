"""Admin browser sessions survive restarts and revoke consistently across workers."""

import asyncio
import hashlib
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from src.core.database import Database


class AdminSessionStorageTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = str(Path(directory.name) / "sessions.db")
        self.db = Database(self.path)
        await self.db.init_db()
        await self.db.init_config_from_toml({})
        self.other_worker = Database(self.path)

    async def session_rows(self):
        async with self.db._connect() as connection:
            return await (await connection.execute(
                "SELECT token_hash, credentials_hash, created_at, expires_at "
                "FROM admin_sessions ORDER BY token_hash"
            )).fetchall()

    async def test_session_survives_reopened_database(self):
        await self.db.create_admin_session("admin-restart-session")

        self.assertTrue(await self.other_worker.is_admin_session_valid("admin-restart-session"))
        reopened = Database(self.path)
        await reopened.check_and_migrate_db()
        self.assertTrue(await reopened.is_admin_session_valid("admin-restart-session"))

    async def test_only_token_hash_is_persisted_and_expiry_is_fixed_utc(self):
        token = "admin-PRIVATE_BROWSER_SESSION_TOKEN"
        now = datetime(2026, 10, 6, 10, 30, tzinfo=timezone.utc)
        with patch("src.core.database.datetime", wraps=datetime) as clock:
            clock.now.return_value = now
            expires_at = await self.db.create_admin_session(token)

        rows = await self.session_rows()
        self.assertEqual(expires_at, now + timedelta(days=30))
        self.assertEqual(rows[0][0], hashlib.sha256(token.encode()).hexdigest())
        self.assertEqual(rows[0][2:], (now.timestamp(), expires_at.timestamp()))
        self.assertEqual(len(rows[0][1]), 64)
        with sqlite3.connect(self.path) as connection:
            self.assertNotIn(token, "\n".join(connection.iterdump()))

    async def test_validations_never_extend_session_expiry(self):
        await self.db.create_admin_session("admin-fixed-expiry", ttl_seconds=60)
        before = await self.session_rows()

        self.assertTrue(await self.db.is_admin_session_valid("admin-fixed-expiry"))
        self.assertTrue(await self.other_worker.is_admin_session_valid("admin-fixed-expiry"))

        self.assertEqual(await self.session_rows(), before)

    async def test_expiry_boundary_and_opportunistic_cleanup(self):
        token = "admin-expiring"
        now = datetime.now(timezone.utc)
        with patch("src.core.database.datetime", wraps=datetime) as clock:
            clock.now.return_value = now
            await self.db.create_admin_session(token, ttl_seconds=10)
            clock.now.return_value = now + timedelta(seconds=9)
            self.assertTrue(await self.db.is_admin_session_valid(token))
            clock.now.return_value = now + timedelta(seconds=10)
            self.assertFalse(await self.other_worker.is_admin_session_valid(token))
            self.assertEqual(len(await self.session_rows()), 1)
            await self.other_worker.create_admin_session("admin-next-session")

        rows = await self.session_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], hashlib.sha256(b"admin-next-session").hexdigest())

    async def test_one_session_revoke_is_visible_to_other_workers(self):
        await self.db.create_admin_session("admin-browser-one")
        await self.db.create_admin_session("admin-browser-two")
        self.assertTrue(await self.other_worker.is_admin_session_valid("admin-browser-one"))

        await self.other_worker.revoke_admin_session("admin-browser-one")

        self.assertFalse(await self.db.is_admin_session_valid("admin-browser-one"))
        self.assertTrue(await self.db.is_admin_session_valid("admin-browser-two"))
        self.assertFalse(await Database(self.path).is_admin_session_valid("admin-browser-one"))

    async def test_all_sessions_revoke_is_visible_to_other_workers(self):
        await self.db.create_admin_session("admin-browser-one")
        await self.other_worker.create_admin_session("admin-browser-two")

        await self.db.revoke_all_admin_sessions()

        self.assertFalse(await self.other_worker.is_admin_session_valid("admin-browser-one"))
        self.assertFalse(await self.other_worker.is_admin_session_valid("admin-browser-two"))
        self.assertEqual(await self.session_rows(), [])

    async def test_unknown_and_malformed_tokens_cannot_authenticate_or_revoke_other_sessions(self):
        await self.db.create_admin_session("admin-valid")
        for token in (None, False, 7, "", " ", " admin-valid", "admin-valid\n", "x" * 1025, "令牌"):
            with self.subTest(token=token):
                self.assertFalse(await self.db.is_admin_session_valid(token))
                await self.db.revoke_admin_session(token)
                with self.assertRaises(ValueError):
                    await self.db.create_admin_session(token)
        self.assertFalse(await self.other_worker.is_admin_session_valid("admin-unknown"))
        await self.other_worker.revoke_admin_session("admin-unknown")
        self.assertTrue(await self.db.is_admin_session_valid("admin-valid"))

    async def test_invalid_session_lifetimes_are_rejected(self):
        for ttl in (0, -1, True, 0.1, "60", None):
            with self.subTest(ttl=ttl), self.assertRaises(ValueError):
                await self.db.create_admin_session("admin-invalid-ttl", ttl_seconds=ttl)
        self.assertEqual(await self.session_rows(), [])

    async def test_validation_does_not_require_a_write_transaction(self):
        await self.db.create_admin_session("admin-read-while-writing")
        async with self.other_worker._connect(write=True) as connection:
            await connection.execute("BEGIN IMMEDIATE")
            self.assertTrue(await asyncio.wait_for(
                self.db.is_admin_session_valid("admin-read-while-writing"), timeout=1
            ))
            await connection.rollback()

    async def test_concurrent_workers_preserve_all_fresh_sessions(self):
        tokens = [f"admin-concurrent-{index}" for index in range(12)]
        await asyncio.gather(*(
            (self.db if index % 2 else self.other_worker).create_admin_session(token)
            for index, token in enumerate(tokens)
        ))

        self.assertEqual(len(await self.session_rows()), len(tokens))
        self.assertTrue(all(await asyncio.gather(*(
            self.other_worker.is_admin_session_valid(token) for token in tokens
        ))))

    async def test_out_of_band_credential_changes_fail_closed(self):
        await self.db.create_admin_session("admin-old-credentials")
        with sqlite3.connect(self.path) as connection:
            connection.execute("UPDATE admin_config SET password = ? WHERE id = 1", ("changed",))

        self.assertFalse(await self.other_worker.is_admin_session_valid("admin-old-credentials"))
        await self.other_worker.create_admin_session("admin-new-credentials")
        self.assertEqual(len(await self.session_rows()), 1)
        self.assertTrue(await self.db.is_admin_session_valid("admin-new-credentials"))

    async def test_password_and_username_updates_revoke_sessions_atomically(self):
        for field in ("password", "username"):
            with self.subTest(field=field):
                previous = getattr(await self.db.get_admin_config(), field)
                await self.db.create_admin_session(f"admin-before-{field}-change")
                await self.other_worker.update_admin_config(**{field: f"changed-{field}"})
                self.assertFalse(await self.db.is_admin_session_valid(f"admin-before-{field}-change"))
                self.assertEqual(await self.session_rows(), [])
                await self.other_worker.update_admin_config(**{field: previous})
                self.assertFalse(await self.db.is_admin_session_valid(f"admin-before-{field}-change"))

    async def test_unrelated_or_unchanged_config_updates_preserve_sessions(self):
        await self.db.create_admin_session("admin-config-change")
        await self.other_worker.update_admin_config(api_key="new-public-api-key")
        await self.other_worker.update_admin_config(username="admin", password="admin")

        self.assertTrue(await self.db.is_admin_session_valid("admin-config-change"))

    async def test_session_creation_rechecks_authenticated_credentials_atomically(self):
        credentials = await self.db.get_admin_config()
        await self.other_worker.update_admin_config(password="new-password")

        with self.assertRaisesRegex(ValueError, "credentials changed"):
            await self.db.create_admin_session(
                "admin-stale-login", expected_credentials=(credentials.username, credentials.password)
            )

        self.assertEqual(await self.session_rows(), [])
        await self.db.create_admin_session(
            "admin-current-login", expected_credentials=(credentials.username, "new-password")
        )
        self.assertTrue(await self.other_worker.is_admin_session_valid("admin-current-login"))

    async def test_missing_admin_configuration_cannot_issue_or_validate_sessions(self):
        await self.db.create_admin_session("admin-removed-config")
        with sqlite3.connect(self.path) as connection:
            connection.execute("DELETE FROM admin_config")

        self.assertFalse(await self.other_worker.is_admin_session_valid("admin-removed-config"))
        with self.assertRaisesRegex(RuntimeError, "not initialized"):
            await self.other_worker.create_admin_session("admin-missing-config")
        self.assertEqual(len(await self.session_rows()), 1)

    async def test_upgrade_creates_session_schema_and_is_idempotent(self):
        with sqlite3.connect(self.path) as connection:
            connection.execute("DROP TABLE admin_sessions")
        await self.db.check_and_migrate_db()
        await self.db.create_admin_session("admin-upgraded-database")

        await self.other_worker.check_and_migrate_db()
        await self.other_worker.init_db()

        self.assertTrue(await self.db.is_admin_session_valid("admin-upgraded-database"))
        self.assertEqual(len(await self.session_rows()), 1)


if __name__ == "__main__":
    unittest.main()
