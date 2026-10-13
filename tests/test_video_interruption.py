"""Accepted video receipts survive disconnects, generator closes and cache cancellation."""

import asyncio
from copy import deepcopy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from src.core.database import Database
from src.core.models import Token, Task, RequestLog
from src.services.concurrency_manager import ConcurrencyManager
from src.services.generation_handler import GenerationHandler
from src.services.submission_ledger import SubmissionLedger


OPERATIONS = [{"operation": {"name": "original-operation"}, "projectId": "original-project",
               "status": "MEDIA_GENERATION_STATUS_ACTIVE", "sceneId": "original-scene"}]
SUBMISSION_ID = "synthetic-original-submission"


class VideoInterruptionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.db = Database(str(Path(directory.name) / "flow.db"))
        await self.db.init_db()
        token_id = await self.db.add_token(Token(st="synthetic", at="synthetic", email="synthetic@example.test",
            video_concurrency=1, user_paygate_tier="PAYGATE_TIER_ONE"))
        self.token = await self.db.get_token(token_id)
        self.ledger = SubmissionLedger(self.db)
        await self.ledger.reserve(SUBMISSION_ID, "original-fingerprint", "omni-1.1-flash-10s-portrait-360p")
        self.handler = GenerationHandler.__new__(GenerationHandler)
        self.handler.db = self.db
        self.handler.proxy_manager = None
        self.handler.flow_client = SimpleNamespace(
            clear_request_fingerprint=Mock(), prefill_remote_browser_pool=AsyncMock(),
            generate_video_text=AsyncMock(return_value={"operations": deepcopy(OPERATIONS)}),
            check_video_status=AsyncMock(),
        )
        self.handler.token_manager = SimpleNamespace(
            ensure_valid_token=AsyncMock(return_value=self.token), ensure_project_exists=AsyncMock(return_value="original-project"),
            record_usage=AsyncMock(), record_success=AsyncMock(), record_error=AsyncMock(),
        )
        self.handler.load_balancer = SimpleNamespace(select_token=AsyncMock(return_value=self.token),
            release_pending=AsyncMock(), record_generation_success=Mock(), record_generation_failure=AsyncMock())
        self.handler.concurrency_manager = ConcurrencyManager()
        await self.handler.concurrency_manager.initialize([self.token])
        self.handler._get_base_url = Mock(return_value="http://offline.test")
        self.config = SimpleNamespace(flow_account_retries=1, flow_video_slot_wait_timeout=1,
            video_timeout=0.35, poll_interval=0.1, cache_enabled=False, captcha_method="browser")
        self.enterContext(patch("src.services.generation_handler.config", self.config))
        self.started = asyncio.Event()

        async def block_poll(*args, **kwargs):
            self.started.set()
            await asyncio.Event().wait()

        self.handler.flow_client.check_video_status.side_effect = block_poll

    async def request_row(self):
        async with self.db._connect() as connection:
            cursor = await connection.execute("SELECT id,status_code,status_text,response_body FROM request_logs ORDER BY id DESC LIMIT 1")
            row = await cursor.fetchone()
            return {"id": row[0], "status_code": row[1], "status_text": row[2], "response": json.loads(row[3])}

    def generate(self):
        return self.handler.handle_generation("omni-1.1-flash-10s-portrait-360p", "original prompt", stream=True,
                                               client_submission_id=SUBMISSION_ID)

    async def collect(self):
        return [part async for part in self.generate()]

    async def assert_pending_preserved(self, reason):
        task = await self.db.get_task("original-operation")
        self.assertEqual(task.status, "status_unknown")
        self.assertIsNone(task.completed_at)
        self.assertEqual((task.prompt, task.scene_id), ("original prompt", "original-scene"))
        row = await self.request_row()
        self.assertEqual((row["status_code"], row["status_text"]), (502, "video_status_unknown"))
        error = row["response"]["error"]
        self.assertEqual(error["reason"], reason)
        self.assertEqual(error["task_id"], "original-operation")
        self.assertTrue(error["submission_pending"])
        self.assertTrue(error["upstream_accepted"])
        receipt = await self.ledger.get(SUBMISSION_ID)
        self.assertEqual((receipt["state"], receipt["operation_id"], receipt["account_id"]),
                         ("pending", "original-operation", self.token.id))
        self.assertEqual(receipt["operations"], OPERATIONS)
        self.assertEqual(receipt["request_hash"], "original-fingerprint")
        self.assertEqual(await self.handler.concurrency_manager.get_video_inflight(self.token.id), 0)
        self.handler.flow_client.generate_video_text.assert_awaited_once()
        self.handler.token_manager.record_error.assert_not_awaited()
        self.handler.token_manager.record_usage.assert_not_awaited()

    async def test_cancel_during_poll_persists_original_pending_receipt_before_releasing_slot(self):
        running = asyncio.create_task(self.collect())
        await asyncio.wait_for(self.started.wait(), 2)
        running.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await running
        await self.assert_pending_preserved("client_disconnected")

    async def test_repeated_cancel_waits_for_durable_cleanup_before_releasing_slot(self):
        cleanup_started = asyncio.Event()
        cleanup_release = asyncio.Event()
        original = self.db.persist_interrupted_video_request

        async def delayed_cleanup(**kwargs):
            cleanup_started.set()
            await cleanup_release.wait()
            return await original(**kwargs)

        with patch.object(self.db, "persist_interrupted_video_request", side_effect=delayed_cleanup):
            running = asyncio.create_task(self.collect())
            await asyncio.wait_for(self.started.wait(), 2)
            running.cancel()
            await asyncio.wait_for(cleanup_started.wait(), 2)
            running.cancel()
            await asyncio.sleep(0)
            self.assertEqual(await self.handler.concurrency_manager.get_video_inflight(self.token.id), 1)
            cleanup_release.set()
            with self.assertRaises(asyncio.CancelledError):
                await running
        await self.assert_pending_preserved("client_disconnected")

    async def test_generator_close_immediately_after_receipt_clears_102_log(self):
        generator = self.generate()
        async for chunk in generator:
            if chunk.startswith("data: ") and "\"submission\"" in chunk:
                break
        await generator.aclose()
        await self.assert_pending_preserved("generator_closed")
        self.handler.flow_client.check_video_status.assert_not_awaited()

    async def test_close_after_poll_error_keeps_original_poll_diagnostic(self):
        self.handler.flow_client.check_video_status.side_effect = RuntimeError("rpc=jwpduf code=401")
        generator = self.generate()
        async for chunk in generator:
            if "\"code\": \"video_status_unknown\"" in chunk:
                break
        await generator.aclose()
        await self.assert_pending_preserved("poll_auth_failed")

    async def test_cancel_during_task_creation_restores_task_and_original_receipt(self):
        async def interrupted_create(task):
            self.started.set()
            await asyncio.Event().wait()

        with patch.object(self.db, "create_task", AsyncMock(side_effect=interrupted_create)):
            running = asyncio.create_task(self.collect())
            await asyncio.wait_for(self.started.wait(), 2)
            running.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await running
        await self.assert_pending_preserved("client_disconnected")

    async def test_cancel_during_receipt_write_fills_only_original_pending_binding(self):
        async def interrupted_accept(*args, **kwargs):
            self.started.set()
            await asyncio.Event().wait()

        with patch.object(SubmissionLedger, "accepted", AsyncMock(side_effect=interrupted_accept)):
            running = asyncio.create_task(self.collect())
            await asyncio.wait_for(self.started.wait(), 2)
            running.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await running
        await self.assert_pending_preserved("client_disconnected")

    async def prepare_successful_poll(self):
        self.handler.flow_client.check_video_status.side_effect = None
        self.handler.flow_client.check_video_status.return_value = {"operations": [{
            "operation": {"name": "original-operation"}, "status": "MEDIA_GENERATION_STATUS_SUCCESSFUL"}]}
        self.handler._resolve_video_asset = AsyncMock(return_value={"video_url": "https://offline.test/result.mp4",
            "video_media_id": "original-media", "aspect_ratio": "portrait", "media_name": "original-media",
            "metadata": {}, "video_info": {}, "model": "model", "duration": 10})

    async def test_cancel_during_cache_does_not_mark_accepted_video_failed(self):
        await self.prepare_successful_poll()
        self.config.cache_enabled = True

        async def cache(*args):
            self.started.set()
            await asyncio.Event().wait()

        self.handler.file_cache = SimpleNamespace(download_and_cache=AsyncMock(side_effect=cache))
        running = asyncio.create_task(self.collect())
        await asyncio.wait_for(self.started.wait(), 2)
        running.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await running
        await self.assert_pending_preserved("client_disconnected")

    async def test_close_after_completed_video_preserves_result_and_finishes_log(self):
        await self.prepare_successful_poll()
        generator = self.generate()
        async for chunk in generator:
            if "<video src=" in chunk:
                await self.ledger.capture(SUBMISSION_ID, {"choices": [{"delta": {"content": "<video src='https://offline.test/result.mp4'>"}}]})
                break
        receipt_before = await self.ledger.get(SUBMISSION_ID)
        await generator.aclose()
        task = await self.db.get_task("original-operation")
        self.assertEqual(task.status, "completed")
        self.assertEqual(task.result_urls, ["https://offline.test/result.mp4"])
        row = await self.request_row()
        self.assertEqual((row["status_code"], row["status_text"]), (200, "completed"))
        self.assertEqual(await self.ledger.get(SUBMISSION_ID), receipt_before)
        self.handler.flow_client.generate_video_text.assert_awaited_once()


class InterruptedVideoTransactionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.db = Database(str(Path(directory.name) / "flow.db"))
        await self.db.init_db()
        self.token_id = await self.db.add_token(Token(st="synthetic", email="synthetic@example.test"))
        await self.db.create_task(Task(task_id="original-operation", token_id=self.token_id, model="model", prompt="prompt", status="processing"))
        self.log_id = await self.db.add_request_log(RequestLog(token_id=self.token_id, operation="generate_video",
            request_body="{}", response_body="{}", status_code=102, status_text="video_polling", progress=45, duration=0))
        self.ledger = SubmissionLedger(self.db)
        await self.ledger.reserve(SUBMISSION_ID, "original-fingerprint")
        await self.ledger.accepted(SUBMISSION_ID, self.token_id, "original-project", OPERATIONS)
        self.payload = {"message": "original accepted observation interrupted", "code": "video_status_unknown",
                        "submission_pending": True, "upstream_accepted": True, "task_id": "original-operation"}

    async def persist(self, **updates):
        args = dict(task_id="original-operation", token_id=self.token_id, log_id=self.log_id, payload=self.payload,
            client_submission_id=SUBMISSION_ID, project_id="original-project", operations=OPERATIONS)
        args.update(updates)
        return await self.db.persist_interrupted_video_request(**args)

    async def test_all_terminal_task_and_ledger_states_are_preserved(self):
        for task_status in ("completed", "failed", "success", "error", "cancelled", "canceled", "future_unknown_state"):
            await self.db.update_task("original-operation", status=task_status, result_urls=["https://offline.test/saved.mp4"],
                                      error_message="saved error", completed_at=123)
            for state in ("confirmed", "failed", "refused"):
                with self.subTest(task_status=task_status, ledger_state=state):
                    await self.ledger.update(SUBMISSION_ID, state=state, video_url="https://offline.test/saved.mp4", error={"code": "saved"})
                    before_task = await self.db.get_task("original-operation")
                    before_receipt = await self.ledger.get(SUBMISSION_ID)
                    self.assertEqual(await self.persist(), "receipt_terminal" if state == "refused" else task_status)
                    self.assertEqual(await self.db.get_task("original-operation"), before_task)
                    self.assertEqual(await self.ledger.get(SUBMISSION_ID), before_receipt)

    async def test_pending_ledger_original_operation_snapshot_is_never_overwritten(self):
        original = deepcopy(OPERATIONS)
        original[0]["saved_extension"] = "original durable evidence"
        await self.ledger.update(SUBMISSION_ID, operations=original)
        await self.persist()
        self.assertEqual((await self.ledger.get(SUBMISSION_ID))["operations"], original)

    async def test_confirmed_receipt_finishes_processing_task_and_102_log_without_downgrade(self):
        await self.ledger.update(SUBMISSION_ID, state="confirmed", video_url="https://offline.test/confirmed.mp4", error=None)
        before_receipt = await self.ledger.get(SUBMISSION_ID)
        self.assertEqual(await self.persist(), "completed")
        task = await self.db.get_task("original-operation")
        self.assertEqual(task.status, "completed")
        self.assertEqual(task.result_urls, ["https://offline.test/confirmed.mp4"])
        async with self.db._connect() as connection:
            cursor = await connection.execute("SELECT status_code,status_text FROM request_logs WHERE id=?", (self.log_id,))
            self.assertEqual(tuple(await cursor.fetchone()), (200, "completed"))
        self.assertEqual(await self.ledger.get(SUBMISSION_ID), before_receipt)

    async def test_proven_failed_receipt_finishes_processing_task_without_changing_receipt(self):
        await self.ledger.update(SUBMISSION_ID, state="failed", error={"code": "video_generation_failed",
            "message": "confirmed upstream failure", "submission_pending": False, "upstream_accepted": True})
        before_receipt = await self.ledger.get(SUBMISSION_ID)
        self.assertEqual(await self.persist(), "failed")
        self.assertEqual((await self.db.get_task("original-operation")).status, "failed")
        async with self.db._connect() as connection:
            cursor = await connection.execute("SELECT status_code,status_text FROM request_logs WHERE id=?", (self.log_id,))
            self.assertEqual(tuple(await cursor.fetchone()), (502, "failed"))
        self.assertEqual(await self.ledger.get(SUBMISSION_ID), before_receipt)

    async def test_refused_or_unproven_terminal_receipt_is_left_intact_without_unknown_task(self):
        for state, error in (("refused", {"code": "submission_not_started"}), ("failed", {"code": "generic_local_failure"}),
                             ("confirmed", None)):
            await self.ledger.update(SUBMISSION_ID, state=state, video_url=None, error=error)
            before_task = await self.db.get_task("original-operation")
            before_receipt = await self.ledger.get(SUBMISSION_ID)
            self.assertEqual(await self.persist(), "receipt_terminal")
            self.assertEqual(await self.db.get_task("original-operation"), before_task)
            self.assertEqual(await self.ledger.get(SUBMISSION_ID), before_receipt)

    async def test_completed_and_failed_request_logs_keep_their_original_response(self):
        for code, text in ((200, "completed"), (502, "failed")):
            await self.db.update_request_log(self.log_id, status_code=code, status_text=text, response_body="{\"original\":true}")
            await self.persist()
            async with self.db._connect() as connection:
                cursor = await connection.execute("SELECT status_code,status_text,response_body FROM request_logs WHERE id=?", (self.log_id,))
                self.assertEqual(tuple(await cursor.fetchone()), (code, text, '{"original":true}'))

    async def test_receipt_bound_to_another_operation_or_account_is_never_updated(self):
        for update in ({"operation_id": "another-operation"}, {"account_id": self.token_id + 1}):
            await self.ledger.update(SUBMISSION_ID, **update)
            before = await self.ledger.get(SUBMISSION_ID)
            await self.persist()
            self.assertEqual(await self.ledger.get(SUBMISSION_ID), before)

    async def test_missing_task_without_receipt_metadata_or_mismatched_operation_fails_closed(self):
        before = await self.ledger.get(SUBMISSION_ID)
        self.assertEqual(await self.persist(task_id="missing-operation", operations=[{"name": "missing-operation"}]), "binding_mismatch")
        self.assertEqual(await self.persist(operations=[{"name": "another-operation"}]), "binding_mismatch")
        self.assertEqual(await self.ledger.get(SUBMISSION_ID), before)


if __name__ == "__main__":
    unittest.main()
