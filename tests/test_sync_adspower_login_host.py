"""Offline host proof tests; synthetic cookies, browser leases and identity only."""
import contextlib
import copy
import asyncio
import importlib.util
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import AsyncMock, Mock, patch

from src.core.account_admission import AccountAdmission, AccountAdmissionBusy


ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "local" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


host = load("offline_login_host", "sync_adspower_login_host.py")
sync = load("offline_login_host_sync", "sync_adspower_cookies.py")


def cookies():
    return [{"name": name, "value": "SYNTHETIC_" + name, "domain": ".google.com",
             "path": "/", "secure": True, "expires": 2000000000,
             "httpOnly": True, "sameSite": "None"}
            for name in ("SID", "SAPISID", "SIDCC", "__Secure-1PSIDCC", "__Secure-3PSIDCC", "NID")]


def renewed(value):
    result = copy.deepcopy(value)
    for cookie in result:
        if cookie["name"] in {"SIDCC", "__Secure-1PSIDCC", "__Secure-3PSIDCC"}:
            cookie["value"] += "_RENEWED"
            cookie["expires"] += 30
    return result


def proof(value=None, **updates):
    value = value if value is not None else cookies()
    result = {"ok": True, "code": "login_verified", "credits": 40,
              "verified_cookie_hash": sync.auth_hash(value),
              "verified_session_hash": sync.auth_session_hash(value),
              "verified_proxy_hash": sync.validation_proxy_hash("http://proxy.example.test:80")}
    result.update(updates)
    return result


class HostProofTests(unittest.TestCase):
    def test_legacy_proof_still_requires_the_exact_full_cookie_hash(self):
        value = proof()
        value.pop("verified_session_hash")
        self.assertEqual(host._verified_outcome(value, value["verified_cookie_hash"],
                                               value["verified_proxy_hash"]), 40)
        with self.assertRaises(host.LoginError) as raised:
            host._verified_outcome(value, "a" * 64, value["verified_proxy_hash"])
        self.assertEqual(raised.exception.code, "login_worker_failed")

    def test_production_proof_accepts_a_renewed_exact_snapshot_for_the_same_session(self):
        original = cookies()
        value = proof(renewed(original))
        self.assertNotEqual(value["verified_cookie_hash"], sync.auth_hash(original))
        self.assertEqual(host._verified_outcome(value, sync.auth_hash(original),
            value["verified_proxy_hash"], sync.auth_session_hash(original)), 40)

    def test_production_proof_requires_well_formed_hashes_and_the_same_session_and_proxy(self):
        original = cookies()
        for change in ({"verified_cookie_hash": "PRIVATE_COOKIE"},
                       {"verified_session_hash": "PRIVATE_COOKIE"},
                       {"verified_session_hash": "f" * 64},
                       {"verified_proxy_hash": "f" * 64},
                       {"verified_session_hash": None}):
            with self.subTest(change=change), self.assertRaises(host.LoginError) as raised:
                host._verified_outcome(proof(**change), sync.auth_hash(original),
                    sync.validation_proxy_hash("http://proxy.example.test:80"), sync.auth_session_hash(original))
            self.assertEqual(raised.exception.code, "login_worker_failed")
        value = proof()
        value.pop("verified_session_hash")
        with self.assertRaises(host.LoginError):
            host._verified_outcome(value, sync.auth_hash(original), value["verified_proxy_hash"],
                                   sync.auth_session_hash(original))

    def test_proof_failure_does_not_become_a_success_or_echo_private_data(self):
        with self.assertRaises(host.LoginError) as raised:
            host._verified_outcome({"ok": False, "code": "login_identity_mismatch"},
                                   "a" * 64, "b" * 64, "c" * 64)
        self.assertEqual(raised.exception.code, "login_identity_mismatch")
        self.assertNotIn("PRIVATE", str(raised.exception))


class HostBusyTests(unittest.TestCase):
    def snapshot(self, *, tasks=(), leases=(), waiting=()):
        return {"queue": {"mode": "accepting"}, "board": {
            "leases": list(leases), "waiting": list(waiting)}, "tasks": list(tasks)}

    def assert_rejected(self, snapshot, code, **ownership):
        with self.assertRaises(host.LoginError) as raised:
            host._spark_idle(snapshot, **ownership)
        self.assertEqual(raised.exception.code, code)

    def test_paused_draining_stopped_and_legacy_paused_queues_are_rejected(self):
        for queue in ({'mode': 'paused'}, {'mode': 'draining'}, {'mode': 'stopped'},
                      {'mode': 'accepting', 'processing_paused': True}):
            with self.subTest(queue=queue):
                snapshot = self.snapshot()
                snapshot['queue'] = queue
                self.assert_rejected(snapshot, 'queue_paused')

    def test_unknown_admission_modes_and_nonboolean_pause_values_are_rejected(self):
        for queue in ({}, {'mode': 'unknown'}, {'mode': None},
                      {'mode': 'accepting', 'processing_paused': 'false'},
                      {'mode': 'accepting', 'processing_paused': 0}):
            with self.subTest(queue=queue):
                snapshot = self.snapshot()
                snapshot['queue'] = queue
                self.assert_rejected(snapshot, 'busy_state_unknown')

    def test_malformed_snapshot_components_are_rejected(self):
        for snapshot in (None, [], {'queue': [], 'board': {}, 'tasks': []},
                         {'queue': {'mode': 'accepting'}, 'board': [], 'tasks': []},
                         {'queue': {'mode': 'accepting'}, 'board': {'leases': [], 'waiting': []}, 'tasks': {}},
                         {'queue': {'mode': 'accepting'}, 'board': {'leases': [], 'waiting': None}, 'tasks': []}):
            with self.subTest(snapshot=snapshot):
                self.assert_rejected(snapshot, 'busy_state_unknown')

    def test_active_frames_and_flow2api_video_orchestration_allow_idle_browser_recovery(self):
        for status in sync.ACTIVE:
            with self.subTest(status=status):
                snapshot = self.snapshot(tasks=[
                    {"task_id": "frames", "status": status,
                     "dimensions": {"type": "frames", "userId": "one"}},
                    {"task_id": "video", "status": status,
                     "dimensions": {"type": "videos", "video_provider": "flow2api"}},
                ])
                host._spark_idle(snapshot)

    def test_exact_own_lease_and_running_login_record_allow_orchestration_tasks(self):
        for state in ("running", "stalled"):
            with self.subTest(state=state):
                snapshot = self.snapshot(
                    leases=[{"task_id": "own-lease", "kind": "auto_login", "user_id": "one", "state": state}],
                    tasks=[{"task_id": "own-record", "status": "running", "maintenance": "cookie_login",
                            "profile_id": "one"},
                           {"task_id": "video", "status": "running",
                            "dimensions": {"type": "videos", "video_provider": "flow2api"}}])
                host._spark_idle(snapshot, own_task_id="own-lease", profile_id="one", own_record_id="own-record")

    def test_every_other_lease_or_waiter_still_blocks_even_for_other_profiles(self):
        for lease in (
                {"task_id": "generation", "kind": "video", "user_id": "one", "state": "running"},
                {"task_id": "other-profile", "kind": "auto_login", "user_id": "other", "state": "running"},
                {"task_id": "cancelled-worker", "kind": "frames", "user_id": "other", "state": "force_released"}):
            with self.subTest(lease=lease):
                self.assert_rejected(self.snapshot(leases=[lease]), "generation_busy")
        for waiter in ({"task_id": "generation"}, {"task_id": "other", "user_id": "other"}):
            with self.subTest(waiter=waiter):
                self.assert_rejected(self.snapshot(waiting=[waiter]), "generation_busy")

    def test_own_lease_identity_kind_count_and_cancellation_remain_strict(self):
        lease = {"task_id": "own", "kind": "auto_login", "user_id": "one", "state": "running"}
        for leases in ([], [lease, lease], [dict(lease, kind="generation")],
                       [dict(lease, user_id="other")], [dict(lease, state="unknown")]):
            with self.subTest(leases=leases):
                self.assert_rejected(self.snapshot(leases=leases), "busy_state_unknown",
                                     own_task_id="own", profile_id="one")
        self.assert_rejected(self.snapshot(leases=[dict(lease, state="force_released")]), "login_cancelled",
                             own_task_id="own", profile_id="one")
        self.assert_rejected(self.snapshot(leases=[lease, dict(lease, task_id="other")]), "generation_busy",
                             own_task_id="own", profile_id="one")
        self.assert_rejected(self.snapshot(leases=[lease], waiting=[{"task_id": "other"}]), "generation_busy",
                             own_task_id="own", profile_id="one")

    def test_own_login_record_identity_count_and_cancellation_remain_strict(self):
        record = {"task_id": "own-record", "status": "running", "maintenance": "cookie_login", "profile_id": "one"}
        for tasks in ([], [record, record], [dict(record, maintenance="generation")],
                      [dict(record, profile_id="other")]):
            with self.subTest(tasks=tasks):
                self.assert_rejected(self.snapshot(tasks=tasks), "busy_state_unknown",
                                     own_record_id="own-record", profile_id="one")
        for updates in ({"status": "cancelled"}, {"status": "completed"}, {"cancelled": True}):
            with self.subTest(updates=updates):
                self.assert_rejected(self.snapshot(tasks=[dict(record, **updates)]), "login_cancelled",
                                     own_record_id="own-record", profile_id="one")

    def test_unrecognized_task_status_and_incomplete_snapshot_are_rejected(self):
        frames = {"task_id": "frames", "status": "running", "dimensions": {"type": "frames"}}
        for unknown in ({"task_id": "unknown", "status": "new_unknown_status"},
                        {"task_id": "unknown"}, {"task_id": "unknown", "status": None}):
            with self.subTest(unknown=unknown):
                self.assert_rejected(self.snapshot(tasks=[frames, unknown]), "busy_state_unknown")
        for snapshot in ({}, {"queue": {"mode": "accepting"}, "board": {"leases": []}, "tasks": []}):
            with self.subTest(snapshot=snapshot):
                self.assert_rejected(snapshot, "busy_state_unknown")

    def test_other_active_cookie_login_blocks_before_acquiring_a_browser_lease(self):
        for marker in ({"maintenance": "cookie_login"}, {"_cookie_login": True},
                       {"task_id": "cookie_login_other"}, {"id": "cookie_login_other"},
                       {"dimensions": {"type": "auto_login"}}):
            for status in sync.ACTIVE:
                with self.subTest(marker=marker, status=status):
                    task = dict({"task_id": "other", "status": status, "profile_id": "other"}, **marker)
                    self.assert_rejected(self.snapshot(tasks=[task]), "generation_busy")


class HostErrorMappingTests(unittest.IsolatedAsyncioTestCase):
    async def test_sync_inventory_errors_return_the_safe_unknown_busy_contract(self):
        request = {'profile_id': 'one', 'expected_email': 'owner@example.test', 'token_id': 2}
        for reason in ('spark_inventory_incomplete', 'spark_task_state_unknown',
                       'spark_lease_inventory_invalid', 'flow_busy_check_unavailable'):
            with self.subTest(reason=reason), \
                 patch.object(host, '_module', side_effect=[sync, types.SimpleNamespace()]), \
                 patch.object(host, '_configured', side_effect=sync.SyncError(reason)), \
                 patch.object(host, '_audit_host'):
                payload, status = await host.handle_login_sync(
                    request, slot_factory=lambda *_args, **_kwargs: self.fail('A lease must not be acquired'),
                    spark_snapshot=lambda: self.fail('No browser snapshot should be needed'))
                self.assertEqual(status, 409)
                self.assertEqual(payload, {'status': 'deferred', 'code': 'busy_state_unknown'})


class HostAdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.path = self.root / 'local/account.json'
        self.path.parent.mkdir()
        self.config = sync.validate_config({'profile_id': 'one', 'expected_email': 'owner@example.test',
            'token_id': 7, 'adspower_base': 'http://127.0.0.1:50325', 'flow_base': 'http://127.0.0.1:38000',
            'flow_db_path': str(self.root / 'data/flow.db')})
        sync.save_private(self.path, self.config)
        sync.save_private(self.path.with_name('account.state.json'), {})
        sync.save_private(self.root / 'local/credentials.json', {'username': 'SYNTHETIC', 'password': 'SYNTHETIC'})
        self.admission = AccountAdmission(self.config['flow_db_path'])
        self.login = AsyncMock(return_value=({'status': 'ok', 'code': 'login_verified', 'credits': 40}, 200))
        self.enterContext(patch.object(host, '_module', side_effect=lambda name, _path:
            sync if name == '_login_sync' else types.SimpleNamespace(_read_private=sync.private_json)))
        self.enterContext(patch.object(host, '_configured', return_value=(self.path, self.config)))
        self.enterContext(patch.object(host, '_audit_host'))
        self.enterContext(patch.object(host, '_login', self.login))

    async def run_host(self, capability=None):
        request = {'profile_id': 'one', 'expected_email': 'owner@example.test', 'token_id': 7}
        if capability is not None:
            request['maintenance_capability'] = capability
        return await host.handle_login_sync(request, flow_root=self.root,
            slot_factory=lambda *_args, **_kwargs: self.fail('Injected login must not touch a browser'),
            spark_snapshot=lambda: self.fail('Injected login must not inspect live tasks'))

    async def test_generation_inflight_rejects_host_before_login_and_releases_no_other_owner(self):
        with self.admission.generation(7):
            payload, status = await self.run_host()
            self.assertEqual((payload, status), ({'status': 'deferred', 'code': 'generation_busy'}, 409))
            self.login.assert_not_awaited()
            with self.assertRaises(AccountAdmissionBusy):
                self.admission.maintenance(7)
        with self.admission.generation(7):
            pass

    async def test_standalone_and_delegated_host_hold_worker_admission_and_forward_its_fd(self):
        async def login(*args):
            with self.assertRaises(AccountAdmissionBusy):
                self.admission.generation(7)
            await args[9]({}, AsyncMock())
            await args[13]({}, AsyncMock())
            for call in (worker.await_args, verify.await_args):
                self.assertEqual(len(call.kwargs['pass_fds']), 1)
                import os
                os.fstat(call.kwargs['pass_fds'][0])
            self.assertEqual(worker.await_args.kwargs['pass_fds'], verify.await_args.kwargs['pass_fds'])
            return {'status': 'ok', 'code': 'login_verified', 'credits': 40}, 200

        self.login.side_effect = login
        for delegated in (False, True):
            with self.subTest(delegated=delegated), \
                 patch.object(host, '_worker', AsyncMock(return_value={'ok': True, 'code': 'already_logged_in'})) as worker, \
                 patch.object(host, '_verify', AsyncMock(return_value=proof())) as verify:
                owner = self.admission.maintenance(7) if delegated else contextlib.nullcontext()
                with owner as lease:
                    payload, status = await self.run_host(lease.capability if delegated else None)
                    self.assertEqual(status, 200)
                    self.assertNotIn('maintenance_capability', payload)
                    if delegated:
                        with self.admission.worker(7, lease.capability):
                            pass
                with self.admission.generation(7):
                    pass

    async def test_forged_or_expired_capability_never_enters_login_or_leaks_the_worker_lock(self):
        for live_owner in (False, True):
            with self.subTest(live_owner=live_owner):
                owner = self.admission.maintenance(7) if live_owner else contextlib.nullcontext()
                with owner:
                    payload, status = await self.run_host('f' * 64)
                    self.assertEqual((payload, status), ({'status': 'deferred', 'code': 'busy_state_unknown'}, 409))
                    self.login.assert_not_awaited()
                with self.admission.generation(7):
                    pass

    def test_optional_capability_keeps_fixed_binding_fields_and_rejects_malformed_requests(self):
        request = {'profile_id': 'one', 'expected_email': 'owner@example.test', 'token_id': 7}
        self.assertEqual(host._request(dict(request, maintenance_capability='c' * 64)),
                         dict(request, maintenance_capability='c' * 64))
        self.assertEqual(host.REQUEST_FIELDS, {'profile_id', 'expected_email', 'token_id'})
        for value in (None, 7, 'c' * 63, 'C' * 64, ['PRIVATE']):
            with self.subTest(value=value), self.assertRaises(host.LoginError) as raised:
                host._request(dict(request, maintenance_capability=value))
            self.assertEqual(raised.exception.code, 'invalid_login_request')
        with self.assertRaises(host.LoginError):
            host._request(dict(request, unrecognized='PRIVATE'))

    async def test_default_worker_and_verifier_forward_admission_descriptors_to_the_child(self):
        check = AsyncMock()
        with patch.object(host, '_child_json', AsyncMock(return_value=({'ok': True, 'code': 'already_logged_in'}, 0))) as child:
            await host._worker({}, check, flow_root=self.root, pass_fds=(97,))
            self.assertEqual(child.await_args.kwargs['pass_fds'], (97,))
        with patch.object(host, '_child_json', AsyncMock(return_value=({'ok': True}, 0))) as child:
            await host._verify({}, check, flow_root=self.root, pass_fds=(98,))
            self.assertEqual(child.await_args.kwargs['pass_fds'], (98,))

    async def test_child_spawn_inherits_only_the_worker_admission_descriptor(self):
        python = self.root / '.venv/bin/python'
        python.parent.mkdir(parents=True)
        python.touch()
        worker = self.root / 'local/synthetic-worker.py'
        worker.write_text('# synthetic offline worker')
        process = types.SimpleNamespace(returncode=0, stdin=types.SimpleNamespace(
            write=Mock(), drain=AsyncMock(), close=Mock()),
            stdout=types.SimpleNamespace(read=AsyncMock(side_effect=[b'{"ok":true}', b''])))
        with self.admission.maintenance(7) as owner, self.admission.worker(7, owner.capability) as lease, \
             patch.object(host.asyncio, 'create_subprocess_exec', AsyncMock(return_value=process)) as spawn:
            result, status = await host._child_json('synthetic-worker.py', {}, AsyncMock(),
                flow_root=self.root, pass_fds=lease.pass_fds)
            self.assertEqual((result, status), ({'ok': True}, 0))
            self.assertEqual(spawn.await_args.kwargs['pass_fds'], (lease.fd,))
            self.assertNotIn(owner.fd, spawn.await_args.kwargs['pass_fds'])


class HostSessionTests(unittest.IsolatedAsyncioTestCase):
    async def execute(self, *, worker_cookies=None, final_cookies=None, final_profile=None,
                      final_token=None, busy_after_verify=False, offline=False, orchestration_running=False,
                      initially_saved=False, start_result=None, became_live_before_start=False,
                      prior_owner_hash=None, stale_prior_owner=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "one.json"
            config = sync.validate_config({"profile_id": "one", "expected_email": "owner@example.test", "token_id": 2,
                "adspower_base": "http://127.0.0.1:50325", "flow_base": "http://127.0.0.1:38000"})
            proxy = "http://proxy.example.test:80"
            state = {"token_id": 2, "proxy_hash": sync.digest(sync.proxy_identity(proxy))}
            sync.save_private(path.with_name("one.state.json"), state)
            token = {"id": 2, "email": "owner@example.test", "login_account": "owner@example.test",
                     "remark": "adspower-sync:one", "proxy_url": proxy, "captcha_proxy_url": proxy,
                     "st": "SYNTHETIC_DB_SESSION"}
            profile = {"source": "cdp", "ws": "ws://127.0.0.1:9222/devtools/browser/test", "proxy": proxy}
            if prior_owner_hash is not None:
                owner = sync.recovery_browser_owner(config, prior_owner_hash)
                if stale_prior_owner:
                    owner["config_hash"] = "f" * 64
                sync.save_private(sync.recovery_browser_owner_path(path), owner)
            parent_cookies = cookies()
            verified_cookies = worker_cookies if worker_cookies is not None else parent_cookies
            current_cookies = final_cookies if final_cookies is not None else verified_cookies
            current_profile = dict(profile, **(final_profile or {}))
            current_token = dict(token, **(final_token or {}))
            saved_profile = dict(profile, source="saved", ws="saved:one")
            needs_start = initially_saved and not became_live_before_start
            profile_reads = ([saved_profile, saved_profile, profile, profile, current_profile]
                             if needs_start else
                             [saved_profile if initially_saved else profile, profile, profile, current_profile])
            startup = (start_result if start_result is not None else
                       {"code": 0, "data": {"ws": {"puppeteer": profile["ws"]}}})
            gateway = types.SimpleNamespace(
                profile=AsyncMock(side_effect=profile_reads),
                tokens=AsyncMock(side_effect=[[token], [token], [token], [current_token]]),
                cookies=AsyncMock(side_effect=[parent_cookies, current_cookies]),
                _profile_request=AsyncMock(return_value=startup))
            board = {"leases": [], "waiting": []}

            @contextlib.contextmanager
            def slot(*_args, **_kwargs):
                board["leases"] = [{"task_id": "own", "kind": "auto_login", "user_id": "one", "state": "running"}]
                try:
                    yield
                finally:
                    board["leases"] = []

            async def verify(payload, check):
                self.assertEqual(payload, {"ws_url": profile["ws"], "expected_email": config["expected_email"],
                                           "proxy_url": proxy})
                await check()
                if busy_after_verify:
                    board["waiting"].append({"task_id": "generation"})
                return proof(verified_cookies)

            async def validator(value, expected_email, authorized_proxy):
                self.assertIs(value, parent_cookies)
                self.assertEqual((expected_email, authorized_proxy), (config["expected_email"], proxy))
                return {"email": expected_email, "credits": 40}

            presence = lambda: {"one": {"user_id": "one", "email": config["expected_email"],
                "has_password": True, "auto_login_blocked": False}}
            login_worker = AsyncMock(return_value={"ok": True, "code": "already_logged_in"})
            verify_runner = AsyncMock(side_effect=verify)
            tasks = ([{"task_id": "frames", "status": "running",
                       "dimensions": {"type": "frames", "userId": "one"}},
                      {"task_id": "video", "status": "running",
                       "dimensions": {"type": "videos", "video_provider": "flow2api"}}]
                     if orchestration_running else [])
            try:
                with patch.object(host, "_configured", return_value=(path, config)), \
                     patch.object(host, "_audit_host"), patch.object(sync, "flow_busy", return_value=False):
                    result = await host._login_reserved(config, path, config, state, sync,
                        types.SimpleNamespace(_read_private=sync.private_json), gateway, slot,
                        lambda: {"queue": {"mode": "accepting"}, "board": board, "tasks": tasks},
                        login_worker, validator if offline else None, root, presence, verify_runner, "own", False)
            finally:
                # The host proves ownership for the post-commit caller. It must
                # leave the source alive for the following credential sync.
                if needs_start:
                    self.assertEqual(gateway._profile_request.await_count, 1)
                    gateway._profile_request.assert_awaited_once_with(
                        "/api/v1/browser/start", params={"user_id": "one"})
                else:
                    gateway._profile_request.assert_not_awaited()
            self.assertEqual(login_worker.await_count, 1)
            self.assertEqual(verify_runner.await_count, 0 if offline else 1)
            self.assertEqual(board, {"leases": [], "waiting": []})
            return result

    async def test_reused_live_browser_never_receives_recovery_close_ownership(self):
        result, status = await self.execute()
        self.assertEqual(status, 200)
        self.assertNotIn("opened_browser_hash", result)

    async def test_host_started_browser_proof_contains_only_its_endpoint_hash_and_stays_open(self):
        result, status = await self.execute(initially_saved=True)
        self.assertEqual(status, 200)
        self.assertEqual(result["opened_browser_hash"],
                         sync.digest("ws://127.0.0.1:9222/devtools/browser/test"))
        self.assertNotIn("ws://", repr(result))
        self.assertNotIn("SYNTHETIC", repr(result))

    async def test_browser_already_live_when_slot_is_granted_is_preserved_without_ownership(self):
        result, status = await self.execute(initially_saved=True, became_live_before_start=True)
        self.assertEqual(status, 200)
        self.assertNotIn("opened_browser_hash", result)

    async def test_retry_on_the_previously_auto_opened_instance_retains_close_ownership(self):
        endpoint_hash = sync.digest("ws://127.0.0.1:9222/devtools/browser/test")
        result, status = await self.execute(prior_owner_hash=endpoint_hash)
        self.assertEqual(status, 200)
        self.assertEqual(result["opened_browser_hash"], endpoint_hash)
        self.assertNotIn("ws://", repr(result))

    async def test_stale_or_different_instance_ownership_does_not_adopt_an_existing_browser(self):
        endpoint_hash = sync.digest("ws://127.0.0.1:9222/devtools/browser/test")
        for options in ({"prior_owner_hash": "e" * 64},
                        {"prior_owner_hash": endpoint_hash, "stale_prior_owner": True}):
            with self.subTest(options=options):
                result, status = await self.execute(**options)
                self.assertEqual(status, 200)
                self.assertNotIn("opened_browser_hash", result)

    async def test_failed_started_browser_verification_does_not_produce_close_ownership(self):
        changed = cookies()
        changed[0]["value"] += "_DIFFERENT_SESSION"
        with self.assertRaises(host.LoginError) as raised:
            await self.execute(initially_saved=True, final_cookies=changed)
        self.assertEqual((raised.exception.code, raised.exception.audit_stage),
                         ("login_binding_mismatch", "cookie_read"))
        self.assertFalse(hasattr(raised.exception, "opened_browser_hash"))

    async def test_failed_browser_start_does_not_produce_close_ownership_or_stop_an_environment(self):
        with self.assertRaises(host.LoginError) as raised:
            await self.execute(initially_saved=True, start_result={"code": 1})
        self.assertEqual(raised.exception.code, "login_browser_unavailable")
        self.assertFalse(hasattr(raised.exception, "opened_browser_hash"))

    async def test_live_login_recovery_succeeds_while_frames_and_flow2api_orchestration_run(self):
        result, status = await self.execute(orchestration_running=True)
        self.assertEqual((status, result["code"]), (200, "login_verified"))
        self.assertEqual(result["verified_session_hash"], sync.auth_session_hash(cookies()))

    async def test_sidcc_renewal_between_all_three_live_snapshots_succeeds_once(self):
        worker_cookies = renewed(cookies())
        final_cookies = renewed(worker_cookies)
        result, status = await self.execute(worker_cookies=worker_cookies, final_cookies=final_cookies)
        self.assertEqual(status, 200)
        self.assertEqual(result["code"], "login_verified")
        self.assertEqual(result["verified_cookie_hash"], sync.auth_hash(worker_cookies))
        self.assertNotEqual(result["verified_cookie_hash"], sync.auth_hash(final_cookies))
        self.assertEqual(result["verified_session_hash"], sync.auth_session_hash(final_cookies))
        self.assertNotIn("SYNTHETIC", repr(result))

    async def test_offline_identity_seam_has_the_same_session_renewal_rule(self):
        result, status = await self.execute(final_cookies=renewed(cookies()), offline=True)
        self.assertEqual(status, 200)
        self.assertEqual(result["verified_session_hash"], sync.auth_session_hash(cookies()))

    async def test_a_different_verified_session_is_rejected_before_final_acceptance(self):
        value = renewed(cookies())
        value[0]["value"] += "_DIFFERENT_ACCOUNT_SESSION"
        with self.assertRaises(host.LoginError) as raised:
            await self.execute(worker_cookies=value)
        self.assertEqual((raised.exception.code, raised.exception.audit_stage),
                         ("login_worker_failed", "identity_verify"))

    async def test_nonrenewing_cookie_and_metadata_changes_remain_strict(self):
        changes = [(0, "value", "CHANGED_SESSION"), (1, "expires", 2000000100),
                   (5, "value", "CHANGED_NID"), (2, "domain", ".other.example.test"),
                   (3, "path", "/different"), (4, "secure", False), (2, "httpOnly", False),
                   (3, "sameSite", "Strict")]
        for index, field, changed in changes:
            value = renewed(cookies())
            value[index][field] = changed
            with self.subTest(index=index, field=field), self.assertRaises(host.LoginError) as raised:
                await self.execute(final_cookies=value)
            self.assertEqual((raised.exception.code, raised.exception.audit_stage),
                             ("login_binding_mismatch", "cookie_read"))
        value = renewed(cookies())
        value.pop(2)
        with self.assertRaises(host.LoginError):
            await self.execute(final_cookies=value)

    async def test_context_proxy_account_and_busy_changes_remain_blocked(self):
        for updates in ({"final_profile": {"ws": "ws://127.0.0.1:9222/devtools/browser/other"}},
                        {"final_profile": {"source": "saved"}},
                        {"final_token": {"st": "CHANGED_DB_SESSION"}},
                        {"final_token": {"is_active": False}}):
            with self.subTest(updates=updates), self.assertRaises(host.LoginError) as raised:
                await self.execute(final_cookies=renewed(cookies()), **updates)
            self.assertEqual(raised.exception.code, "login_binding_mismatch")
        with self.assertRaises(host.LoginError) as raised:
            await self.execute(final_profile={"proxy": "http://other-proxy.example.test:80"})
        self.assertEqual(raised.exception.code, "login_proxy_mismatch")
        with self.assertRaises(host.LoginError) as raised:
            await self.execute(final_cookies=renewed(cookies()), busy_after_verify=True)
        self.assertEqual(raised.exception.code, "generation_busy")


if __name__ == "__main__":
    unittest.main()
