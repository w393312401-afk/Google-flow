"""The login-bridge re-pinning tool: read-only by default, accepted by the real guard."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / 'local'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prepare = load('prepare_login_bridge_plan', LOCAL / 'prepare_login_bridge_plan.py')

PATCHED_RELOAD = """                active_running = False
                with ACTIVE_TASKS_LOCK:
                    for t in ACTIVE_TASKS.values():
                        if (isinstance(t, dict)
                                and (t.get('status') == 'running' or t.get('_cookie_login') is True)):
                            active_running = True
                            break
                if active_running:
                    continue

                time.sleep(1.0)
                with ACTIVE_TASKS_LOCK:
                    if any(isinstance(t, dict)
                           and (t.get('status') == 'running' or t.get('_cookie_login') is True)
                           for t in ACTIVE_TASKS.values()):
                        continue
                    _AUTO_RELOAD_TRIGGERED = True
"""
ROUTE = "        elif path == '/api/account-pool/login-sync':\n            self._send_json({'reviewed': True})\n\n"


def server(reload_block, route=''):
    return ("class Handler:\n    def do_POST(self, path):\n        if path == '/other':\n            pass\n"
            + route + LOGIN_ANCHOR_PREFIX + "            pass\n"
            + "\n\ndef watch(cfg):\n    while True:\n        try:\n            if cfg:\n" + reload_block
            + "                break\n        except Exception:\n            pass\n")


LOGIN_ANCHOR_PREFIX = prepare.LOGIN_ANCHOR


def write_private(path, data, mode=0o600):
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    os.chmod(path, mode)


class PrepareLoginBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name).resolve()  # the guard rejects symlinked (/var -> /private/var) roots
        self.flow = base / 'flow'
        self.spark = base / 'spark'
        (self.flow / 'local/adspower-login-deployment-assets').mkdir(parents=True)
        os.chmod(self.flow / 'local/adspower-login-deployment-assets', 0o700)
        (self.flow / 'data').mkdir()
        self.spark.mkdir()
        local = self.flow / 'local'
        for name in (*prepare.REQUIRED_ASSETS, prepare.GUARD):
            write_private(local / name, f'# {name}\n')

        old_asset = server(PATCHED_RELOAD, ROUTE).encode()
        write_private(local / 'adspower-login-deployment-assets/server.py', old_asset)
        self.current = server(prepare.CURRENT_RELOAD).replace('def watch', '# only in SPARK today\ndef watch')
        (self.spark / 'server.py').write_text(self.current)

        accounts = [(1, 'ok@example.test', 'p1', 'adspower-sync:p1'),
                    (2, 'renamed@example.test', 'p2', 'adspower-sync:p2'),
                    (3, 'gone@example.test', 'p3', 'adspower-sync:p3')]
        db = sqlite3.connect(self.flow / 'data/flow.db')
        db.execute('CREATE TABLE tokens (id INTEGER PRIMARY KEY, email TEXT, login_account TEXT, remark TEXT)')
        db.execute("INSERT INTO tokens VALUES (1,'ok@example.test','ok@example.test','adspower-sync:p1')")
        db.execute("INSERT INTO tokens VALUES (2,'new-name@example.test','new-name@example.test','adspower-sync:p2')")
        db.commit()
        db.close()
        names = []
        for token_id, email, profile, _ in accounts:
            name = f'adspower-cookie-sync-{profile}.json'
            write_private(local / name, json.dumps({'profile_id': profile, 'expected_email': email, 'token_id': token_id}))
            names.append(name)
        write_private(local / 'adspower-cookie-pool.json', json.dumps({'config_paths': names}))
        self.old_plan = {'version': 1, 'one_time_reload_authorized': True,
                         'patched_server_sha256': hashlib.sha256(old_asset).hexdigest()}
        write_private(local / 'adspower-login-deployment.json', json.dumps(self.old_plan))

    def tree(self):
        return {str(p.relative_to(self.flow)): p.read_bytes() for p in (self.flow / 'local').rglob('*') if p.is_file()}

    def test_dry_run_computes_a_plan_but_changes_nothing(self):
        before, spark_before = self.tree(), (self.spark / 'server.py').read_bytes()

        result = prepare.build(self.flow, self.spark)

        self.assertEqual(self.tree(), before)
        self.assertEqual((self.spark / 'server.py').read_bytes(), spark_before)
        self.assertEqual([e['token_id'] for e in result['included']], [1])
        reasons = {e['config_path']: e['reason'] for e in result['excluded']}
        self.assertIn('differs from expected_email', reasons['adspower-cookie-sync-p2.json'])
        self.assertEqual(reasons['adspower-cookie-sync-p3.json'], 'Flow2API account does not exist')

    def test_patch_keeps_newer_spark_code_and_adds_the_reviewed_blocks(self):
        patched = prepare.build(self.flow, self.spark)['patched'].decode()

        self.assertIn('# only in SPARK today', patched)
        self.assertEqual(patched.count("login-sync'"), 1)
        self.assertIn("_cookie_login", patched)
        self.assertNotIn(prepare.CURRENT_RELOAD, patched)
        compile(patched, 'x', 'exec')

    def test_written_plan_is_accepted_by_the_real_guard(self):
        guard = load('guard', LOCAL / prepare.GUARD)
        pool = load('pool', LOCAL / 'sync_adspower_cookie_pool.py')
        pool.ROOT, pool.LOCAL = self.flow, self.flow / 'local'
        result = prepare.build(self.flow, self.spark)

        keep = prepare.write(result, self.flow, self.spark)

        local = self.flow / 'local'
        plan, _ = guard._plan(local)
        self.assertEqual(guard._assets(local, plan), result['patched'])
        accounts = guard._accounts(local, plan, pool)
        self.assertEqual([a[0].name for a in accounts], ['adspower-cookie-sync-p1.json'])
        self.assertEqual(plan['original_server_sha256'], hashlib.sha256(self.current.encode()).hexdigest())
        self.assertEqual(oct(keep.stat().st_mode & 0o777), '0o700')
        self.assertEqual(sorted(p.name for p in keep.iterdir()),
                         ['adspower-cookie-pool.json', 'plan.json', 'server.approved-old.py'])
        self.assertEqual(json.loads((keep / 'plan.json').read_text()), self.old_plan)

    def test_write_never_touches_spark_or_the_account_configs(self):
        configs = {p.name: p.read_bytes() for p in (self.flow / 'local').glob('adspower-cookie-sync-*.json')}
        spark_before = (self.spark / 'server.py').read_bytes()

        prepare.write(prepare.build(self.flow, self.spark), self.flow, self.spark)

        self.assertEqual((self.spark / 'server.py').read_bytes(), spark_before)
        self.assertEqual({p.name: p.read_bytes() for p in (self.flow / 'local').glob('adspower-cookie-sync-*.json')}, configs)
        self.assertNotIn(b'allow_pool_login', b''.join(configs.values()))

    def test_refuses_when_spark_changes_between_preview_and_write(self):
        result = prepare.build(self.flow, self.spark)
        (self.spark / 'server.py').write_text(self.current + '# edited meanwhile\n')

        with self.assertRaises(prepare.PrepareError):
            prepare.write(result, self.flow, self.spark)
        self.assertFalse(list((self.flow / 'local').glob('adspower-login-deployment-superseded-*')))

    def test_refuses_unsafe_starting_points(self):
        local = self.flow / 'local'
        write_private(local / 'adspower-login-deployment.state.json', '{}')
        with self.assertRaises(prepare.PrepareError):
            prepare.build(self.flow, self.spark)
        (local / 'adspower-login-deployment.state.json').unlink()

        (self.spark / 'server.py').write_text(self.current + ServerWithRoute)
        with self.assertRaises(prepare.PrepareError):
            prepare.build(self.flow, self.spark)

        (self.spark / 'server.py').write_text(self.current.replace(prepare.LOGIN_ANCHOR, '        elif path == "/other":\n'))
        with self.assertRaises(prepare.PrepareError):
            prepare.build(self.flow, self.spark)

        (self.spark / 'server.py').write_text(self.current)
        write_private(local / 'adspower-login-deployment-assets/server.py', 'tampered')
        with self.assertRaises(prepare.PrepareError):
            prepare.build(self.flow, self.spark)

    def test_refuses_without_a_reload_authorization_or_qualifying_account(self):
        local = self.flow / 'local'
        write_private(local / 'adspower-login-deployment.json',
                      json.dumps(dict(self.old_plan, one_time_reload_authorized=False)))
        with self.assertRaises(prepare.PrepareError):
            prepare.build(self.flow, self.spark)

        write_private(local / 'adspower-login-deployment.json', json.dumps(self.old_plan))
        write_private(local / 'adspower-cookie-pool.json', json.dumps({'config_paths': ['adspower-cookie-sync-p3.json']}))
        with self.assertRaises(prepare.PrepareError):
            prepare.build(self.flow, self.spark)


ServerWithRoute = "\n# elif path == '/api/account-pool/login-sync':\n"


if __name__ == '__main__':
    unittest.main()
