"""Only Google SIDCC value/expiry renewal may pass a session comparison."""
import copy
import importlib.util
from pathlib import Path
import unittest


path = Path(__file__).resolve().parents[1] / "local/sync_adspower_cookies.py"
spec = importlib.util.spec_from_file_location("cookie_session_hash_tests", path)
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


def cookies():
    return [{"name": name, "value": "SYNTHETIC_" + name, "expires": 2000000000,
             "domain": ".google.com", "path": "/", "secure": True,
             "httpOnly": True, "sameSite": "None"}
            for name in ("SID", "NID", "SIDCC", "__Secure-1PSIDCC", "__Secure-3PSIDCC")]


class CookieSessionHashTests(unittest.TestCase):
    def test_renewing_three_short_lived_values_and_expiries_keeps_session_only(self):
        original = cookies()
        updated = copy.deepcopy(original)
        for cookie in updated:
            if cookie["name"] in sync.RENEWING_SESSION_COOKIES:
                cookie.update(value="SYNTHETIC_RENEWED", expires=2100000000)
        self.assertNotEqual(sync.auth_hash(original), sync.auth_hash(updated))
        self.assertEqual(sync.auth_session_hash(original), sync.auth_session_hash(updated))
        self.assertEqual(sync.auth_session_hash(original), sync.auth_session_hash(list(reversed(original))))

    def test_other_cookie_values_and_expiries_stay_strict(self):
        original = cookies()
        for index in (0, 1):
            for key, value in (("value", "SYNTHETIC_CHANGED"), ("expires", 2100000000)):
                with self.subTest(index=index, field=key):
                    updated = copy.deepcopy(original)
                    updated[index][key] = value
                    self.assertNotEqual(sync.auth_session_hash(original), sync.auth_session_hash(updated))

    def test_renewing_cookie_sending_attributes_and_presence_stay_strict(self):
        original = cookies()
        for field, value in (("domain", ".other.test"), ("path", "/different"),
                             ("secure", False), ("httpOnly", False), ("sameSite", "Strict"),
                             ("partitionKey", "https://different.test")):
            with self.subTest(field=field):
                updated = copy.deepcopy(original)
                updated[2][field] = value
                self.assertNotEqual(sync.auth_session_hash(original), sync.auth_session_hash(updated))
        self.assertNotEqual(sync.auth_session_hash(original), sync.auth_session_hash(original[:-1]))

    def test_missing_nonrenewing_authentication_and_invalid_shapes_are_rejected(self):
        for candidate in (cookies()[2:], [], [None], [{"name": "SID", "value": None}]):
            with self.subTest(candidate=candidate):
                with self.assertRaises(sync.SyncError):
                    sync.auth_session_hash(candidate)


if __name__ == "__main__":
    unittest.main()
