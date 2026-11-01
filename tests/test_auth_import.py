"""Offline browser-session import tests using synthetic credentials only."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import auth_codec as codec
import tinder_auth as auth

NOW = 20000
RECEIVED = NOW - 10


class BrowserImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve()
        self.response = self.directory / "response.bin"
        self.target = self.directory / "session" / "auth.json"
        self.metadata = {"status": 200, "received_at": RECEIVED,
                         "headers": {"persistent-device-id": "browser-device-id",
                                     "app-session-id": "browser-app-session",
                                     "funnel-session-id": "browser-funnel-session",
                                     "X-Auth-Token": "never-store-this-header"}}
        self.body = {"loginResult": {"authToken": "synthetic-new-api", "refreshToken": "synthetic-new-refresh",
                                     "userId": "account-one", "authTokenTtl": 60000}}
        self.write_response()

    def write_response(self):
        self.response.write_bytes(codec._encode_message("AuthGatewayResponse", self.body))

    def run_import(self, execute=True):
        return auth.import_browser(self.response, self.metadata, execute, self.target, NOW)

    def test_import_uses_original_expiry_and_preserves_unrelated_config(self):
        auth.save_config(self.target, {"auth_token": "old-api", "refresh_token": "old-refresh",
                                      "user_id": "account-one", "locale": "en-GB", "custom": {"keep": [1]},
                                      "_login": {"email": "old@example.test", "refresh_token": "old-challenge"},
                                      "auth_requires_action": True})
        result = self.run_import()
        saved = auth.read_config(self.target)
        self.assertTrue(result["authenticated"])
        self.assertTrue(result["imported"])
        self.assertEqual(saved["auth_token"], "synthetic-new-api")
        self.assertEqual(saved["refresh_token"], "synthetic-new-refresh")
        self.assertEqual(saved["device_id"], "browser-device-id")
        self.assertEqual(saved["auth_updated_at"], RECEIVED)
        self.assertEqual(saved["auth_token_expires_at"], RECEIVED + 60)
        self.assertEqual(saved["custom"], {"keep": [1]})
        self.assertEqual(saved["locale"], "en-GB")
        self.assertEqual(saved["login_source"], "browser")
        self.assertNotIn("_login", saved)
        self.assertNotIn("never-store-this-header", json.dumps(saved))
        self.assertNotIn("synthetic-new", json.dumps(result))
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)

    def test_preview_does_not_create_credentials_directory_or_lock(self):
        result = self.run_import(False)
        self.assertTrue(result["preview"])
        self.assertTrue(result["would_authenticate"])
        self.assertNotIn("authenticated", result)
        self.assertFalse(self.target.parent.exists())
        self.assertNotIn("synthetic-new", json.dumps(result))

    def test_existing_identity_mismatch_changes_nothing(self):
        auth.save_config(self.target, {"user_id": "different-account", "auth_token": "keep-api", "custom": 5})
        before = self.target.read_bytes()
        result = self.run_import()
        self.assertFalse(result["ok"])
        self.assertEqual(self.target.read_bytes(), before)

    def test_invalid_receipt_times_are_rejected_without_writes(self):
        for timestamp in (float("nan"), float("inf"), float("-inf"), True, "19990", 0, -1, NOW + 301):
            with self.subTest(timestamp=timestamp):
                self.metadata["received_at"] = timestamp
                with self.assertRaises(auth.AuthError):
                    self.run_import()
                self.assertFalse(self.target.parent.exists())

    def test_small_clock_skew_allowed_but_expired_capture_rejected(self):
        self.metadata["received_at"] = NOW + 60
        result = self.run_import(False)
        self.assertTrue(result["would_authenticate"])
        self.metadata["received_at"] = NOW - 61
        with self.assertRaises(auth.AuthError):
            self.run_import()
        self.assertFalse(self.target.parent.exists())

    def test_capture_needs_a_device_header_and_accepts_case_insensitive_names(self):
        self.metadata["headers"].pop("persistent-device-id")
        with self.assertRaises(auth.AuthError):
            self.run_import()
        self.metadata["headers"]["Persistent-Device-Id"] = ""
        with self.assertRaises(auth.AuthError):
            self.run_import()
        self.metadata["headers"]["Persistent-Device-Id"] = "real-browser-id"
        self.assertTrue(self.run_import()["authenticated"])
        self.assertEqual(auth.read_config(self.target)["device_id"], "real-browser-id")

    def test_captcha_preserves_rotated_pair_and_actual_session_ids(self):
        self.body["loginResult"]["captcha"] = 1
        self.write_response()
        auth.save_config(self.target, {"refresh_token": "old", "user_id": "account-one",
                                      "_login": {"email": "old@example.test", "refresh_token": "old-challenge"}})
        result = self.run_import()
        saved = auth.read_config(self.target)
        self.assertFalse(result["ok"])
        self.assertTrue(result["imported"])
        self.assertNotIn("authenticated", result)
        self.assertTrue(saved["auth_requires_action"])
        self.assertEqual(saved["refresh_token"], "synthetic-new-refresh")
        self.assertEqual(saved["auth_token"], "synthetic-new-api")
        self.assertEqual(saved["_login"], {"state": "captcha", "app_session_id": "browser-app-session",
                                         "funnel_session_id": "browser-funnel-session"})

    def test_incomplete_and_ttl_less_login_responses_rejected(self):
        for body in ({"validateEmailOtpState": {"refreshToken": "pending"}},
                     {"loginResult": {"authToken": "a", "refreshToken": "r", "userId": "u"}},
                     {"loginResult": {"authToken": "a", "userId": "u", "authTokenTtl": 60000}}):
            with self.subTest(body=body):
                self.body = body
                self.write_response()
                with self.assertRaises(auth.AuthError):
                    self.run_import()
                self.assertFalse(self.target.parent.exists())

    def test_older_capture_cannot_overwrite_rotated_credentials(self):
        auth.save_config(self.target, {"auth_token": "latest-api", "refresh_token": "latest-refresh",
                                      "auth_updated_at": RECEIVED + 1, "user_id": "account-one"})
        before = self.target.read_bytes()
        with self.assertRaises(auth.AuthError):
            self.run_import()
        self.assertEqual(self.target.read_bytes(), before)

    def test_cli_preview_requires_absolute_files_and_stays_secret_free(self):
        metadata_path = self.directory / "metadata.json"
        metadata_path.write_text(json.dumps(self.metadata))
        stream = io.StringIO()
        with patch.dict(os.environ, {"TINDER_AUTH_FILE": str(self.target)}, clear=True), patch.object(auth.time, "time", return_value=NOW), redirect_stdout(stream):
            code = auth.main(["import-browser", "--response-file", str(self.response), "--input-file", str(metadata_path)])
        self.assertEqual(code, 0)
        result = json.loads(stream.getvalue())
        self.assertTrue(result["preview"])
        self.assertFalse(self.target.parent.exists())
        self.assertNotIn("synthetic-new", stream.getvalue())
        stream = io.StringIO()
        with redirect_stdout(stream):
            code = auth.main(["import-browser", "--response-file", str(self.response), "--input-file", "relative.json"])
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(stream.getvalue())["ok"])


if __name__ == "__main__":
    unittest.main()
