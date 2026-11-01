import argparse
import importlib.util
import io
import http.client
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("tinder", ROOT / "scripts/tinder.py")
tinder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tinder)
CATALOG = tinder.load_json(tinder.CATALOG_PATH)


def args(operation, **kwargs):
    values = dict(operation=operation, var=[], query=[], body_file=None, dry_run=False, execute=False)
    values.update(kwargs)
    return argparse.Namespace(**values)


class Response(io.BytesIO):
    def __init__(self, body=b'{"data":{"result":"ok"}}', status=200, headers=None):
        super().__init__(body)
        self.code = status
        self.headers = headers or {}


class FakeOpener:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


class TinderTests(unittest.TestCase):
    def test_read_query_and_path_encoding(self):
        _, preview, url, headers, body = tinder.build_request(CATALOG, args(
            "messages", var=["match_id=a/b?&"], query=["count=12", "page_token=a&b=c"]), {"auth_token": "fake"})
        self.assertFalse(preview)
        self.assertIn("/a%2Fb%3F%26/messages?", url)
        self.assertIn("page_token=a%26b%3Dc", url)
        self.assertIn("count=12", url)
        self.assertEqual(headers["X-Auth-Token"], "fake")
        self.assertIsNone(body)

    def test_mutation_defaults_to_preview_and_dry_run_wins(self):
        for extra in ({}, {"dry_run": True, "execute": True}):
            _, preview, _, _, _ = tinder.build_request(CATALOG, args("like-user", var=["user_id=u"], **extra), {})
            self.assertTrue(preview)
        with self.assertRaises(tinder.InputError):
            tinder.build_request(CATALOG, args("like-user", var=["user_id=u"], execute=True), {})

    def test_message_round_trip_and_recipient_binding(self):
        content = {"userId": "me", "otherId": "them", "matchId": "m", "sessionId": None,
                   "message": 'Hey "Sam" 👋\nCoffee tomorrow?'}
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "body.json"
            file.write_text(json.dumps(content), encoding="utf-8")
            entry, preview, url, headers, body = tinder.build_request(CATALOG, args(
                "send-message", var=["match_id=m"], body_file=str(file), execute=True), {"auth_token": "fake"})
            self.assertFalse(preview)
            opener = FakeOpener(Response())
            result = tinder.perform(entry, url, headers, body, 5, opener)
            self.assertTrue(result["ok"])
            self.assertEqual(json.loads(opener.calls[0][0].data), content)
            with self.assertRaises(tinder.InputError):
                tinder.build_request(CATALOG, args("send-message", var=["match_id=wrong"], body_file=str(file)), {})

    def test_unknown_post_outcome_has_one_attempt(self):
        opener = FakeOpener(TimeoutError("timed out"))
        result = tinder.perform({"method": "POST"}, "https://api.gotinder.com/test", {}, {}, 1, opener)
        self.assertFalse(result["ok"])
        self.assertIn("unknown", result["outcome"])
        self.assertEqual(len(opener.calls), 1)

    def test_truncated_write_response_is_unknown(self):
        class TruncatedResponse(Response):
            def read(self):
                raise http.client.IncompleteRead(b"partial", 100)
        opener = FakeOpener(TruncatedResponse())
        result = tinder.perform({"method": "POST"}, "https://api.gotinder.com/test", {}, {}, 1, opener)
        self.assertFalse(result["ok"])
        self.assertIn("unknown", result["outcome"])
        self.assertEqual(len(opener.calls), 1)

    def test_nonfinite_coordinates_rejected(self):
        for value in ("nan", "inf", "-inf"):
            with self.assertRaises(tinder.InputError):
                tinder.build_request(CATALOG, args("location", var=["lat=" + value, "lon=1"]), {})

    def test_http_errors_and_rate_limit(self):
        for status in (401, 403, 429, 500):
            error = urllib.error.HTTPError("https://api.gotinder.com/test", status, "error",
                                           {"Retry-After": "60"}, io.BytesIO(b'{"error":"failed"}'))
            opener = FakeOpener(error)
            result = tinder.perform({"method": "POST"}, "https://api.gotinder.com/test", {}, {}, 1, opener)
            self.assertFalse(result["ok"])
            self.assertEqual(result["status"], status)
            self.assertEqual(result["retry_after"], "60")
            self.assertEqual(len(opener.calls), 1)
            if status == 500:
                self.assertIn("unknown", result["outcome"])

    def test_secrets_redacted_pagination_preserved(self):
        result = tinder.redact({"X-Auth-Token": "secret-value", "detail": "echo secret-value",
                                "data": {"accessToken": "new-secret", "next_page_token": "cursor"}}, "secret-value")
        self.assertNotIn("secret-value", json.dumps(result))
        self.assertNotIn("new-secret", json.dumps(result))
        self.assertEqual(result["data"]["next_page_token"], "cursor")

    def test_origin_and_redirect_restrictions(self):
        for origin in ("http://api.gotinder.com", "https://api.gotinder.com.evil.test", "https://api.gotinder.com@evil.test"):
            with self.assertRaises(tinder.InputError):
                tinder.build_request(CATALOG, args("profile", dry_run=True), {"base_url": origin})
        self.assertIsNone(tinder.NoRedirects().redirect_request(None, None, 302, "", {}, "https://example.com"))

    def test_catalog_operations_construct_without_sample_ids(self):
        values = ["user_id=u", "match_id=m", "message_id=msg", "last_activity_date=2026-11-01T00:00:00Z", "lat=1.23", "lon=4.56"]
        self.assertEqual(len(CATALOG["operations"]), 17)
        for operation in CATALOG["operations"]:
            if operation in ("send-message", "login"):
                with self.assertRaises(tinder.InputError):
                    tinder.build_request(CATALOG, args(operation, var=values, dry_run=True), {})
                continue
            _, preview, url, headers, body = tinder.build_request(CATALOG, args(operation, var=values, dry_run=True), {})
            self.assertTrue(preview)
            self.assertNotIn("{{", url)
            self.assertNotIn("persistent-device-id", headers)
            if operation == "location":
                self.assertIsInstance(body["lat"], float)


if __name__ == "__main__":
    unittest.main()
