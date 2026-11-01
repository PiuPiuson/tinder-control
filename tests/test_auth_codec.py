"""Offline fixtures for Tinder's observed auth protobuf wire format."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("auth_codec", ROOT / "scripts/auth_codec.py")
codec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(codec)


class AuthCodecTests(unittest.TestCase):
    def test_refresh_literal_wire(self):
        # Gateway field 10 -> RefreshAuth field 1, bare string (not wrapper).
        self.assertEqual(codec.encode_request("refreshAuth", {"refreshToken": "abc"}), b"\x52\x05\x0a\x03abc")

    def test_phone_literal_wire(self):
        self.assertEqual(codec.encode_request("phone", {"phone": "+123"}), b"\x0a\x06\x0a\x04+123")

    def test_otp_wrapper_and_leading_zero_preserved(self):
        expected = bytes.fromhex("12 16 0a 06 0a 04 2b 31 32 33 12 06 30 30 31 32 33 34 1a 04 0a 02 72 74")
        self.assertEqual(codec.encode_request("phoneOtp", {"phone": "+123", "otp": "001234", "refreshToken": "rt"}), expected)

    def test_auth_flow_variant_envelope_field_23(self):
        self.assertEqual(codec.encode_request("getInitialState", {}, auth_flow_variant="v"),
                         bytes.fromhex("4a 00 ba 01 03 0a 01 76"))

    def test_login_result_literal_wire(self):
        # LoginResult field 8; ttl is Int64Value(field 1=300000 milliseconds).
        payload = bytes.fromhex("42 0f 0a 01 72 12 01 61 22 01 75 2a 04 08 e0 a7 12")
        self.assertEqual(codec.decode_response(payload), {
            "loginResult": {"refreshToken": "r", "authToken": "a", "userId": "u", "authTokenTtl": 300000}})

    def test_sms_state_booleans_and_empty_wrappers(self):
        payload = bytes.fromhex("22 0e 0a 03 0a 01 72 12 01 70 1a 02 08 06 22 00")
        self.assertEqual(codec.decode_response(payload), {
            "validatePhoneOtpState": {"refreshToken": "r", "phone": "p", "otpLength": 6, "smsSent": False}})

    def test_error_and_captcha(self):
        error = bytes.fromhex("12 09 08 91 03 12 04 6e 6f 70 65")
        self.assertEqual(codec.decode_response(error), {"error": {"code": 401, "message": "nope"}})
        captcha = bytes.fromhex("82 01 09 0a 01 72 12 01 6b 1a 01 62")
        self.assertEqual(codec.decode_response(captcha), {"captchaState": {
            "referenceToken": "r", "captchaPublicKey": "k", "dataBlob": "b"}})

    def test_repeated_social_connections_and_last_oneof_wins(self):
        payload = bytes.fromhex("4a 0d 0a 03 0a 01 72 12 02 08 01 12 02 08 02")
        self.assertEqual(codec.decode_response(payload)["socialConnectionList"], {
            "refreshToken": "r", "connections": [{"service": 1}, {"service": 2}]})
        self.assertEqual(codec.decode_response(payload + bytes.fromhex("2a 00")), {"getEmailState": {}})

    def test_unknown_wire_types_skipped_without_exposing_bytes(self):
        payload = bytes.fromhex("f0 01 01 f9 01") + b"12345678" + bytes.fromhex("82 02 03") + b"xyz" + bytes.fromhex("8d 02") + b"abcd"
        self.assertEqual(codec.decode_response(payload), {"_unknownFields": [30, 31, 32, 33]})

    def test_malformed_wire_fails_cleanly(self):
        for payload in (b"\x80", b"\x00", b"\x42\x05\x01", b"\x42\x01\x00", b"\x43",
                        b"\x80" * 10 + b"\x01", b"\xf0\x01" + b"\xff" * 9 + b"\x02",
                        b"\x12\x03\x12\x01\xff", b"\x40\x00"):
            with self.subTest(payload=payload):
                with self.assertRaises(codec.CodecError):
                    codec.decode_response(payload)

    def test_bad_inputs_do_not_expose_values(self):
        for factor, body in (("phone", {"phone": 123}), ("phoneOtp", {"otp": "secret", "typo": "secret"}),
                             ("phone", {"iosDeviceToken": "secret", "androidJws": "secret"}),
                             ("phone", {"androidJwsVersion": 2**40})):
            with self.subTest(factor=factor):
                with self.assertRaises(codec.CodecError) as error:
                    codec.encode_request(factor, body)
                self.assertNotIn("secret", str(error.exception))

    def test_request_factors_use_verified_envelope_numbers(self):
        expected = {"email": 3, "emailOtp": 5, "phoneOtpResend": 7, "emailOtpResend": 8,
                    "getInitialState": 9, "dismissSocialConnectionList": 12,
                    "captcha": 18, "existingPhoneOtp": 19, "existingPhoneOtpResend": 20}
        for factor, number in expected.items():
            encoded = codec.encode_request(factor, {})
            fields = list(codec._fields(encoded))
            self.assertEqual(fields, [(number, 2, b"")])


if __name__ == "__main__":
    unittest.main()
