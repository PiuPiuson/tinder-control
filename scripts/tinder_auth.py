#!/usr/bin/env python3
"""Email/phone verification and session renewal using Tinder's auth gateway."""

import argparse
import copy
from contextlib import contextmanager
import datetime
import fcntl
import gzip
import http.client
import json
import math
import os
from pathlib import Path
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from auth_codec import encode_request, decode_response

LOGIN_URL = "https://api.gotinder.com/v3/auth/login"
VERSION = "7.40.0"
BUILD = "1074000"


class AuthError(ValueError):
    pass


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def auth_path():
    if os.environ.get("TINDER_AUTH_FILE"):
        return Path(os.environ["TINDER_AUTH_FILE"]).expanduser()
    return Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "tinder-control/auth.json"


def read_config(path):
    config = json.loads(path.read_text()) if path.exists() else {}
    if not isinstance(config, dict):
        raise AuthError("The private credential file must contain a JSON object.")
    return config


def save_config(path, config):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".auth-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(config, stream, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def locked_config(path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(fd, "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise AuthError("Another login or renewal is in progress; wait for its result.") from None
        try:
            yield read_config(path)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def headers_for(config):
    pending = config.get("_login", {})
    return {
        "Accept": "application/x-protobuf",
        "Content-Type": "application/x-protobuf",
        "Accept-Encoding": "identity",
        "Accept-Language": "en-GB,en",
        "Origin": "https://tinder.com",
        "Referer": "https://tinder.com/",
        "platform": "web",
        "tinder-version": VERSION,
        "app-version": BUILD,
        "persistent-device-id": config["device_id"],
        "app-session-id": pending.get("app_session_id") or str(uuid.uuid4()),
        "app-session-time-elapsed": "0",
        "is-created-as-guest": "false",
        "funnel-session-id": pending.get("funnel_session_id") or uuid.uuid4().hex[:16],
    }


def prepare_session(config):
    config.setdefault("device_id", str(uuid.uuid4()))
    pending = config.setdefault("_login", {})
    pending.setdefault("app_session_id", str(uuid.uuid4()))
    pending.setdefault("funnel_session_id", uuid.uuid4().hex[:16])


def gateway(config, factor, values, timeout=30, opener=None):
    payload = encode_request(factor, values)
    request = urllib.request.Request(
        LOGIN_URL + "?" + urllib.parse.urlencode({"locale": config.get("locale", "en-GB")}),
        data=payload, headers=headers_for(config), method="POST")
    opener = opener or urllib.request.build_opener(NoRedirects())
    try:
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status = response.code
            raw = response.read()
            if response.headers.get("Content-Encoding", "").lower() == "gzip":
                raw = gzip.decompress(raw)
            retry_after = response.headers.get("Retry-After")
            try:
                decoded = decode_response(raw) if raw else {}
            except (ValueError, UnicodeError):
                return {"http_status": status, "transport_error": "Unexpected authentication response format; no credentials changed."}
            return {"http_status": status, "body": decoded, "retry_after": retry_after}
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException, EOFError):
        # A phone request or rotating refresh request may have reached Tinder.
        return {"http_status": None, "transport_error": "Login request did not complete; outcome unknown. No retry was attempted."}


def masked(value):
    return "…" + value[-4:] if value else None


def phone_for_gateway(value):
    # Current Tinder phone input concatenates countryCode + local digits;
    # its '+' is display-only. Accept old saved E.164 values as well.
    phone = re.sub(r"[\s()-]", "", str(value)).removeprefix("+")
    if not re.fullmatch(r"[1-9][0-9]{7,14}", phone):
        raise AuthError("The pending login needs an international phone number.")
    return phone


def public_status(config):
    expires = config.get("auth_token_expires_at")
    return {"ok": True, "has_api_credential": bool(config.get("auth_token")),
            "has_refresh_credential": bool(config.get("refresh_token")),
            "token_source": "environment" if os.environ.get("TINDER_AUTH_TOKEN") else "private_file",
            "expires_at": datetime.datetime.fromtimestamp(expires, datetime.timezone.utc).isoformat() if expires else None,
            "expired": expires <= time.time() if expires else None,
            "pending_step": config.get("_login", {}).get("state"),
            "requires_action": config.get("auth_requires_action", False)}


def accept_response(config, response, now=None):
    """Update in-memory credentials and return a deliberately secret-free result."""
    now = time.time() if now is None else now
    status = response["http_status"]
    if response.get("transport_error"):
        return {"ok": False, "status": status, "error": response["transport_error"], "outcome": "unknown"}
    body = response.get("body", {})
    if not status or not 200 <= status < 300 or body.get("error"):
        code = body.get("error", {}).get("code")
        return {"ok": False, "status": status, "error_code": code,
                "error": "Tinder rejected this login step. No retry was attempted.",
                **({"retry_after": response["retry_after"]} if response.get("retry_after") else {})}
    result = body.get("loginResult")
    if result:
        if not result.get("authToken") or not result.get("refreshToken") or not result.get("userId"):
            return {"ok": False, "status": status, "error": "Login response is missing required credentials or account identity."}
        if config.get("user_id") and result["userId"] != config["user_id"]:
            return {"ok": False, "status": status, "error": "Login returned a different account. Existing credentials were preserved."}
        config.update(auth_token=result["authToken"], refresh_token=result["refreshToken"],
                      user_id=result["userId"], auth_requires_action=False, auth_updated_at=now)
        ttl = result.get("authTokenTtl")
        if ttl is not None and int(ttl) > 0:
            config["auth_token_expires_at"] = now + int(ttl) / 1000
        else:
            config.pop("auth_token_expires_at", None)
        if result.get("captcha", 0) != 0:
            config["auth_requires_action"] = True
            config.setdefault("_login", {})["state"] = "captcha"
            return {"ok": False, "status": status, "requires_action": "captcha", "error": "Complete Tinder's verification in the official app or website."}
        config.pop("_login", None)
        return {"ok": True, "status": status, "authenticated": True,
                "automatic_renewal_ready": True,
                "expires_at": public_status(config)["expires_at"]}
    states = [key for key in body if key not in ("meta", "error", "authFlowVariant")]
    if len(states) != 1 or not isinstance(body[states[0]], dict):
        return {"ok": False, "status": status, "error": "Unrecognized login state; no automatic follow-up was attempted."}
    state = states[0]
    value = body[state]
    pending = config.setdefault("_login", {})
    pending["state"] = state
    pending["updated_at"] = now
    if value.get("refreshToken"):
        pending["refresh_token"] = value["refreshToken"]
    if state in ("validatePhoneOtpState", "validateExistingPhoneState"):
        if value.get("phone"):
            pending["phone"] = value["phone"]
        return {"ok": True, "status": status, "authenticated": False, "next_step": "verify-sms",
                "sms_sent": value.get("smsSent"), "otp_length": value.get("otpLength"),
                "sms_delivery": "unconfirmed",
                "phone": value.get("maskedPhoneNumber") or masked(pending.get("phone"))}
    if state == "getEmailState":
        return {"ok": True, "status": status, "authenticated": False, "next_step": "email"}
    if state == "validateEmailOtpState":
        return {"ok": True, "status": status, "authenticated": False, "next_step": "verify-email",
                "email": value.get("maskedEmail"), "otp_length": value.get("otpLength")}
    config["auth_requires_action"] = True
    return {"ok": False, "status": status, "requires_action": state,
            "error": "Tinder requires an additional step in its official app or website. No further action was taken."}


def build_step(action, values, config):
    pending = config.get("_login", {})
    refresh = pending.get("refresh_token")
    if action == "start-email":
        config["_login"] = {"state": "starting", "app_session_id": str(uuid.uuid4()),
                            "funnel_session_id": uuid.uuid4().hex[:16]}
        return "preEmail", {}
    if action == "start":
        phone = re.sub(r"[\s()-]", "", str(values.get("phone", "")))
        if not re.fullmatch(r"\+[1-9][0-9]{7,14}", phone):
            raise AuthError("Supply a phone number with + and its country code in the input file.")
        phone = phone_for_gateway(phone)
        config["_login"] = {"phone": phone, "state": "starting", "app_session_id": str(uuid.uuid4()),
                            "funnel_session_id": uuid.uuid4().hex[:16]}
        return "phone", {"phone": phone}
    if action == "refresh":
        if not config.get("refresh_token"):
            raise AuthError("No refresh credential is saved. Complete an initial login first.")
        return "refreshAuth", {"refreshToken": config["refresh_token"]}
    if action == "verify-sms":
        if pending.get("state") not in ("validatePhoneOtpState", "validateExistingPhoneState"):
            raise AuthError("No SMS verification is pending. Follow the current login steps first.")
        otp = str(values.get("otp", ""))
        if not re.fullmatch(r"[0-9]{4,10}", otp):
            raise AuthError("Supply the SMS code as the otp string in the input file.")
        if pending["state"] == "validateExistingPhoneState":
            return "existingPhoneOtp", {"otp": otp, **({"refreshToken": refresh} if refresh else {})}
        return "phoneOtp", {"phone": phone_for_gateway(pending["phone"]), "otp": otp, **({"refreshToken": refresh} if refresh else {})}
    if action == "resend-sms":
        if pending.get("state") not in ("validatePhoneOtpState", "validateExistingPhoneState"):
            raise AuthError("No SMS verification is pending. Follow the current login steps first.")
        if pending["state"] == "validateExistingPhoneState":
            if not refresh:
                raise AuthError("The pending login has no credential for an existing-phone resend.")
            return "existingPhoneOtpResend", {"refreshToken": refresh}
        if not pending.get("phone"):
            raise AuthError("The pending login has no phone number.")
        return "phoneOtpResend", {"phone": phone_for_gateway(pending["phone"]), **({"refreshToken": refresh} if refresh else {})}
    if action == "email":
        if pending.get("state") != "getEmailState":
            raise AuthError("No email-address step is pending.")
        email = str(values.get("email", ""))
        if not email or "@" not in email:
            raise AuthError("Supply the account email in the input file.")
        pending["email"] = email
        return "email", {"email": email, **({"refreshToken": refresh} if refresh else {})}
    if action == "verify-email":
        if pending.get("state") != "validateEmailOtpState" or not refresh:
            raise AuthError("No supported email-code verification is pending.")
        otp = str(values.get("otp", ""))
        if not re.fullmatch(r"[0-9]{4,10}", otp):
            raise AuthError("Supply the email code as the otp string in the input file.")
        return "emailOtp", {"otp": otp, "refreshToken": refresh,
                            **({"email": pending["email"]} if pending.get("email") else {})}
    raise AuthError("Unsupported login action.")


def run_step(action, values=None, execute=False, path=None, transport=gateway):
    path = Path(path) if path else auth_path()
    if action == "status":
        return public_status(read_config(path))
    with locked_config(path) as config:
        prepare_session(config)
        factor, fields = build_step(action, values or {}, config)
        if not execute:
            return {"ok": True, "preview": True, "action": action,
                    "method": "POST", "url": LOGIN_URL, "format": "application/x-protobuf",
                    "factor": factor, "field_names": sorted(fields)}
        # Save state before the call so interrupted requests can be inspected without repeating them.
        save_config(path, config)
        result = accept_response(config, transport(config, factor, fields))
        if action == "refresh" and not result.get("authenticated"):
            config["auth_requires_action"] = True
            result["ok"] = False
        save_config(path, config)
        return result


def ensure_session(force=False, prior_token=None, path=None, transport=gateway):
    """At most one renewal; never sends an SMS or retries a Tinder account action."""
    path = Path(path) if path else auth_path()
    with locked_config(path) as config:
        if os.environ.get("TINDER_AUTH_TOKEN"):
            return {"ok": True, "renewed": False}, config
        if config.get("auth_requires_action"):
            return {"ok": False, "requires_action": True, "error": "Complete the pending Tinder verification before continuing."}, config
        if force and prior_token and config.get("auth_token") != prior_token:
            return {"ok": True, "renewed": True}, config
        expires = config.get("auth_token_expires_at")
        due = bool(expires and expires <= time.time() + 30) or not config.get("auth_token")
        if not force and not due:
            return {"ok": True, "renewed": False}, config
        if not config.get("refresh_token"):
            return {"ok": False, "error": "Initial login is required; no refresh credential is saved."}, config
        prepare_session(config)
        save_config(path, config)
        result = accept_response(config, transport(config, "refreshAuth", {"refreshToken": config["refresh_token"]}))
        if not result.get("authenticated"):
            config["auth_requires_action"] = True
            result["ok"] = False
        save_config(path, config)
        return {**result, "renewed": bool(result.get("authenticated"))}, config


def import_browser(response_file, metadata, execute=False, path=None, now=None):
    """Import a captured terminal browser login without replaying its request.

    LoginResult fields and wrapped millisecond TTL were verified against Tinder's
    public 2026-11-01 schema:
    https://tinder.com/static/build/l/chunks/async-protobuf-schema-authgateway-8036d41ebaac5496c7d2.js
    """
    response_path = Path(response_file).expanduser()
    if not response_path.is_absolute():
        raise AuthError("The browser response file must have an absolute path.")
    if not isinstance(metadata, dict):
        raise AuthError("Browser import metadata must be a JSON object.")
    status = metadata.get("status")
    if isinstance(status, bool) or not isinstance(status, int) or not 200 <= status < 300:
        raise AuthError("Browser import requires a successful login HTTP status.")
    current_time = time.time() if now is None else now
    received_at = metadata.get("received_at")
    if (isinstance(received_at, bool) or not isinstance(received_at, (int, float))
            or not math.isfinite(received_at) or received_at <= 0
            or received_at > current_time + 300):
        raise AuthError("Browser response receipt time must be a finite Unix timestamp, no more than five minutes in the future.")
    headers = metadata.get("headers")
    if not isinstance(headers, dict):
        raise AuthError("Browser import requires captured request headers.")

    def captured_header(name, required=False):
        values = [value for key, value in headers.items() if isinstance(key, str) and key.lower() == name]
        if not values:
            if required:
                raise AuthError("Browser import requires the captured persistent-device-id header.")
            return None
        if (any(value != values[0] for value in values)
                or not isinstance(values[0], str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", values[0])
                or values[0].lower() in {"null", "undefined", "unknown", "redacted"}):
            raise AuthError("A captured browser session header is missing, conflicting, or invalid.")
        return values[0]

    device_id = captured_header("persistent-device-id", required=True)
    session_ids = {}
    for header, field in (("app-session-id", "app_session_id"), ("funnel-session-id", "funnel_session_id")):
        value = captured_header(header)
        if value is not None:
            session_ids[field] = value
    try:
        body = decode_response(response_path.read_bytes())
    except ValueError:
        raise AuthError("The browser response is not valid authentication protobuf.") from None
    login = body.get("loginResult")
    if (not isinstance(login, dict) or body.get("error")
            or not all(isinstance(login.get(key), str) and login[key].strip()
                       for key in ("authToken", "refreshToken", "userId"))):
        raise AuthError("Browser import requires a terminal loginResult with credentials and account identity.")
    ttl = login.get("authTokenTtl")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
        raise AuthError("Browser login must include a positive authTokenTtl to establish its original expiry.")
    expires = received_at + ttl / 1000
    if not math.isfinite(expires) or expires <= current_time:
        raise AuthError("The captured browser login has expired; capture a fresh completed login.")
    try:
        datetime.datetime.fromtimestamp(expires, datetime.timezone.utc)
    except (ValueError, OverflowError, OSError):
        raise AuthError("The captured browser login has an invalid expiry.") from None
    target = Path(path) if path else auth_path()

    def stage(config):
        updated = config.get("auth_updated_at")
        if (isinstance(updated, (int, float)) and not isinstance(updated, bool)
                and math.isfinite(updated) and updated > received_at):
            raise AuthError("A newer session is already saved; importing this older response would overwrite rotated credentials.")
        candidate = copy.deepcopy(config)
        # Pending details belong to the old attempt; never carry its challenge
        # credential or contact information into the captured browser session.
        candidate.pop("_login", None)
        result = accept_response(candidate, {"http_status": status, "body": body}, now=received_at)
        accepted = result.get("authenticated") or result.get("requires_action") == "captcha"
        if not accepted:
            return result, None
        candidate["device_id"] = device_id
        candidate["login_source"] = "browser"
        if not result.get("authenticated"):
            candidate.setdefault("_login", {}).update(session_ids)
        return result, candidate

    if not execute:
        result, candidate = stage(read_config(target))
        if candidate is None:
            return {**result, "preview": True, "action": "import-browser"}
        return {"ok": True, "preview": True, "action": "import-browser",
                "would_authenticate": bool(result.get("authenticated")),
                "requires_action": result.get("requires_action", False),
                "expires_at": public_status(candidate)["expires_at"]}
    with locked_config(target) as config:
        result, candidate = stage(config)
        if candidate is None:
            return result
        save_config(target, candidate)
        return {**result, "imported": True, "login_source": "browser"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["status", "start", "start-email", "verify-sms", "resend-sms", "email", "verify-email", "refresh", "import-browser"])
    parser.add_argument("--input-file", help="Private JSON input file, or '-' for stdin. Never pass codes in shell arguments.")
    parser.add_argument("--response-file", help="Absolute path to a captured binary login response for import-browser")
    parser.add_argument("--execute", action="store_true", help="Perform this login step; otherwise preview")
    args = parser.parse_args(argv)
    try:
        if args.action == "import-browser":
            if (not args.response_file or not args.input_file or args.input_file == "-"
                    or not Path(args.input_file).expanduser().is_absolute()):
                raise AuthError("Browser import requires --response-file and an absolute --input-file metadata path.")
        elif args.response_file:
            raise AuthError("--response-file is only supported by import-browser.")
        if args.input_file == "-":
            import sys
            values = json.load(sys.stdin)
        elif args.input_file:
            values = json.loads(Path(args.input_file).expanduser().read_text())
        else:
            values = {}
        if not isinstance(values, dict):
            raise AuthError("Login input must be a JSON object.")
        if args.action == "import-browser":
            result = import_browser(args.response_file, values, args.execute)
        else:
            result = run_step(args.action, values, args.execute)
    except AuthError as error:
        result = {"ok": False, "error": str(error)}
    except (ValueError, OSError, KeyError, TypeError):
        # Exceptions from parsers or transport can embed input. Keep output secret-free.
        result = {"ok": False, "error": "Login input, saved state, or file access was invalid. Check the required input fields and private file access."}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
