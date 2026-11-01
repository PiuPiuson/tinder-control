#!/usr/bin/env python3
"""Execute one request from the sanitized Tinder API catalog.

Adapted from an author-provided reverse-engineered Postman collection.
Request definitions: ../references/requests.json
"""

import argparse
import gzip
import http.client
import json
import math
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

CATALOG_PATH = Path(__file__).resolve().parents[1] / "references" / "requests.json"
PLACEHOLDER = re.compile(r"\{\{([^{}]+)\}\}")
SECRET_KEYS = re.compile(r"auth|token|password|secret|cookie", re.I)


def is_secret_key(key):
    # Pagination cursors are required to continue a read; they are not login tokens.
    normalized = re.sub(r"[-_]", "", key).lower()
    if normalized in {"pagetoken", "nextpagetoken", "previouspagetoken", "paginationtoken"}:
        return False
    return bool(SECRET_KEYS.search(key))


class InputError(ValueError):
    pass


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def load_json(path):
    if path == "-":
        return json.load(sys.stdin)
    with open(Path(path).expanduser(), encoding="utf-8") as stream:
        return json.load(stream)


def pairs(values):
    result = {}
    for value in values:
        key, separator, item = value.partition("=")
        if not separator or not key:
            raise InputError("Expected NAME=VALUE.")
        if is_secret_key(key):
            raise InputError("Supply credentials through TINDER_AUTH_TOKEN or the private auth file.")
        result[key] = item
    return result


def interpolate(value, variables):
    if isinstance(value, dict):
        return {key: interpolate(item, variables) for key, item in value.items()}
    if isinstance(value, list):
        return [interpolate(item, variables) for item in value]
    if not isinstance(value, str):
        return value
    match = PLACEHOLDER.fullmatch(value)
    if match:
        if match[1] not in variables:
            raise InputError("Missing variable: " + match[1])
        return variables[match[1]]

    def replace(match):
        if match[1] not in variables:
            raise InputError("Missing variable: " + match[1])
        return str(variables[match[1]])

    return PLACEHOLDER.sub(replace, value)


def redact(value, token=""):
    if isinstance(value, dict):
        return {key: "[redacted]" if is_secret_key(key) else redact(item, token)
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item, token) for item in value]
    if isinstance(value, str) and token:
        return value.replace(token, "[redacted]")
    return value


def runtime_config():
    path = os.environ.get("TINDER_AUTH_FILE")
    if not path:
        config_root = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
        path = str(config_root / "tinder-control" / "auth.json")
    config = load_json(path) if Path(path).expanduser().is_file() else {}
    if not isinstance(config, dict):
        raise InputError("The private auth file must contain a JSON object.")
    for variable, key in [("TINDER_AUTH_TOKEN", "auth_token"),
                          ("TINDER_BASE_URL", "base_url"), ("TINDER_LOCALE", "locale")]:
        if os.environ.get(variable):
            config[key] = os.environ[variable]
    return config


def build_request(catalog, args, config):
    entry = catalog["operations"][args.operation]
    if args.operation == "login":
        raise InputError("Login uses binary protobuf. Use scripts/tinder_auth.py for phone login and session renewal.")
    variables = {**catalog["defaults"],
                 **{key: config[key] for key in ("auth_token", "base_url", "locale") if key in config},
                 **pairs(args.var)}
    preview = args.dry_run or (entry["method"] != "GET" and not args.execute)
    if (not preview and entry["headers"].get("X-Auth-Token") and not variables.get("auth_token")
            and not config.get("refresh_token")):
        raise InputError("Missing Tinder credentials. Set TINDER_AUTH_TOKEN or configure the private auth file.")
    variables.setdefault("auth_token", "[runtime credential]")
    base = urllib.parse.urlsplit(str(variables["base_url"]))
    if (base.scheme != "https" or base.hostname != "api.gotinder.com"
            or base.port not in (None, 443) or base.username or base.password
            or base.path not in ("", "/") or base.query or base.fragment):
        raise InputError("The base URL must be https://api.gotinder.com.")
    path = "/".join(urllib.parse.quote(str(interpolate(part, variables)), safe="")
                    for part in entry["path"].split("/"))
    query = {item["key"]: interpolate(item["value"], variables) for item in entry["query"]}
    query.update(pairs(args.query))
    url = str(variables["base_url"]).rstrip("/") + "/" + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    headers = {key: str(interpolate(value, variables)) for key, value in entry["headers"].items()}
    # urllib does not decode Brotli; ask for an uncompressed response.
    headers["Accept-Encoding"] = "identity"
    if args.body_file:
        body = load_json(args.body_file)
    elif args.operation == "send-message":
        # The saved body concatenates user IDs. Require an explicit body to avoid
        # assuming that its matchId is equivalent to the observed match ID.
        raise InputError("send-message requires --body-file with userId, otherId, matchId, sessionId, and message.")
    elif entry.get("incomplete"):
        raise InputError(entry["incomplete"])
    else:
        body = interpolate(entry["body"], variables)
    if args.operation == "location" and body is not None:
        body = {**body, "lat": float(body["lat"]), "lon": float(body["lon"])}
        if not all(math.isfinite(body[key]) for key in ("lat", "lon")):
            raise InputError("Location coordinates must be finite numbers.")
    if args.operation == "send-message":
        if not isinstance(body, dict):
            raise InputError("The message body must be a JSON object.")
        required = {"userId", "otherId", "matchId", "sessionId", "message"}
        if required - body.keys():
            raise InputError("Missing message fields: " + ", ".join(sorted(required - body.keys())))
        if body["matchId"] != variables.get("match_id"):
            raise InputError("Body matchId must match the explicitly selected URL match_id.")
        if not all(isinstance(body[key], str) and body[key].strip()
                   for key in ("userId", "otherId", "matchId", "message")):
            raise InputError("Message IDs and message text must be nonempty strings.")
    if body is not None:
        headers.setdefault("Content-Type", "application/json")
    return entry, preview, url, headers, body


def perform(entry, url, headers, body, timeout, opener=None):
    payload = None if body is None else json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
    request = urllib.request.Request(url, data=payload, headers=headers, method=entry["method"])
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
            response_text = raw.decode("utf-8", errors="replace")
            try:
                data = json.loads(response_text) if response_text else None
            except json.JSONDecodeError:
                data = response_text
            result = {"ok": 200 <= status < 300, "status": status, "data": data}
            if response.headers.get("Retry-After"):
                result["retry_after"] = response.headers["Retry-After"]
            if not result["ok"]:
                if status in (401, 403):
                    result["error"] = "Authentication rejected; refresh the account credential before continuing."
                elif status == 429:
                    result["error"] = "Rate limited; no retry was attempted."
                elif 300 <= status < 400:
                    result["error"] = "Redirect refused; credentials were not forwarded."
                else:
                    result["error"] = "Tinder returned an unsuccessful HTTP status."
                if entry["method"] != "GET" and status >= 500:
                    result["outcome"] = "unknown; inspect current account state before considering another attempt"
            return result
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException, EOFError) as error:
        return {"ok": False, "status": None, "error": str(error),
                "outcome": "unknown; do not automatically retry" if entry["method"] != "GET" else "request failed"}


def main(argv=None):
    catalog = load_json(CATALOG_PATH)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["list", *catalog["operations"]])
    parser.add_argument("--var", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--query", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--body-file", help="JSON body file, or '-' for stdin")
    parser.add_argument("--dry-run", action="store_true", help="Preview without making an HTTP request")
    parser.add_argument("--execute", action="store_true", help="Execute a non-GET request instead of previewing it")
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args(argv)
    token = ""
    try:
        if args.operation == "list":
            result = {name: {"method": entry["method"], "path": entry["path"],
                             **({"incomplete": entry["incomplete"]} if entry.get("incomplete") else {}),
                             **({"handler": entry["handler"]} if entry.get("handler") else {})}
                      for name, entry in catalog["operations"].items()}
        else:
            config = runtime_config()
            token = str(config.get("auth_token", ""))
            entry, preview, url, headers, body = build_request(catalog, args, config)
            if preview:
                result = {"ok": True, "preview": True, "operation": args.operation,
                          "method": entry["method"], "url": url, "headers": redact(headers, token), "body": body}
            else:
                result = {"operation": args.operation, **execute_request(catalog, args, config)}
                token = str(config.get("auth_token", ""))
        print(json.dumps(redact(result, token), ensure_ascii=False, indent=2))
        return 0 if result.get("ok", True) else 1
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(json.dumps(redact({"ok": False, "error": str(error)}, token), ensure_ascii=False))
        return 2


def execute_request(catalog, args, config, transport=perform, renew=None):
    """Renew expiring sessions first; retry a rejected GET at most once."""
    entry, preview, url, headers, body = build_request(catalog, args, config)
    if preview:
        raise InputError("Execution requires a non-preview request.")
    authenticated_request = bool(entry["headers"].get("X-Auth-Token"))
    if authenticated_request and config.get("auth_requires_action"):
        return {"ok": False, "requires_action": True, "error": "Complete the pending Tinder verification before continuing."}
    can_renew = authenticated_request and config.get("refresh_token") and not os.environ.get("TINDER_AUTH_TOKEN")
    renewed = False
    if can_renew:
        if renew is None:
            from tinder_auth import ensure_session
            renew = ensure_session
        outcome, current = renew()
        if not outcome.get("ok"):
            return {"ok": False, "session": outcome, "error": "Tinder login needs attention; the requested account action was not sent."}
        config.update(current)
        renewed = outcome.get("renewed", False)
        entry, _, url, headers, body = build_request(catalog, args, config)
    result = transport(entry, url, headers, body, args.timeout)
    if result.get("status") == 401 and can_renew and not renewed:
        outcome, current = renew(force=True, prior_token=config.get("auth_token"))
        if not outcome.get("ok"):
            return {**result, "session": outcome}
        config.update(current)
        if entry["method"] == "GET":
            entry, _, url, headers, body = build_request(catalog, args, config)
            return {**transport(entry, url, headers, body, args.timeout), "session_renewed": True}
        return {**result, "session_renewed": True, "retry_needed": True,
                "error": "Session renewed after an authentication rejection. The account action was not automatically repeated."}
    return result


if __name__ == "__main__":
    sys.exit(main())
