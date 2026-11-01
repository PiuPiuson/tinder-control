# Tinder Control

A Codex skill and standalone Python CLI for controlling your own Tinder account through a reverse-engineered API. Read profiles, matches, and conversations; send messages; like or pass; update location; and renew saved sessions automatically.

The helpers use Python's standard library. Python 3.9+ on macOS or Linux is required; authentication uses Unix file locking and permissions. A first login still requires the verification steps requested by Tinder.

## Install in Codex

Clone the repository into your skills directory:

```sh
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
git clone https://github.com/PiuPiuson/tinder-control.git \
  "${CODEX_HOME:-$HOME/.codex}/skills/tinder-control"
```

If that directory already exists, review your existing installation before replacing or updating it. Open a new Codex chat after installation and ask, for example:

> Use $tinder-control to help me sign in to my Tinder account, then show my matches.

The skill provides account controls. Installing it does not start conversations, configure a persona, or schedule activity.

## Use the CLI

Run these from the repository directory:

```sh
python3 scripts/tinder.py list
python3 scripts/tinder_auth.py status
python3 scripts/tinder.py profile --dry-run
python3 scripts/tinder.py matches --query count=20
python3 scripts/tinder.py messages --var match_id=MATCH_ID
```

See [authentication](references/authentication.md) for phone/SMS login, email verification, browser session import, and renewal. The browser import accepts an authorized login response captured by your browser tooling; this repository does not include a browser driver. If you already have an API credential, the helper also accepts `TINDER_AUTH_TOKEN` from your environment.

Credentials live outside the repository in `~/.config/tinder-control/auth.json`, with mode `0600`. `XDG_CONFIG_HOME` or `TINDER_AUTH_FILE` can select another location. Never commit that file or raw login captures. API responses can contain personal data even when authentication secrets are redacted.

GET operations run by default. Other operations preview unless `--execute` is supplied; `--dry-run` always previews. For example:

```sh
python3 scripts/tinder.py send-message \
  --var match_id=MATCH_ID --body-file /absolute/private/message.json
```

The required message body and full operation list are in [SKILL.md](SKILL.md) and the [API reference](references/api.md). Use IDs from your live account. Add `--execute` only when you intend to perform the selected action. Account writes are never retried automatically.

## Status and limitations

- Browser email login followed by an existing-phone SMS challenge, session import, a direct refresh exchange, and a read-only profile check were verified on 2026-11-01.
- The refresh exchange was tested with a fresh session. Renewal at the actual expiry boundary has not yet been observed live.
- Direct phone login returned a successful SMS-sent flag, but delivery was not confirmed. A server flag does not establish delivery.
- Other account operations come from the sanitized request catalog and offline construction tests; they have not all been exercised live.
- The authentication helper follows the observed **web** client protocol. Native iOS/Android parity is unverified. CAPTCHA and unsupported verification steps require completion in Tinder.
- This is an unofficial project, unaffiliated with Tinder. The observed endpoints and client protocol can change.

## Tests and contributions

```sh
python3 -m unittest discover -s tests -v
```

The tests use synthetic identities and mocked transports; they do not contact Tinder. Contributions should include reproducible offline cases and sanitized protocol evidence. Do not attach credentials, phone numbers, private conversations, raw browser traces, or exported personal collections to issues or pull requests.

Endpoint definitions were adapted from an author-provided Postman collection. The protobuf codec is independently implemented from observed field mappings; first-party source links are documented in [authentication](references/authentication.md). No Tinder client bundles are distributed.

## License

[MIT](LICENSE).
