---
name: tinder-control
description: Control the user's Tinder account through a reverse-engineered API, with login and automatic session renewal. Use for profiles, matches, messages, likes, passes, recommendations, updates, and location changes.
---

# Tinder Control

Use the bundled Python 3 helper to perform the requested Tinder operation. This skill supplies API controls; it does not configure a chat persona, reply policy, or recurring automation.

The endpoint catalog was adapted from an author-provided reverse-engineered Postman collection on 2026-11-01. Authentication follows the observed first-party web client protocol. Read [API details](references/api.md) for endpoint inputs and quirks, and [authentication](references/authentication.md) for first login and renewal. Sanitized request definitions are in [requests.json](references/requests.json).

## Login

Run `python3 <skill-directory>/scripts/tinder_auth.py status` for a secret-free local session summary. Existing account operations renew an expiring session automatically when a refresh credential is saved. For email login, start with `start-email --execute`, then follow the returned email and SMS verification steps. Read [authentication](references/authentication.md) for direct email/phone login, browser session import, and renewal; never send JSON to the protobuf login endpoint.

## Use

Resolve `scripts/tinder.py` relative to this SKILL.md. Run `python3 <skill-directory>/scripts/tinder.py list` to list the available controls.

Examples below assume the current directory is this skill directory:

```bash
python3 scripts/tinder.py profile
python3 scripts/tinder.py matches --query count=20
python3 scripts/tinder.py messages --var match_id=MATCH_ID
python3 scripts/tinder.py user --var user_id=USER_ID
python3 scripts/tinder.py send-message --var match_id=MATCH_ID --body-file /absolute/path/message.json --execute
python3 scripts/tinder.py like-user --var user_id=USER_ID --execute
python3 scripts/tinder.py pass-user --var user_id=USER_ID --execute
python3 scripts/tinder.py like-message --var message_id=MESSAGE_ID --execute
python3 scripts/tinder.py unlike-message --var message_id=MESSAGE_ID --execute
python3 scripts/tinder.py updates --var last_activity_date=2026-11-01T00:00:00Z --execute
python3 scripts/tinder.py location --var lat=LATITUDE --var lon=LONGITUDE --execute
```

`--dry-run` previews any operation. Non-GET requests preview unless `--execute` is supplied. A preview never sends a request. Use `--execute` when the user's request authorizes the selected action; no additional confirmation is needed for an already authorized action. Skill creation or installation by itself does not instruct the agent to contact matches or change the account.

`--var NAME=VALUE` binds URL/body placeholders. `--query NAME=VALUE` overrides or adds a query parameter. `--body-file` accepts a UTF-8 JSON file or `-` for standard input. Use structured file writing for message text so quotes, Unicode, and newlines survive intact.

## Resolve the target

Use live match, user, and message IDs returned by the account. Do not reuse sample IDs from Postman, fabricate IDs, or resolve an ambiguous name by guessing. The profile request's saved test locates the account ID at `data.user._id`; other response shapes have no saved examples, so inspect actual returned data.

For sending, read the selected conversation as needed for the user's request. The required message body is:

```json
{
  "userId": "ACCOUNT_USER_ID",
  "otherId": "MATCHED_USER_ID",
  "matchId": "MATCH_ID",
  "sessionId": null,
  "message": "Message text requested by the user"
}
```

The helper requires this explicit body and verifies its `matchId` matches the selected URL `match_id`. The saved Postman body constructs `matchId` by concatenating participant IDs; that is an unverified assumption. Prefer the actual match ID from the selected match.

## Credentials and results

The helper reads `TINDER_AUTH_TOKEN`, or `auth_token` from `~/.config/tinder-control/auth.json` (respecting `XDG_CONFIG_HOME`). `TINDER_AUTH_FILE` selects another private JSON file. Login securely saves the refresh credential, expiry, and stable device identity there as well. An explicit `TINDER_AUTH_TOKEN` overrides automatic renewal. Secrets stay outside this skill. Do not print credentials or copy them into the request catalog, chat, or ordinary artifacts.

Results contain HTTP `status` and parsed `data` when available. Treat an HTTP success as transport evidence; inspect the payload before claiming a message was sent or another action succeeded. No response schemas or cursor conventions were provided in the collection. Follow observed pagination fields only; a single matches page is not necessarily the entire inbox.

The helper refuses redirects and never automatically repeats account writes. It renews expiring sessions before sending an authenticated request. A rejected GET may renew and retry once on 401; a rejected write can renew but returns `retry_needed` without resending. It does not renew on 403. On 429 respect `retry_after`. A timeout or server error after a write may have an unknown outcome: inspect current state before considering another attempt, particularly for messages. Never run the entire source collection as a test.
