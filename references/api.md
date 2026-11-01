# API reference

Source: author-provided reverse-engineered Postman definitions, captured on 2026-11-01. These observations are not a verified public API contract. Personal collection identifiers and saved credentials are excluded.

| Operation | HTTP request | Inputs |
| --- | --- | --- |
| profile | GET /v2/profile | none |
| matches | GET /v2/matches | optional query overrides |
| messages | GET /v2/matches/{match_id}/messages | match_id |
| user | GET /user/{user_id} | user_id; source says an existing match is required |
| send-message | POST /user/matches/{match_id} | match_id and explicit message body |
| like-message | POST /message/{message_id}/like | message_id |
| unlike-message | DELETE /message/{message_id}/like | message_id |
| like-user | POST /like/{user_id} | user_id |
| pass-user | POST /pass/{user_id} | user_id |
| my-likes | GET /v2/my-likes | none |
| fast-match | GET /v2/fast-match | none; source description duplicates my-likes, semantics unverified |
| updates | POST /updates | last_activity_date; nudge=false |
| location | POST /v2/meta | lat and lon as numbers |
| recommendations | GET /v2/recs/core | none |
| explore | GET /v2/explore | none |
| generate | GET /ws/generate | purpose undocumented; may generate a token |
| login | POST /v3/auth/login | binary protobuf; use tinder_auth.py, see authentication.md |

All operations except login use `X-Auth-Token`. Defaults are `https://api.gotinder.com` and locale `en-GB`. Matches retains its source locale `en`, count `2`, message `1`, is_tinder_u `false`, and include_conversations `true`; override explicitly when needed. Messages retains count `200` and message `0`. No saved pagination or response examples establish completeness.

## Source adaptations

- All request authentication uses one runtime token. Get Matches had a separate hardcoded token and copied cURL secrets in its description; those were excluded. Credentials are supplied at runtime or issued by the login gateway.
- No sample match/user/message IDs, message text, location, or update timestamp is used as an execution default.
- Source message-body concatenation is retained as provenance in requests.json, but execution requires an explicit body with a matching authoritative match ID.
- Source enabled headers and query values are retained. The transport requests identity encoding because the standard-library client does not decode Brotli. JSON bodies use Content-Type application/json.
- Embedded Postman scripts are never executed. The Profile script's documented account-ID extraction is handled by the agent from the response.
- Login has no body in the original collection. Current Tinder-hosted client code establishes that it uses protobuf, not JSON; the dedicated authentication helper implements direct email/SMS login, phone login, and refresh. Generate remains a low-level saved operation with undocumented response semantics.

## Maintenance

For authentication, follow [authentication.md](authentication.md). The helper atomically updates the private auth file with mode 0600 and preserves unrelated configuration. Manual `TINDER_AUTH_TOKEN` remains supported and disables automatic renewal.

When an endpoint changes, compare its sanitized definition with the current first-party client or your own authorized Postman collection. Remove credentials and personal examples before updating `requests.json`, and validate request construction offline before use. Never copy raw collection variables, headers, descriptions, or captured responses into the repository. The code does not require access to the original private collection.
