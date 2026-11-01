# Authentication

The helper implements Tinder's protobuf login gateway and persistent refresh-token flow. Current first-party web client code was inspected on 2026-11-01. It uses the same `/v3/auth/login` gateway seen in original mobile reverse-engineering work; current native iOS/Android client parity has not been established. The helper identifies itself as platform `web` and does not invent native device attestations or collector signals.

## Browser login and session import

On 2026-11-01 the live Tinder browser offered email login. Email verification led to an existing-phone SMS challenge for the unrecognized device. Completing both returned a terminal `loginResult`. This route successfully authenticated the intended account; a subsequent direct protobuf refresh and read-only profile identity check both returned HTTP 200. The refresh test used a fresh session, so expiry-boundary renewal has not yet been observed.

Use Tinder's normal browser flow when a first login is required and direct SMS delivery fails. Let the current page select its verification steps. Resolve the intended email/account from user input or confirmed account context; use an alternative identity only within the user's authorization. A masked-phone mismatch must be resolved before continuing. Retrieve only the current requested code from the user's answer or authorized connected inbox, and keep it out of logs. Never treat an accepted email code as the final login if Tinder still asks for SMS or another check.

Capture the response to the **final** `POST /v3/auth/login` submission in a private binary file. Capture its HTTP status, receipt timestamp, and actual request headers in a separate private JSON file:

```json
{
  "status": 200,
  "received_at": 1790000000.0,
  "headers": {
    "persistent-device-id": "<actual browser device ID>",
    "app-session-id": "<actual browser app-session ID>",
    "funnel-session-id": "<actual browser funnel-session ID>"
  }
}
```

The timestamp is an example only; use the actual response receipt time in Unix seconds. Attach the response listener before submitting the code so the terminal response is not lost. With Playwright CLI, return the capture from the `run-code` function; console.log inside that function is not returned as its result. Capture that result privately rather than emitting raw credentials into tool/chat output.

Import with:

`python3 scripts/tinder_auth.py import-browser --response-file /absolute/private/login.bin --input-file /absolute/private/login-meta.json --execute`

The importer preserves the response's original TTL origin and actual device identity, checks the account against an existing saved user ID, and writes atomically. Only `authenticated: true` establishes completion. After a successful import, close the temporary browser to avoid concurrent refreshes, perform one `refresh --execute`, and verify that a read-only profile response has the same account ID. Remove the temporary captures and code files. The long-lived credentials remain in the private auth file.

## Direct phone login

Resolve paths relative to the skill directory. Every network authentication step requires `--execute`; without it the helper returns a redacted preview.

1. Obtain the user's phone number in international format. Write `{"phone":"<international phone number>"}` to a private JSON input file, mode 0600. Then run:

   `python3 scripts/tinder_auth.py start --input-file /absolute/private/phone.json --execute`

2. Inspect the result. `sms_sent: true` means Tinder reported sending an SMS; delivery to the user's phone remains unconfirmed. State that distinction and do not claim the code arrived. If `next_step` is `verify-sms`, obtain the code the user received, write `{"otp":"<SMS code>"}` privately, and run:

   `python3 scripts/tinder_auth.py verify-sms --input-file /absolute/private/code.json --execute`

3. If Tinder requests `next_step: email`, obtain the existing account's email and submit `{"email":"<account email>"}` with the `email` command. If it returns `next_step: verify-email`, submit `{"otp":"<email code>"}` with `verify-email`. Carry forward the saved state; the helper retains the latest challenge credential.

4. Only `authenticated: true` indicates a complete login. Verification, account creation, social connection, and other unsupported states stop for user action in Tinder. Do not interpret HTTP 200 alone as a completed login or create an account to satisfy an unexpected onboarding state.

When using an alternative login method, compare any returned masked phone or account identity with the intended account. If they differ, resolve the mismatch with the user before completing verification or replacing the skill's saved credentials. Email verification alone can lead to an existing-phone SMS challenge; it is not necessarily a complete login.

Remove temporary phone/code input files after each step; no OTP is kept in the credential file. Never put OTPs, API tokens, refresh tokens, or protobuf bodies in shell arguments or logs. `--input-file -` accepts JSON on standard input when the execution environment can provide it securely.

For an explicit resend within a pending phone verification, use `python3 scripts/tinder_auth.py resend-sms --execute`. It uses Tinder's `phoneOtpResend` (or `existingPhoneOtpResend`) factor and preserves the same phone, device, and session. It never loops. A delivery problem is not proof of a malformed request or carrier fault. [Tinder's SMS troubleshooting guidance](https://www.help.tinder.com/hc/en-us/articles/115003498226-Can-t-verify-my-email-or-phone-number) notes delivery delays and recommends waiting a few hours before retrying when a text is missing.

## Renewal

`python3 scripts/tinder_auth.py status` reads local metadata without making a network call.

`python3 scripts/tinder_auth.py refresh --execute` performs one explicit renewal. The standard `tinder.py` controls also renew automatically when the stored API token expires within 30 seconds. A 401 on a GET can trigger one renewal and one retry; writes are never automatically repeated. 403 and 429 do not cause a renewal loop. When a refresh fails or requires verification, automatic renewal stops until the login issue is resolved. It never initiates an SMS automatically.

The gateway returns an API credential, a refresh credential, a user ID, and a TTL in **milliseconds**. Save rotated refresh credentials atomically. The private auth file stores expiry as Unix seconds, not milliseconds. The stable device ID survives process restarts; app-session and funnel-session IDs persist through a pending verification flow. File locking prevents simultaneous refresh attempts. Known account IDs must match before credentials replace an existing account's session.

Configuration is stored outside the skill at `~/.config/tinder-control/auth.json`, respecting `XDG_CONFIG_HOME` and `TINDER_AUTH_FILE`. It contains `auth_token`, `refresh_token`, `auth_token_expires_at`, `device_id`, `user_id`, and temporary `_login` state, plus any unrelated local configuration. An explicit `TINDER_AUTH_TOKEN` takes precedence and disables automatic renewal. Do not share this file.

## Protocol evidence

- [Tinder AuthService](https://tinder.com/static/build/l/chunks/pc-services-7f0e215269531bdf1b8b.js): phone/SMS/email factors; `refreshAuth` submits `{refreshAuth:{refreshToken}}` to the login endpoint.
- [Tinder protobuf schema](https://tinder.com/static/build/l/chunks/async-protobuf-schema-authgateway-8036d41ebaac5496c7d2.js): exact request/response field numbers and scalar wrappers. `auth_codec.py` independently implements the standard wire format using these field mappings.
- [Tinder main client](https://tinder.com/static/build/l/main-1a310f8f22184ab46370.js): `/v3/auth/login`, protobuf content type, session headers, credential storage, and `Date.now() + authTokenTtl` expiration calculation. Observed client version 7.40.0, build 1074000.
- [Tinder Security FAQs](https://www.help.tinder.com/hc/en-us/articles/115003957446-Security-FAQs): phone login requires SMS verification.

The request is HTTPS POST to `https://api.gotinder.com/v3/auth/login?locale=en-GB`, with `Accept` and `Content-Type` set to `application/x-protobuf`. Initial login does not require an existing API token. Session renewal sends only the saved refresh factor; it does not repeat phone verification unless Tinder requires another interactive step.

Phone input accepts `+` country-code notation from the user but sends digits-only international format in phone, phoneOtp, and phoneOtpResend. The [current Tinder phone-input component](https://tinder.com/static/build/l/chunks/51058-70f3b1b98aa88cddbbae.js) concatenates country code and local digits; its `+` is display-only. Existing saved numbers with a leading `+` are normalized when making requests.

Saved-client inspection and offline tests establish wire format and state handling. The browser email-plus-SMS login and subsequent direct refresh/profile check were verified live on 2026-11-01. Direct phone-first requests returned `smsSent: true` but delivery was not confirmed. Unsupported challenges are surfaced rather than silently bypassed.
