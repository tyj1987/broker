# V4.1.1 Error Code Registry

> **Reference for SDK users.** When you receive a `BrokerError` with a
> `code` field, this document tells you exactly what it means, what HTTP
> status it carries, and how to handle it.
>
> All 4 SDKs (Python, Go, Node CLI, VSCode) auto-pass-through the `code`
> field from broker response body to `BrokerError.code`. See
> [SDK-REFERENCE.md §V4.1.1 SDK parity](SDK-REFERENCE.md#v411-sdk-parity)
> for the unified contract.

## How errors are returned

All broker error responses follow this JSON shape:

```json
{
  "error": {
    "code": "<machine-readable code>",
    "message": "<human-readable message>"
  }
}
```

Plus HTTP status (e.g. `401`, `403`, `404`, `429`, `5xx`) and headers
(`X-Request-Id`, `Retry-After`).

V4.1.1 SDKs parse this into a single `BrokerError` class with:
- `e.status` (HTTP status code)
- `e.code` (machine-readable string from this registry)
- `e.requestId` (X-Request-Id)
- `e.retryAfter` (seconds, 0 if absent)
- `e.is_retryable` (true for 5xx / 429)
- `e.message` (human-readable)
- `e.body` (redacted full body)

---

## Error code index

| Code | HTTP | isRetryable | Category | Description |
|------|------|-------------|----------|-------------|
| `auth_failed` | 401 | false | Auth | Wrong username/password, or invalid client cert |
| `mfa_required` | 401 | false | Auth | Login needs MFA code (TOTP / WebAuthn / SMS / recovery) |
| `mfa_invalid` | 401 | false | Auth | MFA code wrong or expired |
| `session_expired` | 401 | false | Auth | Session cookie expired; re-login required |
| `cert_required` | 401 | false | Auth | Endpoint requires mTLS client cert |
| `cert_invalid` | 401 | false | Auth | mTLS client cert not signed by trusted CA |
| `cert_expired` | 401 | false | Auth | mTLS client cert past its notAfter |
| `permission_denied` | 403 | false | Authz | Authenticated but lacks permission for this resource |
| `forbidden` | 403 | false | Authz | Access denied by policy (IP allowlist, etc.) |
| `not_found` | 404 | false | Resource | Secret / client / service / config not found |
| `conflict` | 409 | false | Resource | Resource already exists or version mismatch |
| `validation_failed` | 400 | false | Request | Request body / params failed schema validation |
| `bad_request` | 400 | false | Request | Generic 400 (e.g. malformed JSON) |
| `unsupported_media_type` | 415 | false | Request | Content-Type not `application/json` |
| `payload_too_large` | 413 | false | Request | Request body > limit (default 1 MB) |
| `rate_limited` | 429 | **true** | Throttle | Per-tenant or per-IP rate limit exceeded; honor Retry-After |
| `unavailable` | 503 | **true** | Server | Broker temporarily unavailable (overloaded / restarting) |
| `bad_gateway` | 502 | **true** | Server | Upstream (proxy / workload identity) error |
| `gateway_timeout` | 504 | **true** | Server | Upstream timed out |
| `internal_error` | 500 | **true** | Server | Generic 500 (unexpected exception) |
| `not_implemented` | 501 | false | Server | Endpoint not yet implemented |
| `service_unavailable` | 503 | **true** | Server | Alias for `unavailable` |
| `mfa_method_unavailable` | 400 | false | Auth | Requested MFA factor not configured (e.g. SMS disabled) |
| `approval_required` | 403 | false | Authz | High-risk operation needs two-person approval (WebAuthn grant) |
| `approval_invalid` | 403 | false | Authz | Approval grant expired / wrong session / wrong payload |
| `webauthn_required` | 401 | false | Auth | Strict mode requires WebAuthn login (not password) |

---

## Per-code reference

### Auth (`401`)

#### `auth_failed`

- **HTTP**: 401
- **is_retryable**: false
- **When**: Wrong password, wrong username, invalid mTLS client cert.
- **SDK handling**:
  ```python
  except BrokerError as e:
      if e.status == 401 or e.code == "auth_failed":
          # Re-prompt user for credentials, or call login() again
          ...
  ```
- **V4.1.0 → V4.1.1**: No change. Same code.

#### `mfa_required`

- **HTTP**: 401
- **is_retryable**: false
- **When**: Login succeeded but broker's `mfa_policy.is_required()` returned true.
  Response body includes `mfa_token` and `factor` (TOTP / WebAuthn / SMS / recovery).
- **SDK handling**:
  ```python
  except BrokerError as e:
      if e.code == "mfa_required":
          # Re-call login with mfa_token + mfa_code
          c.login(user, pw, mfa_token=e.body["mfa_token"], mfa_code="123456")
  ```
- **V4.1.0 → V4.1.1**: No change.

#### `mfa_invalid`

- **HTTP**: 401
- **is_retryable**: false
- **When**: MFA code wrong or already used (one-time).
- **SDK handling**: Re-prompt for code; do not retry blindly.

#### `session_expired`

- **HTTP**: 401
- **is_retryable**: false
- **When**: Session cookie's `exp` passed (12h absolute) or 15-min inactivity.
- **SDK handling**:
  ```python
  except BrokerError as e:
      if e.code == "session_expired":
          c.login(username, password)  # re-authenticate
  ```

#### `cert_required` / `cert_invalid` / `cert_expired`

- **HTTP**: 401
- **is_retryable**: false
- **When**: mTLS endpoint hit without / with invalid / with expired client cert.
- **SDK handling**:
  - Verify cert path, CA, and notAfter date.
  - Run `openssl x509 -in cert.crt -noout -text` to inspect.
  - Re-issue via `broker cert issue` (admin tool).

### Authz (`403`)

#### `permission_denied`

- **HTTP**: 403
- **is_retryable**: false
- **When**: Authenticated user lacks the role/scope for this resource.
- **SDK handling**: Log + alert admin. Do not retry. User must request
  permission from broker admin.

#### `forbidden`

- **HTTP**: 403
- **is_retryable**: false
- **When**: Access denied by `ip-allowlist`, time-of-day policy, or
  proxy / workload-identity policy.
- **SDK handling**: Surface to user with explanation. Do not retry.

#### `approval_required` / `approval_invalid`

- **HTTP**: 403
- **is_retryable**: false
- **When**: Strict mode + sensitive operation (client create / cert
  rotate / secret update) requires 2-person approval. The requester
  must request approval; a second admin must approve via WebAuthn grant.
- **SDK handling**:
  - `approval_required`: Open approval flow (UI / CLI / API). Wait for
    second admin to approve. Retry the original request with the
    approval grant attached.
  - `approval_invalid`: Approval grant expired / wrong session / wrong
    payload. Re-request approval.

#### `webauthn_required`

- **HTTP**: 401
- **is_retryable**: false
- **When**: Strict mode enforces WebAuthn login (password disabled for
  this user). User must log in via WebAuthn (e.g. YubiKey).
- **SDK handling**: Use `c.login_webauthn(challenge_response)` instead
  of `c.login(user, pw)`.

### Resource (`404` / `409`)

#### `not_found`

- **HTTP**: 404
- **is_retryable**: false
- **When**: Secret / client / service / config does not exist.
- **SDK handling**:
  ```python
  except BrokerError as e:
      if e.status == 404 or e.code == "not_found":
          # Secret name typo, or it was deleted
          # Check available secrets via c.list()
          ...
  ```

#### `conflict`

- **HTTP**: 409
- **is_retryable**: false
- **When**: Resource already exists (e.g. creating client with duplicate
  name) or version mismatch (optimistic locking).
- **SDK handling**:
  - For duplicates: change name or update existing resource.
  - For version mismatch: re-fetch current state, re-apply diff, retry.

### Request (`400` / `413` / `415`)

#### `validation_failed`

- **HTTP**: 400
- **is_retryable**: false
- **When**: Request body / params failed JSON schema validation.
  Response body includes per-field error details.
- **SDK handling**: Inspect `e.body` for field-level errors. Fix client.

#### `bad_request`

- **HTTP**: 400
- **is_retryable**: false
- **When**: Generic 400 (malformed JSON, missing required field, etc.).
- **SDK handling**: Log + fix client.

#### `payload_too_large`

- **HTTP**: 413
- **is_retryable**: false
- **When**: Request body > 1 MB (configurable via `limits.body` in broker.yaml).
- **SDK handling**: Reduce request body size (chunked upload if needed).

#### `unsupported_media_type`

- **HTTP**: 415
- **is_retryable**: false
- **When**: `Content-Type` header not `application/json`.
- **SDK handling**: Set `Content-Type: application/json`.

### Throttle (`429`)

#### `rate_limited`

- **HTTP**: 429
- **is_retryable**: **true** (V4.1.1 SDKs auto-retry)
- **When**: Per-tenant (`limits.tenant_per_minute`) or per-IP
  (`limits.ip_per_minute`) limit exceeded.
- **Response header**: `Retry-After: <seconds>` (V4.1.1 SDKs honor this)
- **SDK handling**:
  ```python
  except BrokerError as e:
      if e.code == "rate_limited":
          # V4.1.1 SDK already retried up to max_retries
          # (using Retry-After for backoff, then exponential)
          # Surface to user: "service throttled, please try again later"
          ...
  ```
- **V4.1.0 → V4.1.1**: V4.1.0 SDKs ignored `Retry-After`. V4.1.1 SDKs
  honor it (thundering-herd prevention).

### Server (`5xx`)

#### `unavailable` / `service_unavailable`

- **HTTP**: 503
- **is_retryable**: **true** (V4.1.1 SDKs auto-retry)
- **When**: Broker overloaded or restarting (e.g. graceful shutdown in
  progress).
- **SDK handling**: V4.1.1 SDK retries with exponential backoff.

#### `bad_gateway`

- **HTTP**: 502
- **is_retryable**: **true**
- **When**: Upstream (proxy / workload identity / OIDC) returned error.
- **SDK handling**: Retry; if persistent, log upstream name + alert ops.

#### `gateway_timeout`

- **HTTP**: 504
- **is_retryable**: **true**
- **When**: Upstream timed out (proxy / OIDC > 30s default).
- **SDK handling**: Retry with longer backoff; consider lowering request
  scope (e.g. fewer secrets in bulk resolve).

#### `internal_error`

- **HTTP**: 500
- **is_retryable**: **true**
- **When**: Unexpected broker exception. Response includes request_id;
  broker audit log has stack trace (visible to admin only).
- **SDK handling**: Retry; report `request_id` to broker admin for
  correlation with audit log.

#### `not_implemented`

- **HTTP**: 501
- **is_retryable**: false
- **When**: Endpoint declared in OpenAPI but not yet implemented.
- **SDK handling**: Surface to developer. Do not retry.

---

## New error codes per V4.1.0 → V4.1.1

V4.1.1 introduces no new error codes. V4.1.1 changes the **error model**
(from 6 typed classes to single `BrokerError` + structured fields); the
underlying codes broker returns are unchanged.

V4.1.0 → V4.1.1 SDK migration: instead of catching `BrokerAuthError`,
catch `BrokerError` and check `e.code === "auth_failed"`. See
[SDK-UPGRADE-GUIDE.md](SDK-UPGRADE-GUIDE.md) for full migration.

---

## How to handle a new error code

When broker adds a new error code (in a future release):

1. **Read the docs**: This file is updated with each new code. Check
   [CHANGELOG.md](../CHANGELOG.md) for "Added error code" entries.
2. **Match on `e.code`** (preferred) or `e.status`:
   ```python
   if e.code == "<new_code>":
       # handle new case
   ```
3. **Add a test**: Update your SDK client test to cover the new code
   (using `parse_broker_error` factory — see
   [examples/v4.1.1_error_handling.py](../sdk/python/examples/v4.1.1_error_handling.py)).
4. **File an issue** if the new code is missing context (e.g.
   description, recommended action).

---

## Reference

- [SDK-REFERENCE.md §V4.1.1 SDK parity](SDK-REFERENCE.md#v411-sdk-parity) — unified `BrokerError` contract
- [SDK-UPGRADE-GUIDE.md](SDK-UPGRADE-GUIDE.md) — V4.1.0 → V4.1.1 SDK migration
- [CHANGELOG.md](../CHANGELOG.md) — error code additions per release
- [docs/openapi.yaml](openapi.yaml) — full OpenAPI spec with response codes
- [broker/lib/http.js](../broker/lib/http.js) — broker's error response builder
- [broker/lib/audit.js](../broker/lib/audit.js) — audit log shape (includes `code`)

---

**Document version**: 2026-09-06 (V4.1.1 release prep)
**Last verified against**: broker source (broker/server.js + broker/lib/*.js)
**Maintained by**: broker maintainers
