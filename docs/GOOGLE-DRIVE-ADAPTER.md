# Google Drive document adapter

`google_drive.document.read@1.0.0` exports one explicitly authorized Google
Workspace document as plain text. The caller supplies only the exact file ID as
`resource_ref`; it cannot select an origin, URL, method, MIME type, OAuth scope,
header or export size.

The adapter uses Google's fixed `files.export` endpoint, requires the
per-file `drive.file` scope, denies redirects and accepts at most 1 MiB even
though the upstream API allows larger exports. The credential capability must
be bound to the same account, environment and file, and must expire within five
minutes. The pinned HTTPS transport validates every DNS answer and the TLS
hostname before sending the bearer token.

Document text is not returned directly from the transport. An injected content
release filter must approve the exact file and return only a bounded plain-text
result plus its redaction count. Missing, failed, malformed or non-approving
filter results fail closed. The Broker applies its known-secret redactor again
after that boundary as defense in depth. Raw document bytes and access tokens
are never included in task events or error messages.

Google recommends `drive.file` for narrow per-file access. Broad `drive` and
`drive.readonly` scopes are restricted and are not accepted by this operation.
Production enablement additionally requires:

- an authoritative mapping from Broker account and file references to an exact
  Drive principal and share;
- workload identity federation or another short-lived token issuer whose
  signing material is unavailable to the Broker process;
- a separately isolated content-classification and release service with tests
  for tenant isolation, prompt injection, credentials, personal data and
  classifier outage;
- isolated-account tests proving wrong-file denial, share revocation, token
  expiry, export limits, redirect denial, audit redaction and cancellation.

The current implementation and deterministic tests are source evidence only.
No live Drive account, production token issuer or production content filter is
enabled, so the provider remains `contract_required`.
