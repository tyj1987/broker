# MCP typed-task bridge

The MCP server exposes only executable `/api/v2` Broker tools and task lifecycle
controls. It does not list or resolve secrets, run credential checks, accept an
arbitrary service URL or proxy caller-selected HTTP methods and paths.

At startup the bridge reads a pre-provisioned, least-privilege Broker API key
from `--api-key-file`. Command-line key values, environment master keys and
automatic child-key issuance are rejected. The key should be limited to the
exact operations, accounts, resources and environments required by that MCP
workload, have a short absolute lifetime and be rotated outside the Agent
process. Optional client certificate, private-key and CA files enable mTLS to
the Broker without placing their values in arguments or logs.

`tools/list` is derived from the running Broker's executable-tool view. For an
API-key identity, that view is intersected with the key's scopes, services,
operations and environments, and requires non-empty account and resource
constraints; missing key metadata fails closed. Each entry receives a stable MCP name and a closed input schema
containing the registered typed parameters plus `account_ref`, `environment`
and an explicit idempotency key. Calling an entry creates a task. A `READY` task
is run once; an approval-gated task is returned without bypassing approval.
Separate MCP controls read, run, cancel or inspect events for an existing task.

The local MCP listener binds only to loopback, rejects every request carrying a
browser `Origin`, validates the `Host` header, emits no CORS permission, accepts
JSON only, limits bodies and batches, and returns no upstream error body. Every
request also requires an independent high-entropy bearer capability loaded from
`--listener-token-file`; it is compared in constant time and cannot equal the
Broker API key. This prevents another local process from silently borrowing the
MCP workload's Broker authority. The
Broker client permits only fixed `/api/v2/tools` and `/api/v2/tasks` paths,
always verifies TLS and bounds requests, responses and time. Broker failures
expose only a validated machine-readable error code to the MCP caller. Response
messages and all other upstream body fields are discarded, so an orchestrator
can route retry or approval handling without receiving provider details or
credential material.

The old `healthcheck.upstream: mcp_server` setting is rejected. Credential
health checks remain inside the Broker's controlled local implementation until
a typed, provider-specific health operation is registered. This prevents a
secondary MCP process from resolving credentials merely to test them.

The file-backed API key is a migration boundary, not the target identity
design. Production enablement requires DQ-008, workload attestation and a
short-lived identity exchange. Until then the MCP server must remain local and
must not receive a master key.
