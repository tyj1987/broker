# Tool registry

`tools/registry.json` is the versioned control-plane inventory for executable
tools. Provider manifests describe upstream protocols; the tool registry adds
the authorization and operational constraints needed to expose an operation to
an authenticated caller.

Every registration includes:

- a stable name and semantic version;
- closed input and output schemas;
- provider and operation bindings;
- the minimum role, risk level, permitted environments and target binding;
- timeout and rate limits;
- approval and mandatory audit policies; and
- whether an agent identity may execute the tool.

The Node transition layer loads the registry before configuration or secrets.
Startup and configuration reload fail if an enabled operation is unregistered,
uses parameters absent from its registration, exceeds its registered
environments, or weakens a HIGH or CRITICAL approval requirement. Runtime
authorization repeats the relevant checks before consulting the Go policy
core. A missing registration is a denial, not a compatibility fallback.

Risk levels have these minimum controls:

| Risk | Minimum behavior |
|---|---|
| LOW | Explicit role, target, environment, schema, limit and audit policy |
| MEDIUM | LOW controls with narrower operational limits |
| HIGH | Approval is mandatory |
| CRITICAL | Agent execution is disabled, WebAuthn step-up is required, and approval is mandatory |

`GET /api/v2/tools` returns only registrations available to the authenticated
role and identity type. It contains protocol metadata, never credentials or
credential references.

Changes to the registry require the schema/risk regression test, generated
OpenAPI update and full security-core coverage gate. A registration does not
make an adapter production-ready: its provider manifest must still have a real
isolated-account contract result and the deployment acceptance gates must pass.
