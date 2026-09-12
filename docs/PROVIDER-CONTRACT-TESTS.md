# Isolated provider contract tests

Provider operations remain `contract_required` until a real isolated account
has passed the active-path and revocation checks defined for that provider.
Passing unit tests or enabling a tool in the registry is not contract evidence.

The first executable contract runner covers these read-only operations:

- `github.repository.read@1.0.0`
- `aliyun.ecs.instances.list@1.0.0`

For one exact provider, account, environment and resource binding, the runner
checks registry discovery, one bounded read, secret-free output, wrong-account
denial and wrong-resource denial. It issues only typed `/api/v2/tasks` requests.
It cannot submit a URL, authentication header, provider credential or arbitrary
operation. An unexpected negative task is cancelled when possible and the run
still fails.

## Protected invocation

The JSON plan and every credential input are absolute file paths supplied by
the operator's existing protected local channel. Credential values are not
accepted as command-line arguments or environment variables. A representative
invocation is:

```console
npm run provider:contract -- \
  --broker https://broker.52trz.com \
  --plan-file /protected/dq004-plan.json \
  --api-key-file /protected/broker-api-key \
  --client-cert-file /protected/client.crt \
  --client-key-file /protected/client.key \
  --ca-file /protected/broker-ca.crt
```

The plan is an external evidence input and must not be committed. It contains
only account and resource references, never credentials. The command emits a
small pass/fail receipt containing provider, operation, environment and check
names. It omits account references, resource references and provider results.
Failures emit only a stable contract error code.

The operator must retain the signed plan digest, exact release SHA, timestamp,
provider-side audit event references and the safe receipt outside the source
repository. The runner does not collect or print those external references.

## Evidence boundary

This runner proves the active read path and two authorization boundaries only.
Provider-side credential or role revocation, rotation overlap, wrong-workload
denial, regional outage behavior and audit continuity are separate required
phases. A passing receipt alone must not change a provider manifest from
`contract_required` to `production`.

The 2026-09-12 production capability probe did not run either provider
operation: the deployed registry exposed only `broker.tools.inspect`, and both
requested provider bindings were denied before execution. That result is a
safe fail-closed observation, not a completed DQ-004 contract test.
