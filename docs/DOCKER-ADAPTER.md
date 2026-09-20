# Docker repository tags adapter

`docker.repository.tags.list@1.0.0` lists at most 100 tags for one exact Docker
Hub repository. The caller supplies a lowercase namespace and repository, and
`resource_ref` must equal `namespace/repository`. The execution grant, account
binding and token lease must all match that same repository.

The adapter fixes the origin to `https://registry-1.docker.io`, method to
`GET`, path to `/v2/{namespace}/{repository}/tags/list?n=100`, response size to
1 MiB and redirect handling to deny. The injected token provider may return
only a short-lived registry bearer token scoped to
`repository:{namespace}/{repository}:pull`; its declared expiry must be valid
and no more than five minutes away. AI callers never receive that token.

Repository components follow the Distribution Registry name grammar. The
response repository name must exactly match the authorization and every tag
must match the bounded tag grammar. Duplicate, excessive, malformed or
wrong-repository output fails closed. Error bodies, authentication challenges
and transport details are not returned.

The current executor uses the common DNS-validating, address-pinned HTTPS
transport with TLS hostname verification.

## Runtime activation

The executor becomes discoverable only when `docker:repository.tags.list` is
enabled with `execution_mode: adapter`, reviewed `contract_verified: true`
evidence and an exact account binding. Configuration stores repository and
environment metadata only:

```yaml
provider_accounts:
  docker:
    docker-primary:
      environments: [production]
      repositories: [tyj1987/broker]
```

Unknown fields, plaintext token fields, duplicate repositories and invalid
repository names fail configuration loading. Startup must also validate the
fixed `/run/secret-broker-credentials/docker.sock` boundary before registering
the executor. Credential lease requests bind the exact account, environment,
operation and repository. Responses must echo those values and expire within
five minutes; the adapter then independently verifies repository and expiry
again before using the token.

Deterministic tests cover the fixed request, scoped lease, expiry, redirects,
errors, projection, size bounds, pinned transport, exact runtime bindings,
credential-service preflight and atomic executor replacement. A production
credential service, real Docker Hub token exchange and isolated account
contract have not run, so the provider remains `contract_required`.
