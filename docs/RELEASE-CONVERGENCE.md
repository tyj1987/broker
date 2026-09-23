# Mainline release convergence

This work implements the first bounded convergence step tracked in #42. It ports missing protections from a separately tested legacy candidate onto the current control-plane architecture. It is not a bulk merge of the legacy tree, a replacement for deployment validation, or a claim that the legacy candidate's end-to-end evidence applies to this revision.

## Preserved mainline contracts

The typed v2 operation, approval, execution-token and provider-policy pipeline is retained. Direct mTLS and trusted RFC 9440 forwarding keep their existing precedence and trust checks. Credentials continue to be narrowed by a supplied API key even when the transport or session identifies an administrator. Existing public-destination restrictions, DNS pinning, HTTPS verification, response-size limits, historical audit JSON compatibility, and immutable deployment/provenance mechanisms are not replaced with older implementations.

## Compatibility changes

| Boundary | Effective behavior |
| --- | --- |
| API-key expiry | Missing, malformed, elapsed and boundary-equal expiries fail closed. Existing configuration must contain an explicit valid expiry; absent expiry no longer creates an immortal credential. |
| Child credentials | Authentication requires exactly one live issuing master with matching ownership and current child-issuance authority. Parent revocation, expiry, deletion or invalidation immediately prevents child authentication. |
| Sessions | Authorization uses the current client record after configuration replacement. Removing the owner invalidates the session identity; cached login-time roles are not retained. This does not introduce new session lifetime guarantees. |
| Compatibility API keys | v1 keys may inspect their own identity, list or use delegated services/secrets with matching scopes, and use an authorized issuing master to request a child. They do not inherit account, certificate, operator, audit or sibling-key management privileges. Typed v2 routes continue through their existing policy pipeline. |
| Secret metadata | Listing and resolution use the same owner ACL and delegated-key intersection. An absent, malformed or empty non-admin resolve allowlist denies access. Explicit wildcards remain supported. |
| Service metadata | Non-admin and delegated identities see only permitted service names and minimal metadata, not upstream locations, secret references or secret-health detail. A path-restricted service may be discoverable without granting access to another path or method. |
| Service methods | Administrative CRUD preserves `allowed_methods`, including explicit empty deny-all arrays and partial updates. Omitted configuration retains the mainline GET/POST default. Client `allowed_proxy[].methods` is separately enforced on actual proxy calls. |
| MFA step-up | Once TOTP is enrolled, a password cannot replace the enrolled factor for certificate rotation or API-key issuance/revocation. Legacy password compatibility remains only where no TOTP factor is enrolled. |
| Rate limits | Both legacy string limits and minute/hour/day quota objects are enforced without counting the same cached request identity twice. Invalid configuration fails closed. Active buckets are not evicted to admit a new identity. |
| Proxy responses | Upstream cookies and hop-by-hop/Connection-nominated headers are removed. Browser sandbox, no-sniff and no-store protections cannot be replaced by upstream response headers. Encoded response bytes and their framing remain unchanged. |
| Configuration reload | Cached read-route dependencies follow the current configuration/cache, rather than preserving an old object reference. |

Clients using delegated keys for legacy account-management APIs must migrate to an appropriate authenticated management flow or the typed v2 operation contract. Do not restore old administrator inheritance to avoid a client migration.

Quotas remain process-local. They are not persistent, shared between replicas, or a guarantee of cluster-wide enforcement across restarts. Capacity protection may reject a request below its configured logical limit rather than permit unbounded memory use.

## Reuse and review boundaries

The service method CRUD behavior and its regression/documentation are forward-ported from #35, source commit `984db18ed250eb3a2592245af5c52de287485e85`; no second competing method-policy design is introduced. See [service HTTP methods](SERVICE-HTTP-METHODS.md).

The existing audit hash algorithm and historical JSON preimage compatibility remain unchanged. The legacy candidate's differently structured audit ledger is deliberately not copied over the mainline journal. Durable audit checkpoints, independent anchoring, journal migration and recovery need their own integration evidence and must not be claimed from this patch's passing unit tests.

This patch also does not claim completion of all legacy certificate-issuance persistence or TOTP enrollment/recovery-code transaction migrations. Those are release-readiness items, not reasons to weaken the tests or silently widen this change.

## Verification

Run the checked-in mainline toolchain (Node 24.20.0), install from the lockfile, then execute:

```sh
npm --prefix broker ci --ignore-scripts --no-audit --no-fund
node --check broker/server.js
node broker-test/test-release-convergence.js
node broker-test/test-compatibility-runtime.js
node broker-test/test-service-method-config.js
npm --prefix broker run lint
npm --prefix broker run test:coverage
npm --prefix broker audit --omit=dev --audit-level=high
npm --prefix broker run openapi:generate
git diff --exit-code -- contracts/openapi.yaml
git diff --check
```

The regression tests use synthetic identities and local temporary data. Some execute uniquely extracted production functions with injected test dependencies; these establish wiring/authorization behavior, not real TLS, SOPS or provider execution. They preserve typed v2 routing and the mainline operation suite. New standalone security helpers are included in the existing coverage gate without lowering thresholds.

A release decision must bind the exact reviewed commit and fresh CI evidence, compare the actual deployed revision rather than relying only on a GitHub deployment record, and exercise the chosen rollout and rollback path. Delegated automated review is not an independent human signature. No deployment is triggered by this document.
