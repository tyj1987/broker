# Forwarded certificate proof-of-possession

This implementation converges a previously deployed PoP contract into the mainline source without copying site-specific certificate fingerprints. It preserves the current direct private-CA and RFC 9440 paths and adds an explicitly selected deployment-compatible header. It is not proof that a particular site's Nginx/Cloudflare configuration has been migrated or deployed.

## v1 wire contract

The header is `X-Broker-PoP: v1:<unix_seconds>:<canonical_base64_signature>`. The signed UTF-8 message contains exactly these LF-separated fields, with no final newline:

```text
v1
UPPERCASE_METHOD
/path?raw=query
unix_seconds
```

RSA-SHA256 with PKCS#1 v1.5, ECDSA-SHA256 with DER signatures and supported RSA-PSS keys are verified against the already pinned forwarded leaf's public key. The time window is plus or minus 300 seconds. Invalid encodings, method/request-target changes, unsupported keys and out-of-window timestamps do not produce a verified proof.

The wire message has not been extended with a nonce or body digest. **v1 does not cryptographically bind request body bytes.** It is an additional possession check inside an already authenticated, narrowly trusted forwarding chain, not a replacement for TLS, request authorization or an end-to-end signed-operation protocol. A future body-bound version requires coordinated client/server migration; it must not be introduced by silently interpreting existing v1 signatures differently.

## Narrow forwarding trust

The origin must see an authorized loopback Nginx workload certificate in its configured proxy fingerprint list. The overwritten single-value `X-Forwarded-For` must exactly match the configured connector address. A forwarded certificate must match the configured leaf SHA-256 fingerprint and map to a current existing client. The parsed DER must match exactly, be a non-CA client-auth leaf and be within its validity interval.

| Runtime input | Meaning |
| --- | --- |
| `BROKER_FORWARDED_MTLS_SOURCE_IP` | Exact immediate connector address, as overwritten by trusted Nginx. |
| `BROKER_FORWARDED_MTLS_FINGERPRINT_SHA256` | Exact approved forwarded leaf fingerprint. |
| `BROKER_FORWARDED_MTLS_CLIENT` | Existing client name; no identity is created automatically. |
| `BROKER_FORWARDED_MTLS_HEADER` | `client-cert` by default; alternatively `x-broker-cf-client-cert`. No arbitrary header names. |
| `BROKER_FORWARDED_MTLS_OWNER_FINGERPRINT_SHA256` | Optional live owner-certificate anchor for the RFC 9440 default; **required** for the deployment-compatible header. It preserves the deployed mapping's revocation/rotation semantics. |

A partially specified feature configuration is rejected. Two competing certificate headers, a certificate from the wrong source, a proxy marker without trusted transport, or a changed owner anchor must not fall back to an unrelated session or key. The alternative header must be overwritten by the actual trusted Nginx configuration; accepting a name in application code does not prove the edge is configured correctly.

Site-specific values belong in the authorized deployment configuration, not in repository source, tests or public review artifacts. Do not remove the existing live mapping until equivalent new mappings and negative tests have passed in the actual deployment topology.

## Enforcement

The single gate runs before the public, typed-v2, login and compatibility dispatchers. It applies to identities explicitly identified as edge-forwarded. Ordinary direct TLS and Nginx-verified client-certificate identities retain their transport possession proof and do not require an extra application header.

`security.require_pop` supports:

- `off` (also missing/null/empty for backward compatibility): no additional PoP requirement.
- `privileged`: unverified forwarded identities may only GET the exact public dashboard assets, `/health`, `/api/v1/identity` and `/api/v1/services`.
- `all`: every request using an edge-forwarded identity needs a verified proof.

An unknown non-empty mode is invalid and denies affected forwarded requests, even when a proof is present; it never silently disables the control. Selecting `off` is an explicit compatibility/security decision, not a way to fix a failed production migration test.

## Replay and availability boundaries

Replay tracking binds the certificate identity, timestamp and canonical message digest, rather than signature bytes. A second valid randomized/ECDSA representation of the same message cannot bypass replay detection. The cache refuses additional proofs at its total or per-key capacity and never evicts still-valid proofs to make space. Expiry pruning retains state through the last accepted timestamp second.

The cache is process-local and not persisted. Restarting the process or routing to another replica can lose that replay state; cross-replica/restart replay protection requires a separately designed shared durable store. The capacity refusal is intentionally fail-closed and may reduce availability under load. With this nonce-free v1 format, identical requests signed in the same second are indistinguishable and the second request is rejected; clients must not assume such retries are safe.

## Verification evidence required before promotion

`broker-test/test-pop.js` generates test RSA/ECDSA/RSA-PSS keys and an OpenSSL client-auth leaf. It exercises real cryptographic verification, replay capacity and expiry, method/query binding, leaf validation, source/header ambiguity, owner-anchor invalidation and policy behavior. `test-compatibility-runtime.js` also checks the actual extracted pre-route guard precedes v2 and login handlers. These synthetic socket-metadata tests do not prove a real TLS, Cloudflare or Nginx handshake.

The existing mTLS test fixtures now explicitly describe the valid DER, validity and EKU properties required by the production checks; no negative assertion was removed. Before production promotion, verify the exact candidate with real trusted-proxy TLS, both supported certificate-header routes, incorrect-source and revoked/expired-leaf refusal, signed-client requests, and a rollback that restores the live mapping without re-enabling revoked credentials.
