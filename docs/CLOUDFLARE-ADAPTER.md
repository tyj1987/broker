# Cloudflare inventory adapters

`cloudflare.zones.list@1.0.0` implements only Cloudflare's
`GET /client/v4/zones` operation. The operation requires the exact 32-character
Cloudflare account ID as `resource_ref`; that value is also sent as the
`account.id` filter and must match the verified execution capability and the
credential provider binding.

The caller can supply only an exact lowercase zone name and bounded pagination.
The adapter fixes `page` to at least 1 and `per_page` to Cloudflare's documented
range of 5 through 50. It returns only zone ID, name, status, type and paused
state plus integer pagination metadata. Nameservers, ownership, plans,
permissions and other upstream fields are discarded.

`cloudflare.dns.records.list@1.0.0` implements the fixed
`GET /client/v4/zones/{zone_id}/dns_records` operation. `resource_ref` and
`zone_id` must be the same registered 32-character zone ID. Automation may use
only exact name, type and proxied filters plus pagination capped at 100 records.
The result intentionally omits record content, comments, tags, settings and all
other upstream metadata; it releases only ID, type, name, TTL and proxied state.

## Credential and network boundary

The adapter accepts a scoped token-provider capability. It rejects a credential
unless the provider binds it to the requested account. The token is injected
only into the fixed Cloudflare request and is not included in the business
result or safe errors. DNS inventory additionally requires the zone ID to be
registered under the selected account and a zone-scoped `DNS Read` token.

The composed executor uses the shared pinned HTTPS transport. All DNS answers
must be public, the socket is pinned to a validated address, TLS hostname
verification remains enabled, redirects are not followed, and request time and
response size are bounded.

A production token should be an account-owned API token when the endpoint
supports it, limited to the necessary account or zones, `Zone Zone Read`, an IP
allowlist and an explicit lifetime. Global API keys and user passwords are not
supported by this adapter.

## Runtime activation

The Broker registers the executor only when `cloudflare:zones.list` is enabled,
uses `execution_mode: adapter`, has reviewed `contract_verified: true` evidence
and references an exact provider account. Configuration contains only the
account ID and allowed environments:

```yaml
provider_accounts:
  cloudflare:
    cloudflare-primary:
      account_id: 0123456789abcdef0123456789abcdef
      environments: [production]
      zones: [abcdef0123456789abcdef0123456789]
```

Plaintext token fields and unknown binding fields are rejected. Before making
the executor discoverable, startup probes the fixed
`/run/secret-broker-credentials/cloudflare.sock` boundary. The socket and its
parent directory must be controlled by an identity other than the Broker
process, inaccessible to other users and accessible through the Broker's
explicit supplementary group.

The versioned socket request contains only the provider, operation, account,
environment, resource, execution ID and canonical request binding. A response
must echo every binding and issue
a token lease with an absolute lifetime of at most five minutes. Malformed,
overlong, expired, wrongly bound or oversized responses fail closed. The token
can enter only the Broker adapter's memory for injection into the fixed
Cloudflare request; it is never returned to the Agent, written to configuration
or included in safe errors. A production-grade credential service and real
account contract test are still required before activation.

## Verification status

Tests cover parameter validation, account, zone and execution binding, credential
scope, response projection, upstream failures, redirect denial, oversized and
invalid responses, pagination defaults, error redaction and the composed pinned
transport. Runtime tests additionally cover exact configuration bindings,
credential-service preflight, atomic executor replacement, socket ownership,
lease expiry and response-binding failures. The provider remains
`contract_required`: no production credential service or isolated Cloudflare
account contract has been configured or run.

Official references checked on 2026-09-11:

- [List Zones](https://developers.cloudflare.com/api/resources/zones/methods/list/)
- [Create API tokens](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)
- [Account API tokens](https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/)
- [List DNS Records](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/)
- [API token permissions](https://developers.cloudflare.com/fundamentals/api/reference/permissions/)
