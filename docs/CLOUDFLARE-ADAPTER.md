# Cloudflare zones adapter

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

## Credential and network boundary

The adapter accepts a scoped token-provider capability. It rejects a credential
unless the provider binds it to the requested account. The token is injected
only into the fixed Cloudflare request and is not included in the business
result or safe errors.

The composed executor uses the shared pinned HTTPS transport. All DNS answers
must be public, the socket is pinned to a validated address, TLS hostname
verification remains enabled, redirects are not followed, and request time and
response size are bounded.

A production token should be an account-owned API token when the endpoint
supports it, limited to the necessary account or zones, `Zone Zone Read`, an IP
allowlist and an explicit lifetime. Global API keys and user passwords are not
supported by this adapter.

## Verification status

Tests cover parameter validation, account and execution binding, credential
scope, response projection, upstream failures, redirect denial, oversized and
invalid responses, pagination defaults, error redaction and the composed pinned
transport. The provider remains `contract_required`: no production token
resolver or isolated Cloudflare account contract has been configured or run.

Official references checked on 2026-09-09:

- [List Zones](https://developers.cloudflare.com/api/resources/zones/methods/list/)
- [Create API tokens](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)
- [Account API tokens](https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/)
