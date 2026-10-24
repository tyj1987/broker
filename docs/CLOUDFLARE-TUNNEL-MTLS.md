# Cloudflare Tunnel mTLS bridge

Broker can keep its existing private-CA mTLS for direct/LAN clients while also
accepting a Cloudflare-managed client certificate that was validated at the
Cloudflare edge and forwarded through the existing Tunnel.

This bridge is disabled unless all three environment variables are set:

```text
BROKER_FORWARDED_MTLS_SOURCE_IP=<exact immediate Tunnel connector address seen by nginx>
BROKER_FORWARDED_MTLS_FINGERPRINT_SHA256=<64 hex characters, no wildcards>
BROKER_FORWARDED_MTLS_CLIENT=<existing Broker client name>
```

nginx keeps `ssl_verify_client optional`. A browser that presents the approved
client certificate still signs in through that certificate. A browser that
presents no certificate reaches the dashboard and can use password login, when
`allow_password_login` is set, or a WebAuthn security key. Strict-profile writes
still require that security key.

The Cloudflare hostname used by the dashboard must allow a request that has no
client certificate. A WAF rule that blocks every unverified client certificate
stops those browsers before nginx, so Broker never sees the login. Keep
certificate checks for workloads that authenticate with the Cloudflare client
certificate: a presented certificate that is revoked, malformed, or not the
approved fingerprint still fails closed.

When a verified certificate is present, a request header Transform Rule
overwrites `Client-Cert` with `cf.tls_client_auth.cert_rfc9440` for that exact
certificate. Broker does not trust `Client-Cert` merely because the header
exists. The connection from nginx to Broker must already satisfy
`trusted_proxy_fingerprints`, and nginx must have overwritten `X-Forwarded-For`
with the immediate peer IP. That exact peer must equal
`BROKER_FORWARDED_MTLS_SOURCE_IP`. Broker then parses the RFC 9440 leaf
certificate, recomputes its fingerprint, and maps it only to the configured
existing client.

A trusted Tunnel request with nginx client verification `NONE` and no
`Client-Cert` header can continue with an existing browser session. It cannot
continue with a bearer API key alone. A presented certificate that does not
validate still fails closed and does not fall through to a session. A presented
certificate that does validate is an edge-forwarded mTLS identity: API and
proxy routes still require it to satisfy the configured proof-of-possession
policy (`security.require_pop`). Omitting the certificate does not create that
identity and does not bypass the policy. Existing direct private-CA mTLS
remains unchanged, including when it originates from the same host address.

Do not use this feature to trust arbitrary proxy headers, a CIDR, a wildcard
fingerprint, or a client name that is not already present in Broker config. Do
not disable origin TLS verification to make the Tunnel work. Keep a rollback
copy of the origin/Tunnel configuration and test valid-certificate, no-certificate,
wrong-certificate, forged-header, direct-LAN, and revoked-certificate paths before
production cutover.
