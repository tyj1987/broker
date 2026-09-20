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

The Cloudflare side must enforce mTLS for the public hostname before origin
routing. A WAF rule must block requests when the certificate is not verified,
is revoked, or does not have the exact approved SHA-256 fingerprint. A request
header Transform Rule must then overwrite `Client-Cert` with
`cf.tls_client_auth.cert_rfc9440` for that exact verified certificate.

Broker does not trust `Client-Cert` merely because the header exists. The
connection from nginx to Broker must already satisfy `trusted_proxy_fingerprints`,
and nginx must have overwritten `X-Forwarded-For` with the immediate peer IP.
That exact peer must equal `BROKER_FORWARDED_MTLS_SOURCE_IP`. Broker then parses
the RFC 9440 leaf certificate, recomputes its fingerprint, and maps it only to
the configured existing client.

A request from the trusted Tunnel source with nginx client verification `NONE`
but without a valid forwarded certificate fails closed and cannot fall back to
a session or bearer API key. Existing direct private-CA mTLS remains unchanged,
including when it originates from the same host address.

Do not use this feature to trust arbitrary proxy headers, a CIDR, a wildcard
fingerprint, or a client name that is not already present in Broker config. Do
not disable origin TLS verification to make the Tunnel work. Keep a rollback
copy of the origin/Tunnel configuration and test valid-certificate, no-certificate,
wrong-certificate, forged-header, direct-LAN, and revoked-certificate paths before
production cutover.
