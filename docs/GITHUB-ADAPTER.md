# GitHub repository adapter

The GitHub provider currently implements two credential-isolated, read-only
operations:

- `github.repository.read@1.0.0` calls `GET /repos/{owner}/{repo}` and returns
  the bounded `id`, `full_name`, `visibility` and `archived` projection.
- `github.branches.list@1.0.0` calls
  `GET /repos/{owner}/{repo}/branches` and returns at most 100 branch names,
  commit identifiers and protection flags. Pagination and the optional
  protection filter are typed and bounded.

The adapter fixes the origin to `https://api.github.com`, the method to `GET`,
redirect handling to manual denial, the response limit to 1 MiB and the API
version to `2026-03-10`. Owner and repository values are validated as path
segments. `resource_ref` must equal `owner/repo`, and the verified execution
capability must bind the same tool and target.

## Credential boundary

The adapter accepts a token-provider capability, not a caller credential. For
each execution that provider must return a GitHub App installation token lease
bound to the exact repository and expiring in no more than one hour. The token
is injected only into the fixed outbound request and is never returned in the
business result or included in safe errors.

`github-app-token-provider.js` implements the token-minting protocol behind
three injected capabilities: a pinned request transport, an account-binding
resolver and a non-exportable RS256 signer. The provider creates a short App
JWT and requests a token for exactly one repository. Its required permissions
are fixed when the provider is constructed, accept explicit read-only grants
only, and are checked exactly in the GitHub response and returned lease.
Repository metadata uses only `Metadata: read`; branch listing uses only
`Contents: read`. Account bindings must also match the requested environment
and repository.

The signer receives only the JWT signing input and binding metadata. It must
return signature bytes; the provider has no private-key loading API. The shared
HTTPS transport resolves and validates every destination address, pins one
validated address into the socket lookup, preserves TLS hostname verification,
denies redirects and bounds request/response sizes and time. Production KMS/HSM
signer, account configuration and runtime wiring are not yet included. Adding a
private key to source, ordinary configuration, logs or an Agent response is
prohibited.

## Verification status

Unit contract tests cover path and target injection, typed pagination and
filtering, bounded branch projection, execution-binding
tampering, App/account/environment/repository binding, JWT claims and algorithm,
invalid signer results, fixed read-only token permissions, missing/wrong/expired/overlong
leases, redirect denial, upstream status mapping, invalid and oversized
responses, bounded projection and error redaction. The provider manifest
remains `contract_required` until a production-grade signer and account binding
are configured, the transport is wired into the runtime, and an isolated GitHub
App account passes a real request and revocation test.

Official references checked on 2026-09-10:

- [Get a repository](https://docs.github.com/en/rest/repos/repos#get-a-repository)
- [Generate a JSON Web Token for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app)
- [Generate an installation access token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)
- [Authenticate as a GitHub App installation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)
- [Choose GitHub App permissions](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app)
- [List branches](https://docs.github.com/en/rest/branches/branches#list-branches)
