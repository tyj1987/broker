# GitHub repository adapter

`github.repository.read@1.0.0` is the first credential-isolated provider
adapter. It implements only GitHub's `GET /repos/{owner}/{repo}` operation and
returns the bounded `id`, `full_name`, `visibility` and `archived` projection.

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

The repository does not yet contain a production token minter or live account
configuration. A production implementation must scope the installation-token
request to the named repository and use only Metadata read permission. The App
JWT signer must be backed by a non-exportable workload/KMS identity; adding a
private key to source, ordinary configuration, logs or an Agent response is
prohibited.

## Verification status

Unit contract tests cover path and target injection, execution-binding
tampering, missing/wrong/expired/overlong leases, redirect denial, upstream
status mapping, invalid and oversized responses, bounded projection and error
redaction. The provider manifest remains `contract_required` until an isolated
GitHub App account passes a real request and revocation test.

Official references checked on 2026-09-09:

- [Get a repository](https://docs.github.com/en/rest/repos/repos#get-a-repository)
- [Authenticate as a GitHub App installation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)
- [Choose GitHub App permissions](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app)
