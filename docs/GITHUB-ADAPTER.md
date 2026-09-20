# GitHub repository adapter

The GitHub provider implements five credential-isolated read-only operations
and one approval-gated write operation:

- `github.repository.read@1.0.0` calls `GET /repos/{owner}/{repo}` and returns
  the bounded `id`, `full_name`, `visibility` and `archived` projection.
- `github.branches.list@1.0.0` calls
  `GET /repos/{owner}/{repo}/branches` and returns at most 100 branch names,
  commit identifiers and protection flags. Pagination and the optional
  protection filter are typed and bounded.
- `github.commits.list@1.0.0` calls
  `GET /repos/{owner}/{repo}/commits` and returns at most 100 commit identifiers,
  commit times, signature-verification flags and optional GitHub login names.
  Branch/SHA, path, author, committer and time filters are typed and bounded.
  Commit messages, email addresses, signatures and signed payloads are excluded
  from the Agent-visible result.
- `github.issues.list@1.0.0` calls
  `GET /repos/{owner}/{repo}/issues` with typed state, actor, label, ordering,
  time and pagination filters. Because GitHub returns pull requests from this
  endpoint, `item_kind` explicitly selects issues, pull requests or both. Each
  title is marked `untrusted_external`; bodies, comments, email addresses and
  credentials are never projected.
- `github.workflow-runs.list@1.0.0` calls
  `GET /repos/{owner}/{repo}/actions/runs` using only `Actions: read`. Actor,
  branch, event, status, head SHA, pull-request exclusion, check-suite and
  pagination filters are typed and bounded. Workflow names are marked
  `untrusted_external`; pull-request payloads, jobs, logs and artifacts are not
  projected.
- `github.pull-request.create@1.0.0` calls
  `POST /repos/{owner}/{repo}/pulls` with an installation token limited to
  `pull_requests:write`. It accepts only a bounded title/body, validated head
  and base refs and a repository-matching `resource_ref`. Pull requests default
  to draft. The Tool Registry classifies this as HIGH and requires a human
  approval bound to the complete request before the executor can run.

The adapters fix the origin to `https://api.github.com`; read operations use
`GET` and pull-request creation uses `POST` on its single registered path.
Redirect handling is denied, responses are limited to 1 MiB and the API version
is fixed to `2026-03-10`. Owner and repository values are validated as path
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
are fixed when the provider is constructed and are checked exactly in the
GitHub response and returned lease. Only reviewed read grants are accepted,
except for the explicit `pull_requests:write` grant used by the HIGH operation.
Repository metadata uses only `Metadata: read`; branch and commit listing use
only `Contents: read`; issue listing uses only `Issues: read`; workflow-run
listing uses only `Actions: read`. Account bindings must also match the
requested environment and repository.

The signer receives only the JWT signing input and binding metadata. It must
return signature bytes; the provider has no private-key loading API. The shared
HTTPS transport resolves and validates every destination address, pins one
validated address into the socket lookup, preserves TLS hostname verification,
denies redirects and bounds request/response sizes and time.

## Runtime activation

The server registers a GitHub executor only when its operation policy is
explicitly enabled, uses `execution_mode: adapter`, has reviewed
`contract_verified: true` evidence, and references a configured account. The
account binding contains metadata only:

```yaml
provider_accounts:
  github:
    github-primary:
      client_id: Iv1.REPLACE_WITH_GITHUB_APP_CLIENT_ID
      installation_id: 123456
      environments: [production]
      repositories: [owner/repository]
```

The runtime rejects unknown fields, so an App private key cannot be placed in
this configuration. Before committing a configuration reload it probes the
fixed `/run/secret-broker-signer/github.sock` boundary. The socket and its
directory must not be owned or replaceable by the Broker process. Requests use
a bounded versioned protocol containing only the RS256 signing input and
account metadata; responses contain only signature bytes. Socket errors,
timeouts, ownership violations and malformed responses fail closed before the
tool becomes discoverable.

The isolated signer workload and its KMS/HSM policy are still subject to
DQ-004 and are not included in the Broker process. The Go `githubsigner`
protocol core validates the peer, exact metadata binding and GitHub App JWT
claims before passing only a SHA-256 digest to an injected backend. It does not
contain a file-key fallback. Adding a private key to source, ordinary
configuration, logs or an Agent response is prohibited.

## Verification status

Unit contract tests cover path and target injection, typed pagination and
filtering, bounded branch and commit projections, execution-binding
tampering, issue-versus-pull-request classification, untrusted-content marking,
workflow-run filter validation and bounded status projection,
App/account/environment/repository binding, task execution and canonical request
binding across the adapter, token provider and signer, JWT claims and algorithm,
invalid signer results, fixed-socket ownership and protocol failures,
strict signer-side JWT validation, peer and binding denial, digest-only backend calls,
configuration reload removal, fixed least-privilege token permissions,
step-up approval and single-execution enforcement for pull-request creation,
missing/wrong/expired/overlong leases, redirect denial, upstream status mapping,
invalid and oversized responses, bounded projection and error redaction. The provider manifest
remains `contract_required` until a production-grade signer and account binding
are configured and an isolated GitHub App account passes a real request and
revocation test. Runtime wiring is covered by deterministic integration tests;
that evidence is not a substitute for the external contract test.

Official references checked on 2026-09-11:

- [Get a repository](https://docs.github.com/en/rest/repos/repos#get-a-repository)
- [Generate a JSON Web Token for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app)
- [Generate an installation access token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)
- [Authenticate as a GitHub App installation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)
- [Choose GitHub App permissions](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app)
- [List branches](https://docs.github.com/en/rest/branches/branches#list-branches)
- [List commits](https://docs.github.com/en/rest/commits/commits#list-commits)
- [List repository issues](https://docs.github.com/en/rest/issues/issues#list-repository-issues)
- [List workflow runs for a repository](https://docs.github.com/en/rest/actions/workflow-runs#list-workflow-runs-for-a-repository)
- [Create a pull request](https://docs.github.com/en/rest/pulls/pulls#create-a-pull-request)
