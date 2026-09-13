# Decision queue

This queue records consequential choices that should not be guessed during
incremental implementation. Work that does not depend on a queued choice may
continue.

## DQ-001: durable control-plane state

- Status: open
- Needed before: production automation scheduling or more than one Broker node
- Decision: choose the authoritative durable store and transaction boundary for
  task, approval, operation, OTP, browser lease and device registry state,
  idempotency records and audit outbox events.
- Required evidence: encrypted backup/restore, failover, concurrent claim,
  revocation race, audit-write failure and disaster-recovery tests.
- Current safe default: encrypted, atomic file-backed restart recovery for one
  Broker process. It fails closed on missing or unauthenticated state, but has
  no external monotonic generation anchor and cannot prove cold-start rollback;
  no production scheduling or horizontal scaling.

## DQ-002: worker delivery semantics

- Status: open
- Needed before: remote or horizontally scaled executors
- Decision: select a queue and an at-least-once claim/lease protocol, including
  adapter idempotency requirements and handling of indeterminate upstream
  results. Do not claim exactly-once execution across network boundaries.
- Required evidence: worker crash before/after upstream commit, lease expiry,
  duplicate delivery, cancellation race and replay tests.
- Current safe default: explicit caller-triggered execution in one Broker
  process; terminal failure is never retried automatically.

## DQ-003: independent audit anchor

- Status: accepted; implementation and live evidence pending
- Decision authority: the user approved the recommended design on 2026-09-12.
  This approval selects the architecture but does not approve cloud resource
  creation, production cutover, or deployment of an unverified release.
- Needed before: production acceptance
- Decision: use a non-exportable Alibaba Cloud KMS signing key behind an
  independently owned signer workload, publish signed heads to an independently
  administered Alibaba Cloud OSS bucket locked with BucketWorm for 365 days,
  and mirror the same signed envelopes to a separate Tencent Cloud COS account
  with per-object COMPLIANCE retention of at least 365 days. The mirror is an
  explicit typed worker because neither cloud provides native continuous
  cross-cloud replication. The signing identity must not be available to the
  Broker application process.
- Required evidence: signed-head verification, suffix and full-chain deletion
  detection, signer revocation, clock rollback, storage outage, retention-lock
  enforcement and disaster-recovery tests.
- Current safe default: restart-safe local chain verification plus a
  provider-neutral signed-head envelope, fail-closed verifier, fixed,
  ownership-checked Unix-socket signer client, and provider-neutral export
  coordinator. The coordinator verifies every signature before publication,
  uses the previous anchor digest for compare-and-set, and makes same-chain
  retries idempotent without sending audit content or private key material.
  A fixed-head, bounded-page recovery verifier checks every retained anchor
  from sequence one against its local historical chain proof.
  Deterministic tests cover payload/signature tampering, signer trust and
  revocation, predecessor/sequence continuity, clock and count rollback,
  retained anchors on growing chains, publication conflicts, signer/store
  outages, incomplete recovery and recovery bounds. The Go `auditanchor`
  protocol core now validates the fixed purpose, algorithm, key, stream,
  sequence, previous anchor digest, payload digest and version 2
  domain-separated signing input before an injected independent authority or
  KMS backend can be called. Its monotonic authorizer uses a linearizable
  compare-and-swap state contract to reject forks, gaps, rewinds and corrupt
  state while allowing an exact retry. It authenticates the local peer on Linux
  and returns only stable error codes. Its Alibaba KMS adapter now binds the
  approved `ECDSA_SHA_256` and `DIGEST` request to the exact configured key and
  rejects malformed P-256 DER signatures and mismatched response metadata.
  The Go immutable-writer contract now rejects arbitrary object keys and
  headers, independently verifies the v2 ECDSA P-256 signature against the
  configured stream and a bounded trusted-key sequence epoch, verifies Locked
  365-day BucketWorm with versioning disabled before an OSS
  create-without-overwrite request, requires COS Object Lock with versioning
  enabled, applies per-object COMPLIANCE retention for at least 365 days, and
  reads back identical canonical bytes and retention metadata from both clouds.
  Sequence epochs preserve historical verification across safe key rotation
  while refusing anchors outside a key's authorization window. Each sequence
  uses one digest-independent immutable key, so a
  conflicting same-sequence payload cannot evade create-without-overwrite by
  choosing another digest. Sequence N additionally requires identical,
  canonical and retained sequence N-1 copies in both clouds with the committed
  predecessor digest. Tests cover exact creation, idempotent retries, content
  conflicts, malformed envelopes, missing or divergent predecessors and every
  storage-control failure boundary.
  Official SDK transports now pin Alibaba OSS Go SDK v2 `v1.6.0` and Tencent
  COS Go SDK v5 `v0.7.75`, bind each client to one exact bucket and region,
  reject custom/insecure OSS routing and mismatched/non-HTTPS COS BucketURLs,
  reduce provider errors to stable failures, enforce bounded read-back and
  cancellation, and expose no delete or retention-policy mutation capability.
  Transport tests
  cover exact requests, immutable duplicate handling, object-lock headers,
  response bounds, invalid provider responses and internal cancellation
  boundaries. A separate, hermetically tested store protocol now binds a fixed
  stream and purpose to `publish`, `read_head`, `read_page` and `health`, uses
  exact non-root exporter/recovery UID roles, bounds pages and wire sizes, and
  independently verifies returned envelopes. Its fixed-path Node client maps
  only those operations to the existing exporter and recovery contracts. The
  socket boundary does not by itself resolve restart-safe dual-cloud head
  discovery or independently prove recovery freshness. This source checkpoint
  adds bounded OSS/COS object-key pagination and a provider-backed repository
  that derives the contiguous common sequence from both clouds without a
  Broker-host head. It permits only one repairable primary-only tail and rejects
  gaps, mirror leads, content divergence, invalid retention and pagination
  exhaustion. A conflicting retry may be reported only after the existing
  primary tail is mirrored and read back. Repository operations serialize
  through a context-cancellable gate. The default and hard enumeration
  capacities are 128,000 and 512,000 anchors respectively; capacity alerting,
  stream rollover and lifecycle after retention expiry remain operational
  design gaps. CI enforces Go statement coverage, while the 85 percent
  branch-coverage release evidence remains open. Runnable signer/store services,
  immutable buckets, mirror worker, credentials, retention locks and recovery
  authority are not deployed yet, so there is no claim of independent
  non-repudiation and RR-012 remains open.
  The OSS bounded read contract accepts `206 Partial Content` only when the
  response metadata proves the range is the complete object; this corrects the
  prior source path that rejected normal OSS range reads. The 22-item production
  preflight now combines store process liveness with an exact fresh health probe
  executed as the recovery UID, so an active placeholder cannot assert verified
  lock or mirror state.
  A strict non-secret service configuration, injected cloud-client factory,
  fixed Linux Unix-socket lifecycle and bounded health helper are now source
  implemented. The configuration accepts no provider endpoint or credential
  source and requires distinct OSS/COS provider profile identifiers plus
  non-overlapping P-256 verification-key epochs. Its Linux loader pins a
  root-managed path and verifies ownership, write protection, no-follow open and
  file identity. The store socket rejects concurrent active instances and only
  reclaims a same-owner stale endpoint. The checked-in default factory returns
  `identity_unavailable`. The hermetic container build stage now compiles the
  audit-store service and bounded health helper, but intentionally does not copy
  them into the Node production image or ECS release payload. No live cloud
  identity, bucket or retention lock has been created. Packaging remains blocked
  until the independent service identities can execute only their own binaries,
  deployment atomically restarts and verifies the exact audit processes, and
  rollback proves the prior audit runtime is executable. The 22-item production
  preflight now binds each audit service's `MainPID` executable to the exact
  binary below the active release; an old, deleted or alternate-path process
  cannot satisfy the existing active-service gates. Linux peer/socket E2E and
  the existing provider-backed repository tests remain the current CI evidence
  point. A bounded Go read-only audit-chain verifier and historical proof
  reader now provide the local-chain dependency needed by a future Go exporter
  and recovery authority. CI constructs the chain with Node and requires Go
  compatibility across Unicode, number and historical-anchor cases. The Go
  reader fails closed on non-I-JSON input and is not yet packaged or used by
  the production deployment helper. A runtime switch remains blocked on real
  retained-chain parity, a quiet filesystem snapshot, exact release packaging
  and rollback evidence.

## DQ-004: provider signing and account-binding authority

- Status: open
- Needed before: any live provider adapter is production-enabled
- Decision: select the independently managed KMS/HSM signing service and the
  authoritative encrypted store for provider account, environment, installation
  and resource bindings. Define workload attestation, key rotation, revocation,
  regional failover and break-glass ownership without exposing signing keys to
  the Broker process.
- Required evidence: signer policy denial, wrong-key and wrong-workload tests,
  rotation overlap, revocation latency, store rollback detection, regional
  outage behavior and isolated-account contract tests.
- Current safe default: dependency-injected signer and account resolver used
  by deterministic tests plus a fixed, signature-only Unix-socket client. The
  Broker runtime registers verified GitHub operations only after the socket and
  metadata bindings pass preflight. The Go signer protocol core independently
  validates peer authorization, exact account/environment/client bindings, the
  consumed task execution ID, the canonical request binding, and the bounded
  GitHub App JWT before giving only a SHA-256 digest plus those non-secret
  execution bindings to an injected non-exportable backend. Linux peer identity
  is verified with `SO_PEERCRED`
  against an explicit non-root Broker UID. No production signer workload or
  KMS/HSM authority has been selected. A source-only GitHub pull-request
  creation operation now exercises the same boundary with a fixed API path, a
  draft-by-default request, and WebAuthn step-up approval, but remains disabled
  in production until this decision and its isolated GitHub App contract test
  are closed. The Cloudflare runtime now has a fixed,
  ownership-checked Unix-socket credential lease client and refuses plaintext
  token configuration; only exact five-minute account/environment/resource
  leases are accepted. Its source-only DNS inventory operation additionally
  binds the task resource to an account-allowed zone and releases no DNS record
  content or other potentially sensitive provider fields. Docker now uses the
  same isolated boundary with exact
  repository bindings and a second expiry check in the adapter. The external
  credential-service implementation and its authority remain undecided, so
  every provider remains `contract_required`. Alibaba Cloud Signature V3 now
  matches the current official byte-level example, uses ISO 8601 time and a
  per-request nonce, and signs temporary STS security tokens. This corrects the
  local primitive only. A typed `ecs.instances.list` adapter now fixes the
  regional endpoint and API metadata, uses the current token-based pagination,
  releases only bounded inventory fields and accepts only an isolated signed
  request capability. A fixed, ownership-checked Unix socket and exact
  account/environment/region/resource runtime binding are implemented; a
  verified policy fails startup when that signer is absent. No signer service,
  authoritative account store or production operation is enabled while this
  decision is open. A separate Go credential-service protocol core now validates
  Linux peer identity, the exact provider/operation/account/environment/resource
  tuple, the consumed task execution ID, the canonical request binding, and a
  maximum five-minute printable lease before returning it to the Broker runtime.
  It supports only the bounded Cloudflare, Docker and DeepSeek resource shapes
  already enforced by the Node client, which also rejects responses with altered
  execution bindings. Its issuer remains
  dependency-injected: this protocol boundary is not a credential store and
  does not enable a provider by itself. OpenAI model inventory now uses the
  same source-only, execution-bound lease boundary with an exact project
  resource and model-ID-only response projection. WIF token exchange and the
  isolated OpenAI project contract remain required before activation. Tencent
  Cloud CVM inventory now has a source-only adapter with a fixed API 3.0
  endpoint, execution-bound payload hash, temporary-token requirement and a
  network-address-free response projection. Its runtime is gated on an
  explicitly verified policy and an ownership-checked local signer socket, and
  fails startup when either is missing. The isolated TC3 signer service, CAM
  role authority and account contract test remain required before activation.
  A source-only version 2 contract runner now validates one exact GitHub or
  Alibaba Cloud read-only binding through the real `/api/v2/tasks` path. The
  same execution-bound signer path first calls a fixed GitHub App installation
  identity endpoint or Alibaba Cloud STS `GetCallerIdentity`; adapters release
  only SHA-256 principal digests and a bounded principal type. The protected
  plan supplies expected digests, and a mismatch fails before a receipt can be
  issued. Alibaba signer protocol version 3 additionally binds the identity and
  ECS signatures to one opaque credential lease; drift is rejected before the
  business request leaves the Broker, and invalid business parameters cannot
  trigger the identity probe. Its Go protocol core independently enforces the
  fixed operation, account, environment, resource, region, execution and
  request bindings before an injected backend can sign. The remaining checks
  cover bounded secret-free
  output plus wrong-account and wrong-resource denials. Credentials are accepted only from
  operator-supplied files and the receipt contains no account, resource,
  principal or digest. The 2026-09-12 production probe was denied before
  provider execution because neither tool is deployed, so no real account contract has passed;
  revocation and rotation remain separate required phases.
  The source deployment contract now assigns GitHub and Alibaba Cloud signers
  distinct fixed users, groups, runtime directories and socket paths. The
  22-item production preflight no longer accepts an environment variable that
  makes the GitHub signer optional: its single provider-signer gate requires
  both services and root-owned socket units, exact identities, exact
  `0750`/`0660` boundaries, unique numeric UID/GID values, Broker group-only
  access, exact runtime supplementary-group allowlists, actual process
  credentials, stable processes and executables bound to the active release.
  The privileged deployment account is also included in numeric collision
  checks. The collected production gate now invokes a release-bound verifier
  for canonical, detached-Ed25519 signed evidence. The evidence binds the
  exact release SHA, current provider configuration generation, exact protected
  signer-authority configuration generations, both bounded read receipts,
  their plan digests and provider-side audit reference digests;
  unsafe, missing, stale or mismatched files fail closed without exposing
  evidence contents. Evidence expires after at most 15 minutes and the verifier
  double-samples the Broker generation through its independently owned mode
  `0600` Unix socket. The verifier has only a root-owned public keyring, never an evidence-signing
  private key. The Node clients use the same future paths.
  Both signer protocol cores now require a loaded-authority generation and
  expose it only through a peer-authorized, random-challenge probe on their
  fixed Unix sockets. Production preflight double-samples those responses
  inside the stable process/release window and requires them to match both the
  protected configuration hashes and the signed evidence. A separate pre-start
  marker remains unacceptable because it leaves an open-file race.
  This prepares,
  but does not perform, DQ-009. Neither runnable signer executable,
  cloud authority, protected configuration nor signed isolated-account receipt
  exists yet, so the gate intentionally fails in production and DQ-004 remains
  open.

## DQ-005: SSH target, host-key and certificate authority

- Status: open
- Needed before: any SSH-backed capability is production-enabled
- Decision: select the authoritative target registry, independently verified
  host-key or host-certificate store, short-lived user-certificate signer and
  isolated runner workload. Define principal restrictions, forced commands,
  revocation, regional failover and emergency ownership.
- Required evidence: unknown and changed host-key denial, wrong target and
  principal denial, expired and revoked certificate denial, forced-command and
  forwarding escape attempts, signer outage, runner compromise containment,
  output redaction and isolated-target contract tests.
- Current safe default: a dependency-injected runner used only by deterministic
  tests. No host address, credential, certificate signer or free-form command is
  available through the strict adapter, and the provider remains
  `contract_required`.

## DQ-006: PostgreSQL runner and authorization authority

- Status: open
- Needed before: any PostgreSQL capability is production-enabled
- Decision: select the isolated query-runner workload, authoritative database
  target registry, short-lived login issuer and per-query privilege ownership.
  Define TLS trust, RLS policy ownership, connection pooling, revocation,
  cancellation, audit and regional failover boundaries.
- Required evidence: wrong-target and wrong-database denial, read/write and DDL
  escape attempts, function and foreign-data side effects, RLS bypass,
  privileged-role detection, session revocation, timeout and cancellation,
  pool state reset, output bounds, log redaction and isolated-database contract
  tests.
- Current safe default: a dependency-injected fixed-query runner used only by
  deterministic tests. The strict adapter accepts no SQL or credentials and
  the provider remains `contract_required`.

## DQ-007: Google Drive identity and content-release authority

- Status: open
- Needed before: any Google Drive capability is production-enabled
- Decision: select the workload identity federation or OAuth authority, exact
  file-sharing registry and isolated content-classification service. Define
  tenant binding, file revocation, classifier policy/version ownership, data
  retention, regional failover and human override boundaries.
- Required evidence: wrong-file and cross-tenant denial, share and workload
  revocation latency, token expiry, broad-scope rejection, export-size and
  encoding limits, prompt-injection and sensitive-content handling, classifier
  outage, audit/log leakage, cancellation and isolated-account contract tests.
- Current safe default: dependency-injected token and content-filter
  capabilities used only by deterministic tests. The adapter accepts only a
  fixed plain-text export for one file and remains `contract_required`.

## DQ-008: MCP workload identity and credential delivery

- Status: open
- Needed before: production or remotely reachable MCP execution
- Decision: select the attested workload identity, short-lived Broker token
  exchange and revocation authority for each MCP deployment. Define audience,
  host, process, tool/account/resource/environment scope, rotation and emergency
  ownership without making a master key available to the MCP or Agent process.
- Required evidence: wrong-workload and wrong-audience denial, token theft and
  replay, process restart, revocation latency, issuer outage, mTLS rotation,
  local listener DNS-rebinding and browser-origin tests, and secret-free crash,
  error and audit logs.
- Current safe default: loopback-only MCP with separate file-loaded capabilities
  for the local listener and a pre-provisioned scoped Broker API key. The two
  values cannot be reused. Master keys, environment credentials, secret
  resolution, arbitrary proxying and external MCP healthcheck execution are
  denied. The deployed STDIO bridge is being accepted first with a seven-day
  key constrained to `broker:tools.inspect`, `control-plane`, `tool-registry`
  and `production`; this proves the boundary but does not close this decision
  or authorize remotely reachable MCP execution.

## DQ-009: production trust-domain cutover

- Status: open
- Needed before: the first protected ECS CD deployment
- Decision: approve a maintenance window and name the offline CA or HSM
  authority, the second verified management path, the client re-enrollment
  owners, and the rollback boundary for replacing the currently co-located CA
  and final-client private keys. Rollback must not restore the compromised trust
  domain after new identities have been accepted.
- Required evidence: pre-cutover snapshot and hashes, independently verified
  SSH host identity, new nginx workload identity, exact trusted-proxy binding,
  rejection of every old identity, successful read-only typed operation,
  secret-free audit output, and a timed rollback rehearsal.
- Current safe default: keep the legacy service available for existing users,
  deny protected CD, and continue source/staging work. A strict source-only
  plan validator now requires the maintenance window, distinct CA
  fingerprints, offline/HSM authority, two independently verified management
  paths, exact nginx trusted-proxy binding, enrolled client owners, immutable
  rollback boundary, external evidence and separate authorization. Its safe
  report omits fingerprints and evidence references. This is preparation only:
  no production plan has been populated or approved and no identity has been
  switched. Do not copy the old key hierarchy into the hardened layout or use
  it to satisfy the preflight.
  The candidate source now reserves separate GitHub and Alibaba Cloud signer
  runtime paths and validates them in the production preflight. This path
  preparation changes no live service, account, socket or trust root. Activating
  either path remains part of the maintenance-window report and requires the
  explicit pre-cutover approval described above.

## DQ-010: DeepSeek credential authority and usage controls

- Status: open
- Needed before: any DeepSeek operation is production-enabled
- Decision: select the authoritative API-key store, rotation owner, account and
  environment binding, spending limits, model allowlist and emergency revoke
  process. Decide whether a future response-generation operation requires
  per-task approval, budget reservation and content-retention controls.
- Required evidence: isolated-account contract test, wrong-account and
  wrong-environment denial, lease expiry and revocation latency, quota and
  upstream outage behavior, output bounds, prompt/result audit policy and
  secret-free logs, errors and crash artifacts.
- Current safe default: only the official read-only `GET /models` operation is
  implemented. It uses a fixed origin and path, a five-minute account-bound
  credential lease, bounded response projection and startup preflight. The
  provider remains `contract_required`; response generation and production
  credentials are not enabled.
