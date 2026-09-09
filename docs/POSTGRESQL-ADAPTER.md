# PostgreSQL fixed-query adapter

`postgresql.database.inspect@1.0.0` returns bounded metadata for one registered
database target. It accepts only an opaque `resource_ref`; callers cannot
provide SQL, bind values, connection strings, credentials, schema names or
timeouts.

The Broker sends the isolated runner a fixed `database.inspect.v1` query ID,
target and account binding, a read-only transaction requirement, five-second
statement timeout, one-second lock timeout and one-row maximum. The runner must
prove that the transaction is read-only and its login lacks `SUPERUSER`,
`BYPASSRLS`, `CREATEDB`, `CREATEROLE` and `REPLICATION`. Missing or privileged
attestation fails closed. Only the database name, server version number,
recovery state, current role and `read_only_enforced: true` are returned.

PostgreSQL documents that a read-only transaction blocks ordinary writes and
DDL but is a high-level restriction that does not prevent every possible side
effect. The production boundary therefore requires all of these controls:

- fixed query IDs implemented inside the isolated runner; no arbitrary SQL or
  caller-selected function, relation, column, operator or expression;
- a dedicated `NOLOGIN` privilege owner and short-lived `LOGIN` execution role
  with only the explicit catalog permissions required by the query;
- row-level security preserved, no security-definer escape, no writable foreign
  server, untrusted procedural language, large-object or filesystem privilege;
- TLS verification, target pinning, session and statement timeouts, one-row and
  response-size bounds, rollback on every path, and session termination on
  revocation;
- isolated-database tests for DML, DDL, `COPY`, lock, function side effects,
  privilege escalation, RLS bypass, cancellation, timeout and credential/log
  leakage.

Future typed operations remain distinct: bounded business reads are `READ`,
reversible changes are at least `HIGH`, sensitive DDL is `HIGH` or `CRITICAL`,
and destructive statements such as `DROP` or `TRUNCATE` are `CRITICAL` and
unavailable to Agent automation by default.

The current deterministic runner and automation-loop tests are source evidence
only. No database driver, production credential resolver or isolated PostgreSQL
contract has been enabled, so the provider remains `contract_required`.
