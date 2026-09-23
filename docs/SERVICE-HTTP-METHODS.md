# Service HTTP method configuration

The admin service create and partial-update endpoints accept `allowed_methods`.
This field configures an existing outbound constraint; it does not replace
caller authorization, fixed upstream/path checks, secret health, or auditing.
Only an authenticated admin can change service configuration.

```json
{
  "name": "fixed_resource",
  "type": "bearer",
  "upstream": "https://provider.example.test",
  "token_secret": "SYNTHETIC_TOKEN",
  "allow_paths": ["^/fixed/resource$"],
  "allowed_methods": ["GET", "PUT"]
}
```

Supported entries are GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS. Lowercase
entries are normalized to uppercase. Duplicates, unknown verbs, whitespace,
nulls, non-string members and non-array values are rejected, not silently
removed. An empty array explicitly denies every method.

Omitting the field from a new service retains the existing GET/POST default.
Omitting it from a partial update preserves that service's existing constraint.
Admin service reads return the effective method array, including legacy
GET/POST defaults. A read-back does not prove live provider execution succeeded.
