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

Omitting the field from a new service applies the default, which is `["GET"]`
only. Any other method, including POST, must be listed explicitly, for example
`"allowed_methods": ["GET", "POST"]`. The same GET-only default is used by the
proxy path, the admin service read API and `validateMethod`, so an unconfigured
service rejects POST everywhere. Omitting the field from a partial update
preserves that service's existing constraint. Admin service reads return the
effective method array, so an unconfigured service reads back as `["GET"]`.
A read-back does not prove live provider execution succeeded.

Upgrade note: services that relied on an implicit POST must add
`allowed_methods` with POST before upgrading; otherwise POST calls are denied.
