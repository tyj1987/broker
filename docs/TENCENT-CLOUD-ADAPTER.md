# Tencent Cloud CVM adapter

The source-only `tencent.cvm.instances.list@1.0.0` adapter implements the
Tencent Cloud API 3.0 `DescribeInstances` request without exposing a SecretId,
SecretKey or session token to an Agent.

The adapter accepts only an inventory resource binding, region, offset and
bounded page size. It fixes `POST https://cvm.tencentcloudapi.com/`, action
`DescribeInstances` and version `2017-03-12`. Its isolated signer input carries
the consumed task execution ID, canonical request binding and SHA-256 of the
exact JSON payload. Returned headers must match all of those fields, use a
temporary `X-TC-Token`, and have a timestamp within five minutes.

The response projection releases only instance ID, name, state, type, requested
region and zone. Network addresses, login settings, image identifiers, tags,
request IDs and upstream error details are not released.

This is not a production activation. The manifest remains `contract_required`.
Runtime registration requires an independently isolated TC3 signer, exact
account/region/resource policy bindings and a successful isolated CAM-role
contract test.

Official references checked on 2026-09-11:

- [DescribeInstances](https://cloud.tencent.com/document/product/213/15728)
- [API 3.0 TC3-HMAC-SHA256 signing](https://cloud.tencent.com/document/product/1278/46716)
