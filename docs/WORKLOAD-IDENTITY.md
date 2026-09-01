# Workload Identity (V4.1)

> **Goal**: K8s / ECS / GKE Pods never hold long-lived AWS access keys. The
> broker exchanges the projected OIDC token for short-lived STS credentials.

## 3 providers

| Provider | Cluster type | OIDC discovery | STS endpoint |
|----------|-------------|----------------|--------------|
| `aliyun` | Alibaba Cloud ACK | `acs:ram::123:oidc-provider/cluster` | `https://sts.aliyuncs.com/` |
| `aws`    | EKS / IRSA      | `https://oidc.eks.us-east-1.amazonaws.com/id/XXX` | `https://sts.amazonaws.com/` |
| `gcp`    | GKE Workload Identity Federation | `//iam.googleapis.com/projects/.../workloadIdentityPools/.../providers/...` | `https://sts.googleapis.com/v1/token` |

## Configuration

`secrets/broker.yaml`:
```yaml
workload_identity:
  enabled: true
  providers:
    aliyun:
      oidcProviderArn: "acs:ram::1234567890:oidc-provider/tyj-cluster"
      roleArns:
        - "acs:ram::1234567890:role/tyj-app-role"
      audience: "broker.example.com"
    aws:
      clusterOidcIssuer: "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
      roleArns:
        - "arn:aws:iam::1234567890:role/tyj-app-role"
    gcp:
      projectNumber: "1234567890"
      poolId: "tyj-pool"
      audience: "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/tyj-pool/providers/tyj-provider"
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/workload-identity/assume` | Exchange OIDC token for STS credentials |
| `GET`  | `/api/v1/workload-identity/cache` | View in-memory cache (admin only) |
| `POST` | `/api/v1/workload-identity/invalidate` | Force refresh (admin only) |
| `POST` | `/api/v1/workload-identity/config/validate` | Validate config (admin only) |

## Cache policy

- **In-memory** Map keyed by `${provider}:${role_arn_or_audience}`.
- **TTL**: STS default 1h, GCP default 1h. Cache refreshes 10 min before
  expiration (`REFRESH_SKEW_MS = 600_000`).
- **In-flight coalesce**: 5 concurrent requests for the same key produce
  exactly 1 upstream call. Returns the same `Promise` to all callers.

## Pod manifest (Kubernetes)

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
spec:
  serviceAccountName: my-app
  containers:
    - name: app
      image: my-app:1.0
      env:
        - name: BROKER_ENDPOINT
          value: "https://broker.broker.svc.cluster.local:8443"
        - name: BROKER_ROLE_ARN   # for AWS / Aliyun
          value: "arn:aws:iam::123:role/my-app"
  projectedServiceAccountToken:
    - path: broker-oidc
      audience: broker.example.com
      expirationSeconds: 3600
```

## Application code (Python)

```python
from secret_broker import BrokerClient, WorkloadIdentity

c = BrokerClient(
    endpoint="https://broker:8443",
    client_cert="/var/run/secrets/tls/client.crt",
    client_key="/var/run/secrets/tls/client.key",
    ca_cert="/var/run/secrets/tls/ca.crt",
    workload_identity=WorkloadIdentity("k8s", role_arn=os.environ["BROKER_ROLE_ARN"]),
)

# Token is auto-read from /var/run/secrets/tokens/broker-oidc
creds = c.assume_workload_identity("aws")
s3 = boto3.client(
    "s3",
    aws_access_key_id=creds.access_key_id,
    aws_secret_access_key=creds.access_key_secret,
    aws_session_token=creds.security_token,
)
```

## Application code (Go)

```go
wi := broker.NewWorkloadIdentity(broker.ProviderK8S, os.Getenv("BROKER_ROLE_ARN"))
c, _ := broker.NewClient(broker.Config{
    Endpoint: "https://broker:8443",
    WorkloadIdentity: wi,
    // ... certs
})
creds, _ := c.AssumeWorkloadIdentity(ctx, "aws", "", "", "")
sess := session.Must(session.NewSession(&aws.Config{
    Credentials: credentials.NewStaticCredentials(
        creds.AccessKeyID, creds.AccessKeySecret, creds.SecurityToken,
    ),
}))
```

## Security properties

- **Pod never holds long-lived AK**: only the projected OIDC token, which
  has 1h TTL and is rotated by the kubelet.
- **Broker never sees persistent AK**: STS exchange is one-shot.
- **STS credentials never returned to AI**: clients receive the STS but
  AI agents using the proxy mode never see the values; they just call
  `c.proxy("s3", "GET", "/bucket/key")` and the broker injects auth.
- **No audit log leakage**: cache list endpoint returns metadata only,
  not the actual access keys.

## Validation

`POST /api/v1/workload-identity/config/validate` returns:
```json
{
  "ok": true,
  "errors": []
}
```

If invalid:
```json
{
  "ok": false,
  "errors": [
    "aliyun: oidcProviderArn required",
    "aws: roleArns (non-empty array) required"
  ]
}
```

## Testing

Mock the upstream STS endpoint by injecting `httpClient`:

```javascript
import { _resetForTests, getCredentials } from '../broker/lib/workload-identity.js';

_resetForTests();
const http = async (url, opts) => ({
  status: 200,
  body: JSON.stringify({
    Credentials: { AccessKeyId: 'AKID', AccessKeySecret: 'SEC', SecurityToken: 'TOK',
                   Expiration: new Date(Date.now() + 3600_000).toISOString() },
  }),
});
const creds = await getCredentials('aws', 'oidc.token', { roleArn: 'arn:aws:iam::1:role/app' }, { httpClient: http });
```

See `broker-test/test-workload-identity.js` (56 tests).
