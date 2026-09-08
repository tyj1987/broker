# Secret Broker — Helm chart

Kubernetes deployment chart for [Secret Broker V4](https://github.com/tyj1987/broker).

## Install

```bash
# 1. Create namespace
kubectl create namespace broker

# 2. Provision secrets through the cluster's approved secret controller.
# The referenced objects must expose broker.yaml and tls.crt/tls.key/ca.crt.

# 3. Install
helm install broker ./deploy/helm/broker \
  --namespace broker \
  --set secrets.configSecretName=broker-config \
  --set secrets.tlsSecretName=broker-tls \
  --set image.digest=sha256:RELEASE_DIGEST
```

## Verify

```bash
kubectl -n broker create secret tls broker-health-client \
  --cert=secrets/health-client.crt \
  --key=secrets/health-client.key
helm upgrade broker ./deploy/helm/broker \
  --namespace broker \
  --reuse-values \
  --set tests.enabled=true \
  --set tests.clientCertificateSecret=broker-health-client \
  --set tests.tlsServerName=broker.local
helm test broker --namespace broker
```

## Values

| Value | Default | Description |
|-------|---------|-------------|
| `replicaCount` | `2` | Number of broker pods |
| `image.repository` | `ghcr.io/tyj1987/broker` | Container image |
| `image.tag` | (chart appVersion) | Image tag |
| `image.digest` | (empty) | Immutable production image digest |
| `service.port` | `8443` | mTLS listener port |
| `persistence.size` | `1Gi` | PVC size for SOPS data |
| `autoscaling.enabled` | `false` | Enable HPA |
| `config.mfaPolicy.enabled` | `true` | Enable MFA |
| `config.websocket.enabled` | `true` | Enable WebSocket events |
| `config.workloadIdentity.enabled` | `false` | Enable K8s/ECS/GKE OIDC |
| `secrets.configSecretName` | required | Existing Secret containing `broker.yaml` |
| `secrets.tlsSecretName` | required | Existing Secret containing `tls.crt`, `tls.key`, and `ca.crt` |
| `tests.enabled` | `false` | Render the mTLS chart test pod |
| `tests.clientCertificateSecret` | (empty) | Dedicated Kubernetes TLS secret for the chart test identity |
| `tests.tlsServerName` | `broker.local` | DNS SAN verified on the Broker server certificate |

See `values.yaml` for the full list.

## Security defaults

- `runAsNonRoot: true`
- `readOnlyRootFilesystem: true`
- `allowPrivilegeEscalation: false`
- `capabilities.drop: [ALL]`
- `fsGroup: 65532`
- `runAsUser: 65532`
- TLS secret `defaultMode: 0400`
- PodDisruptionBudget `minAvailable: 1`
- Container probes use the loopback-only HTTP health listener; `helm test` uses
  a dedicated mTLS identity and verifies the configured CA and DNS SAN.

## Resources

- [Repository](https://github.com/tyj1987/broker)
- [Architecture](https://github.com/tyj1987/broker/blob/master/ARCHITECTURE.md)
- [Helm chart tests](templates/tests/)

## License

MIT
