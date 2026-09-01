# Secret Broker — Helm chart

Kubernetes deployment chart for [Secret Broker V4](https://github.com/tyj1987/broker).

## Install

```bash
# 1. Create namespace
kubectl create namespace broker

# 2. Pre-encrypt broker.yaml with sops
sops --encrypt --in-place secrets/broker.yaml

# 3. Install
helm install broker ./deploy/helm/broker \
  --namespace broker \
  --set-file secrets.brokerYaml=secrets/broker.yaml \
  --set-file secrets.tlsCert=secrets/broker.crt \
  --set-file secrets.tlsKey=secrets/broker.key \
  --set-file secrets.caCert=secrets/ca.crt
```

## Verify

```bash
helm test broker
```

## Values

| Value | Default | Description |
|-------|---------|-------------|
| `replicaCount` | `2` | Number of broker pods |
| `image.repository` | `ghcr.io/tyj1987/broker` | Container image |
| `image.tag` | (chart appVersion) | Image tag |
| `service.port` | `8443` | mTLS listener port |
| `persistence.size` | `1Gi` | PVC size for SOPS data |
| `autoscaling.enabled` | `false` | Enable HPA |
| `config.mfaPolicy.enabled` | `true` | Enable MFA |
| `config.websocket.enabled` | `true` | Enable WebSocket events |
| `config.workloadIdentity.enabled` | `false` | Enable K8s/ECS/GKE OIDC |
| `secrets.brokerYaml` | (empty) | Path to SOPS-encrypted broker.yaml |
| `secrets.tlsCert` | (empty) | Path to broker TLS cert (PEM) |
| `secrets.tlsKey` | (empty) | Path to broker TLS key (PEM) |
| `secrets.caCert` | (empty) | Path to broker CA cert (PEM) |

See `values.yaml` for the full list.

## Security defaults

- `runAsNonRoot: true`
- `readOnlyRootFilesystem: true`
- `allowPrivilegeEscalation: false`
- `capabilities.drop: [ALL]`
- `fsGroup: 1000`
- `runAsUser: 1000`
- TLS secret `defaultMode: 0400`
- PodDisruptionBudget `minAvailable: 1`

## Resources

- [Repository](https://github.com/tyj1987/broker)
- [Documentation](https://github.com/tyj1987/broker/blob/main/docs/DESIGN-V4-MASTER-PLAN.md)
- [Helm chart tests](templates/tests/)

## License

MIT
