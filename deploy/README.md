# Deployment Assets

Production deployment resources for Secret Broker.

## Layout

```
deploy/
├── helm/broker/           # Helm chart (Kubernetes)
├── systemd/               # Broker and Go policy-core services
├── nginx/                 # Trusted public proxy boundary
├── bin/                   # Atomic deployment helper
└── grafana/               # Grafana dashboards + Prometheus alerts
```

## Helm chart

```bash
helm repo add broker https://tyj1987.github.io/broker
helm install broker broker/broker \
  --namespace secret-broker \
  --create-namespace \
  --set secrets.configSecretName=broker-config \
  --set secrets.tlsSecretName=broker-tls \
  --set image.digest=sha256:RELEASE_DIGEST
```

See [`helm/broker/README.md`](helm/broker/README.md) for the full chart reference
and values.

## Infrastructure

Cloud resources live under `infra/`. The retired generic Kubernetes Terraform
module accepted private keys as Terraform variables, which placed them in
state, so it is intentionally not part of the supported deployment path.

## Atomic ECS deployment

The protected GitHub environment deploys one attested release through
`bin/secret-broker-deploy`. The helper refuses to read the release archive
unless the active service already runs as `broker:broker`, the Go policy core
is active, nginx has upstream certificate verification enabled with no
effective `proxy_ssl_verify off`, and no CA or final-client private key remains
in either the target PKI layout or the legacy application PKI tree.

The one-time production migration must establish those invariants first.
Normal CI deployment is deliberately unable to migrate a legacy or unsafe
host.

## Grafana

Pre-built observability:

* `dashboard.json` — single-pane broker overview
* `alerts.yml` — recording rules + alerts (5xx rate, credential age, healthcheck failure)
* `prometheus.yml` + `provisioning/` — drop-in for `prometheus-operator` CRDs

Import via Grafana UI or mount the `provisioning/` directory into your
Prometheus/Grafana containers.
