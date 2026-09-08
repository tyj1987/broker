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

## Grafana

Pre-built observability:

* `dashboard.json` — single-pane broker overview
* `alerts.yml` — recording rules + alerts (5xx rate, credential age, healthcheck failure)
* `prometheus.yml` + `provisioning/` — drop-in for `prometheus-operator` CRDs

Import via Grafana UI or mount the `provisioning/` directory into your
Prometheus/Grafana containers.
