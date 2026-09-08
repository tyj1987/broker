# Deployment Assets

Production deployment resources for Secret Broker.

## Layout

```
deploy/
├── helm/broker/           # Helm chart (Kubernetes)
├── terraform/             # Terraform modules (Aliyun, AWS, GCP, Azure)
└── grafana/               # Grafana dashboards + Prometheus alerts
```

## Helm chart

```bash
helm repo add broker https://tyj1987.github.io/broker
helm install broker broker/broker \
  --namespace secret-broker \
  --create-namespace \
  --set broker.config.brokerYaml="$(cat secrets/broker.yaml)"
```

See [`helm/broker/README.md`](helm/broker/README.md) for the full chart reference
and values.

## Terraform

The `terraform/modules/broker` module is reusable across cloud providers
for provisioning the compute, networking, and storage prerequisites.

```bash
cd terraform/examples/aws
terraform init
terraform plan -var-file=example.tfvars
terraform apply
```

See [`terraform/README.md`](terraform/README.md) for the module API and
per-cloud examples.

## Grafana

Pre-built observability:

* `dashboard.json` — single-pane broker overview
* `alerts.yml` — recording rules + alerts (5xx rate, credential age, healthcheck failure)
* `prometheus.yml` + `provisioning/` — drop-in for `prometheus-operator` CRDs

Import via Grafana UI or mount the `provisioning/` directory into your
Prometheus/Grafana containers.
