# Secret Broker — Terraform module

Terraform module to deploy [Secret Broker V4](https://github.com/tyj1987/broker) on Kubernetes,
plus examples for AWS EKS, Azure AKS, and GCP GKE.

## Pure-Terraform module

```hcl
module "broker" {
  source = "github.com/tyj1987/broker/deploy/terraform/modules/broker"

  name          = "broker"
  replicas      = 2
  image         = "ghcr.io/tyj1987/broker:4.1.0"
  broker_config = file("secrets/broker.yaml")           # SOPS-encrypted
  tls_cert_pem  = file("secrets/broker.crt")
  tls_key_pem   = file("secrets/broker.key")
  ca_cert_pem   = file("secrets/ca.crt")
}

output "broker_endpoint" {
  value = module.broker.service_host
}
```

## Cloud examples

| Example | Description |
|---------|-------------|
| [`examples/aws`](examples/aws/) | EKS + AWS ALB Ingress + ACM cert + IRSA workload identity |
| [`examples/azure`](examples/azure/) | AKS + Key Vault cert + Workload Identity |
| [`examples/gcp`](examples/gcp/) | GKE + Workload Identity Federation + Cloud DNS + managed SSL cert |

## Inputs

| Name | Description | Default |
|------|-------------|---------|
| `name` | Resource name prefix | `"broker"` |
| `image` | Container image (repo:tag) | `ghcr.io/tyj1987/broker:4.1.0` |
| `replicas` | Number of pods | `2` |
| `container_port` | mTLS listener port | `8443` |
| `metrics_port` | Prometheus metrics port | `9090` |
| `cpu` | CPU limit | `"500m"` |
| `memory` | Memory limit | `"512Mi"` |
| `pvc_size` | Persistent volume size | `"1Gi"` |
| `broker_config` | SOPS-encrypted broker.yaml (sensitive) | `""` |
| `tls_cert_pem` | mTLS server cert (sensitive) | `""` |
| `tls_key_pem` | mTLS server key (sensitive) | `""` |
| `ca_cert_pem` | CA cert | `""` |

## Outputs

| Name | Description |
|------|-------------|
| `namespace` | K8s namespace where broker runs |
| `service_name` | Service name |
| `service_host` | FQDN of broker service |
| `service_port` | mTLS port |
| `deployment_name` | Deployment name |

## Security defaults

- `runAsNonRoot: true`
- `readOnlyRootFilesystem: true`
- `allowPrivilegeEscalation: false`
- `capabilities.drop: [ALL]`
- `fsGroup: 1000`
- TLS secret `defaultMode: 0400`
- PodDisruptionBudget `minAvailable: 1`
- Namespace labelled `pod-security.kubernetes.io/enforce=restricted`
- HPA on CPU when replicas > 1

## SOPS workflow

```bash
# Encrypt broker.yaml with sops before passing to Terraform
sops --encrypt --in-place secrets/broker.yaml
terraform apply -var-file=...
```

Or use the [`sops_file`](https://registry.terraform.io/providers/carlpett/sops/latest/docs) data source.

## License

MIT
