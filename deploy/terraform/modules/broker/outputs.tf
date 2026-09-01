output "namespace" {
  description = "Kubernetes namespace where broker is deployed"
  value       = kubernetes_namespace.broker.metadata[0].name
}

output "service_name" {
  description = "Kubernetes service name"
  value       = kubernetes_service_v1.broker.metadata[0].name
}

output "service_host" {
  description = "FQDN of the broker service"
  value       = "${kubernetes_service_v1.broker.metadata[0].name}.${kubernetes_namespace.broker.metadata[0].name}.svc.cluster.local"
}

output "service_port" {
  description = "mTLS listener port"
  value       = kubernetes_service_v1.broker.spec[0].port[0].port
}

output "deployment_name" {
  description = "Kubernetes deployment name"
  value       = kubernetes_deployment_v1.broker.metadata[0].name
}
