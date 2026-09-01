variable "name" {
  description = "Name prefix for all broker resources"
  type        = string
  default     = "broker"
}

variable "image" {
  description = "Container image (repository:tag)"
  type        = string
  default     = "ghcr.io/tyj1987/broker:4.1.0"
}

variable "replicas" {
  description = "Number of broker instances"
  type        = number
  default     = 2
}

variable "container_port" {
  description = "mTLS listener port inside the container"
  type        = number
  default     = 8443
}

variable "metrics_port" {
  description = "Prometheus metrics port"
  type        = number
  default     = 9090
}

variable "cpu" {
  description = "CPU units (millicores for K8s, vCPU for cloud)"
  type        = string
  default     = "500m"
}

variable "memory" {
  description = "Memory limit"
  type        = string
  default     = "512Mi"
}

variable "pvc_size" {
  description = "Size of the persistent volume for SOPS data"
  type        = string
  default     = "1Gi"
}

variable "broker_config" {
  description = "SOPS-encrypted broker.yaml contents (raw text, NOT a file path)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "tls_cert_pem" {
  description = "Broker mTLS server certificate (PEM)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "tls_key_pem" {
  description = "Broker mTLS server private key (PEM)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "ca_cert_pem" {
  description = "Broker CA certificate (PEM, distributed to clients)"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags applied to all resources (AWS)"
  type        = map(string)
  default = {
    Project     = "secret-broker"
    ManagedBy   = "terraform"
    Environment = "production"
  }
}
