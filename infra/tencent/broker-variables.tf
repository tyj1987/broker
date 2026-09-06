# infra/tencent/broker-variables.tf

variable "region" {
  type        = string
  default     = "ap-shanghai"
  description = "Tencent region"
}

variable "admin_cidr" {
  type        = string
  description = "你的办公出口 IP CIDR, 例如 203.0.113.5/32"
}

variable "ssh_key_name" {
  type        = string
  description = "Name of an existing Tencent Cloud SSH key pair. Password login is forbidden."
}

variable "broker_domain" {
  type        = string
  default     = "broker.example.com"
}
