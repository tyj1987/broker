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

variable "ssh_key_ids" {
  type        = list(string)
  description = "IDs of existing Tencent Cloud SSH key pairs"
}

variable "cam_role_name" {
  type        = string
  description = "Existing least-privilege CAM role attached to the standby CVM"
}

variable "availability_zone" {
  type    = string
  default = "ap-shanghai-2"
}

variable "dns_resolver_cidrs" {
  type        = list(string)
  description = "Approved VPC DNS resolver addresses in CIDR notation"

  validation {
    condition     = length(var.dns_resolver_cidrs) > 0 && alltrue([for value in var.dns_resolver_cidrs : can(cidrhost(value, 0))])
    error_message = "Provide at least one valid, reviewed DNS resolver CIDR."
  }
}

variable "ntp_server_cidrs" {
  type        = list(string)
  description = "Approved NTP server addresses in CIDR notation"

  validation {
    condition     = length(var.ntp_server_cidrs) > 0 && alltrue([for value in var.ntp_server_cidrs : can(cidrhost(value, 0))])
    error_message = "Provide at least one valid, reviewed NTP server CIDR."
  }
}

variable "broker_domain" {
  type    = string
  default = "broker.example.com"
}
