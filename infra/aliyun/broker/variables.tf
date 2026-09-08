# infra/aliyun/broker-variables.tf
# broker.tf 的输入变量

variable "region" {
  type        = string
  default     = "cn-beijing"
  description = "Aliyun region"
}

variable "admin_cidr" {
  type        = string
  description = "你的办公出口 IP CIDR, 例如 203.0.113.5/32. SSH 只能从这里进"
}

variable "ssh_key_name" {
  type        = string
  description = "Name of an existing Aliyun ECS SSH key pair"
}

variable "operation_role_arns" {
  type        = list(string)
  description = "Explicit RAM operation roles the Broker workload may assume"

  validation {
    condition     = length(var.operation_role_arns) > 0 && alltrue([for value in var.operation_role_arns : startswith(value, "acs:ram::")])
    error_message = "Provide at least one explicit RAM role ARN."
  }
}

variable "availability_zone" {
  type        = string
  default     = "cn-beijing-h"
  description = "Availability zone for the Broker instance"
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

variable "image_id" {
  type        = string
  default     = "" # 默认空，让阿里云选 Ubuntu 22.04
  description = "ECS 系统镜像 ID。留空用默认 Ubuntu 22.04"
}

variable "broker_domain" {
  type        = string
  default     = "broker.example.com"
  description = "broker 域名（用于服务端证书 SAN）"
}
