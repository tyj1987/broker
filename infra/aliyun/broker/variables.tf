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

variable "ssh_password" {
  type        = string
  sensitive   = true
  description = "ECS 初始 root 密码（首次登录后改 SSH key）"
}

variable "image_id" {
  type        = string
  default     = ""  # 默认空，让阿里云选 Ubuntu 22.04
  description = "ECS 系统镜像 ID。留空用默认 Ubuntu 22.04"
}

variable "broker_domain" {
  type        = string
  default     = "broker.52trz.com"
  description = "broker 域名（用于服务端证书 SAN）"
}

variable "broker_alt_names" {
  type        = list(string)
  default     = ["localhost", "127.0.0.1"]
  description = "broker 服务端证书的额外 SAN（DNS / IP）"
}
