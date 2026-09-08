# infra/tencent/broker.tf
# 腾讯云部署 Secret Broker（CVM 镜像 + 数据盘 + EIP + 安全组）
# Disaster-recovery infrastructure only. Secrets and PKI are restored from an
# encrypted, tested backup; they are never copied directly from the primary host.

terraform {
  required_version = "= 1.16.1"

  required_providers {
    tencentcloud = {
      source  = "tencentcloudstack/tencentcloud"
      version = "= 1.83.26"
    }
  }

}

provider "tencentcloud" {
  region = var.region
}

# ============================
# Network
# ============================

resource "tencentcloud_vpc" "broker" {
  name       = "secret-broker-vpc-tc"
  cidr_block = "10.20.0.0/16"
}

resource "tencentcloud_subnet" "broker" {
  vpc_id            = tencentcloud_vpc.broker.id
  name              = "secret-broker-subnet"
  cidr_block        = "10.20.1.0/24"
  availability_zone = var.availability_zone
}

# 安全组
resource "tencentcloud_security_group" "broker" {
  name        = "secret-broker-sg"
  description = "Secret Broker - mTLS HTTPS only"
}

# SSH 仅 admin IP
resource "tencentcloud_security_group_rule" "ssh" {
  security_group_id = tencentcloud_security_group.broker.id
  type              = "ingress"
  ip_protocol       = "TCP"
  port_range        = "22"
  cidr_ip           = var.admin_cidr
  policy            = "accept"
  description       = "SSH from admin"
}

# mTLS HTTPS 公网
resource "tencentcloud_security_group_rule" "https" {
  security_group_id = tencentcloud_security_group.broker.id
  type              = "ingress"
  ip_protocol       = "TCP"
  port_range        = "443"
  cidr_ip           = "0.0.0.0/0"
  policy            = "accept"
  description       = "Trusted nginx TLS boundary"
}

# Provider calls are HTTPS-only. Add reviewed private DNS/NTP rules for the selected VPC resolver.
resource "tencentcloud_security_group_rule" "egress_https" {
  security_group_id = tencentcloud_security_group.broker.id
  type              = "egress"
  ip_protocol       = "TCP"
  port_range        = "443"
  cidr_ip           = "0.0.0.0/0"
  policy            = "accept"
}

resource "tencentcloud_security_group_rule" "egress_dns_udp" {
  for_each          = toset(var.dns_resolver_cidrs)
  security_group_id = tencentcloud_security_group.broker.id
  type              = "egress"
  ip_protocol       = "UDP"
  port_range        = "53"
  cidr_ip           = each.value
  policy            = "accept"
  description       = "DNS to an approved VPC resolver"
}

resource "tencentcloud_security_group_rule" "egress_dns_tcp" {
  for_each          = toset(var.dns_resolver_cidrs)
  security_group_id = tencentcloud_security_group.broker.id
  type              = "egress"
  ip_protocol       = "TCP"
  port_range        = "53"
  cidr_ip           = each.value
  policy            = "accept"
  description       = "DNS fallback to an approved VPC resolver"
}

resource "tencentcloud_security_group_rule" "egress_ntp" {
  for_each          = toset(var.ntp_server_cidrs)
  security_group_id = tencentcloud_security_group.broker.id
  type              = "egress"
  ip_protocol       = "UDP"
  port_range        = "123"
  cidr_ip           = each.value
  policy            = "accept"
  description       = "NTP to an approved time source"
}

# ============================
# CVM standby instance
# ============================

# 选 2C2G 标准型
data "tencentcloud_instance_types" "broker" {
  cpu_core_count = 2
  memory_size    = 2
  filter {
    name   = "instance-family"
    values = ["S5.SMALL2"]
  }
}

# Select a current Ubuntu 24.04 LTS image from the provider catalog.
data "tencentcloud_images" "ubuntu" {
  image_type       = ["PUBLIC_IMAGE"]
  image_name_regex = "^Ubuntu Server 24.04 LTS 64位$"
}

resource "tencentcloud_instance" "broker" {
  instance_name              = "secret-broker"
  availability_zone          = var.availability_zone
  image_id                   = data.tencentcloud_images.ubuntu.images[0].image_id
  instance_type              = data.tencentcloud_instance_types.broker.instance_types[0].instance_type
  vpc_id                     = tencentcloud_vpc.broker.id
  subnet_id                  = tencentcloud_subnet.broker.id
  security_groups            = [tencentcloud_security_group.broker.id]
  internet_max_bandwidth_out = 10
  allocate_public_ip         = false # 用 EIP 关联
  key_ids                    = var.ssh_key_ids
  cam_role_name              = var.cam_role_name
  instance_charge_type       = "POSTPAID_BY_HOUR"
  system_disk_type           = "CLOUD_PREMIUM"
  system_disk_size           = 40
  system_disk_encrypt        = true

  data_disks {
    data_disk_type = "CLOUD_PREMIUM"
    data_disk_size = 50
    encrypt        = true
  }
}

# EIP
resource "tencentcloud_eip" "broker" {
  name                       = "secret-broker-eip"
  internet_max_bandwidth_out = 10
  internet_charge_type       = "TRAFFIC_POSTPAID_BY_HOUR"
  type                       = "EIP"
}

resource "tencentcloud_eip_association" "broker" {
  eip_id      = tencentcloud_eip.broker.id
  instance_id = tencentcloud_instance.broker.id
}

# ============================
# Outputs
# ============================

output "broker_public_ip" {
  value       = tencentcloud_eip.broker.public_ip
  description = "Secret Broker 公网 IP（灾备，平时不用）"
}

output "broker_ssh_cmd" {
  value = "ssh ubuntu@${tencentcloud_eip.broker.public_ip}"
}

output "recovery_endpoint" {
  value       = "https://${var.broker_domain}"
  description = "Enable only after an approved restore, certificate validation, and read-only smoke test"
}
