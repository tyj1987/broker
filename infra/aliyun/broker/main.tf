# infra/aliyun/broker/main.tf
# Aliyun deployment of the Secret Broker.
# Creates the network and compute baseline. Application installation is handled
# by the reviewed systemd deployment path; Terraform never receives credentials.
#
# Usage:
#   Authenticate Terraform with an OIDC-backed RAM role.
#   terraform init
#   terraform plan -var-file=b.tfvars
#   terraform apply -var-file=b.tfvars

terraform {
  required_version = "= 1.16.1"

  required_providers {
    alicloud = {
      source  = "aliyun/alicloud"
      version = "= 1.279.0"
    }
  }

}

provider "alicloud" {
  region = var.region
}

# ============================================================
# Network
# ============================================================

resource "alicloud_vpc" "broker" {
  vpc_name   = "secret-broker-vpc"
  cidr_block = "10.10.0.0/16"
}

resource "alicloud_vswitch" "broker" {
  vpc_id     = alicloud_vpc.broker.id
  zone_id    = var.availability_zone
  cidr_block = "10.10.1.0/24"
}

resource "alicloud_security_group" "broker" {
  vpc_id              = alicloud_vpc.broker.id
  security_group_name = "secret-broker-sg"
  description         = "Secret Broker - mTLS HTTPS only"
}

# SSH 仅 admin CIDR
resource "alicloud_security_group_rule" "ssh" {
  type              = "ingress"
  ip_protocol       = "tcp"
  port_range        = "22/22"
  security_group_id = alicloud_security_group.broker.id
  cidr_ip           = var.admin_cidr
  description       = "SSH from admin"
}

# Public TLS terminates at the trusted nginx boundary. Port 8443 remains loopback-only.
resource "alicloud_security_group_rule" "https" {
  type              = "ingress"
  ip_protocol       = "tcp"
  port_range        = "443/443"
  security_group_id = alicloud_security_group.broker.id
  cidr_ip           = "0.0.0.0/0"
  description       = "Trusted nginx TLS boundary"
}

resource "alicloud_security_group_rule" "egress_https" {
  type              = "egress"
  ip_protocol       = "tcp"
  port_range        = "443/443"
  security_group_id = alicloud_security_group.broker.id
  cidr_ip           = "0.0.0.0/0"
}

resource "alicloud_security_group_rule" "egress_dns_udp" {
  for_each          = toset(var.dns_resolver_cidrs)
  type              = "egress"
  ip_protocol       = "udp"
  port_range        = "53/53"
  security_group_id = alicloud_security_group.broker.id
  cidr_ip           = each.value
  description       = "DNS to an approved VPC resolver"
}

resource "alicloud_security_group_rule" "egress_dns_tcp" {
  for_each          = toset(var.dns_resolver_cidrs)
  type              = "egress"
  ip_protocol       = "tcp"
  port_range        = "53/53"
  security_group_id = alicloud_security_group.broker.id
  cidr_ip           = each.value
  description       = "DNS fallback to an approved VPC resolver"
}

resource "alicloud_security_group_rule" "egress_ntp" {
  for_each          = toset(var.ntp_server_cidrs)
  type              = "egress"
  ip_protocol       = "udp"
  port_range        = "123/123"
  security_group_id = alicloud_security_group.broker.id
  cidr_ip           = each.value
  description       = "NTP to an approved time source"
}

# ============================================================
# ECS
# ============================================================

# 选 2C2G 标准型
data "alicloud_instance_types" "broker" {
  cpu_core_count       = 2
  memory_size          = 2
  instance_type_family = "ecs.t6"
  availability_zone    = var.availability_zone
}

# Ubuntu 24.04 LTS image selected from the provider catalog.
data "alicloud_images" "ubuntu" {
  most_recent = true
  owners      = "system"
  name_regex  = "^ubuntu_24_04_x64.*"
}

resource "alicloud_instance" "broker" {
  instance_name              = "secret-broker"
  instance_type              = data.alicloud_instance_types.broker.instance_types[0].id
  image_id                   = data.alicloud_images.ubuntu.images[0].id
  vswitch_id                 = alicloud_vswitch.broker.id
  security_groups            = [alicloud_security_group.broker.id]
  internet_max_bandwidth_out = 10
  internet_charge_type       = "PayByTraffic"
  key_name                   = var.ssh_key_name
  instance_charge_type       = "PostPaid"
  system_disk_category       = "cloud_essd"
  system_disk_size           = 40
  system_disk_encrypted      = true

  data_disks {
    name      = "broker-data"
    size      = 50
    category  = "cloud_essd"
    encrypted = true
  }
}

# ============================================================
# EIP
# ============================================================

resource "alicloud_eip" "broker" {
  bandwidth            = 10
  internet_charge_type = "PayByTraffic"
  payment_type         = "PayAsYouGo"
  description          = "Secret Broker public IP"
}

resource "alicloud_eip_association" "broker" {
  allocation_id = alicloud_eip.broker.id
  instance_id   = alicloud_instance.broker.id
}

# ============================================================
# Outputs
# ============================================================

output "broker_public_ip" {
  value       = alicloud_eip.broker.ip_address
  description = "Public EIP for the reviewed nginx TLS boundary"
}

output "broker_ssh_cmd" {
  value = "ssh ubuntu@${alicloud_eip.broker.ip_address}"
}

output "broker_endpoint" {
  value       = "https://${var.broker_domain}"
  description = "Public TLS endpoint after DNS and reviewed nginx provisioning"
}
