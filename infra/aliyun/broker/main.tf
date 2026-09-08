# infra/aliyun/broker/main.tf
# Aliyun deployment of the Secret Broker.
# Spins up a single 2C2G ECS in cn-beijing, runs the broker via Docker Compose.
# Security group: 22 (ssh, IP-restricted) + 8443 (mTLS HTTPS).
#
# Usage:
#   export ALICLOUD_ACCESS_KEY=...
#   export ALICLOUD_SECRET_KEY=...
#   terraform init
#   terraform plan -var-file=b.tfvars
#   terraform apply -var-file=b.tfvars
# Then SSH to the ECS:
#   ssh root@<eip>
#   cd /opt/secret-broker
#   ./scripts/broker/init-ca.sh
#   ./scripts/broker/issue-server-cert.sh --domain broker.example.com
#   ./scripts/broker/issue-client-cert.sh --cn client.tyj-laptop
#   docker compose up -d broker

terraform {
  required_version = ">= 1.5"

  required_providers {
    alicloud = {
      source  = "aliyun/alicloud"
      version = "~> 1.200"
    }
  }

  # Local backend by default. State lives wherever you run terraform.
  # Switch to "oss" for shared team state.
  backend "local" {
    path = "terraform.tfstate"
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
  zone_id    = "cn-beijing-h"  # t6-c1m1.large available here
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

# mTLS HTTPS - 公网开放
resource "alicloud_security_group_rule" "mtls" {
  type              = "ingress"
  ip_protocol       = "tcp"
  port_range        = "8443/8443"
  security_group_id = alicloud_security_group.broker.id
  cidr_ip           = "0.0.0.0/0"
  description       = "mTLS HTTPS (client cert auth required)"
}

# 出站全开
resource "alicloud_security_group_rule" "egress_all" {
  type              = "egress"
  ip_protocol       = "all"
  port_range        = "-1/-1"
  security_group_id = alicloud_security_group.broker.id
  cidr_ip           = "0.0.0.0/0"
}

# ============================================================
# ECS
# ============================================================

# 选 2C2G 标准型
data "alicloud_instance_types" "broker" {
  cpu_core_count         = 2
  memory_size            = 2
  instance_type_family   = "ecs.t6"
  availability_zone      = "cn-beijing-h"
}

# Ubuntu 22.04 镜像
data "alicloud_images" "ubuntu" {
  most_recent = true
  owners      = "system"
  name_regex  = "^ubuntu_22_04_x64*"
}

resource "alicloud_instance" "broker" {
  instance_name              = "secret-broker"
  instance_type              = data.alicloud_instance_types.broker.instance_types[0].id
  image_id                   = data.alicloud_images.ubuntu.images[0].id
  vswitch_id                 = alicloud_vswitch.broker.id
  security_groups            = [alicloud_security_group.broker.id]
  internet_max_bandwidth_out = 10
  internet_charge_type       = "PayByTraffic"
  password                   = var.ssh_password
  instance_charge_type       = "PostPaid"
  system_disk_category       = "cloud_essd"
  system_disk_size           = 40

  data_disks {
    name        = "broker-data"
    size        = 50
    category    = "cloud_essd"
    encrypted   = true
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
  description = "Public EIP. SSH here, then point your broker client at https://<this>:8443"
}

output "broker_ssh_cmd" {
  value       = "ssh root@${alicloud_eip.broker.ip_address}"
}

output "broker_endpoint" {
  value       = "https://${var.broker_domain}:8443"
  description = "mTLS endpoint. Add DNS A record broker.example.com -> <EIP> in Cloudflare first."
}

output "next_steps" {
  value = <<-EOT
  1. SSH to ECS:  ssh root@${alicloud_eip.broker.ip_address}  (password in b.tfvars)
  2. cd /opt/secret-broker
  3. ./scripts/broker/init-ca.ps1   (or init-ca.sh if running in WSL)
  4. ./scripts/broker/issue-server-cert.ps1 -Domain ${var.broker_domain} -AltNames "localhost,127.0.0.1,${alicloud_eip.broker.ip_address}"
  5. ./scripts/broker/issue-client-cert.ps1 -CN client.tyj-laptop -Role developer -RegisterToConfig
  6. Place a SOPS-encrypted broker.yaml into /opt/secret-broker/secrets/
  7. Place a SOPS-encrypted common.env into /opt/secret-broker/secrets/
  8. Copy your age key to /opt/secret-broker/age/age.key (chmod 600)
  9. docker compose up -d broker
  10. From your laptop: secret-broker health
  EOT
}
