# infra/tencent/broker.tf
# 腾讯云部署 Secret Broker（CVM 镜像 + 数据盘 + EIP + 安全组）
# 灾备使用：阿里云主，腾讯云备，平时空跑
# 当主故障时切 DNS 指向这里（failover 脚本见 scripts/broker/failover.sh）

terraform {
  required_version = ">= 1.5"

  required_providers {
    tencentcloud = {
      source  = "tencentcloudstack/tencentcloud"
      version = "~> 1.81"
    }
  }

  backend "cos" {
    bucket = "my-tf-state-prod-1250000000"
    key    = "secret-broker/tencent/terraform.tfstate"
    region = "ap-shanghai"
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
  availability_zone = "${var.region}1"
}

# 安全组
resource "tencentcloud_security_group" "broker" {
  name        = "secret-broker-sg"
  description = "Secret Broker - mTLS HTTPS only"
}

# SSH 仅 admin IP
resource "tencentcloud_security_group_lite_rule" "ssh" {
  security_group_id = tencentcloud_security_group.broker.id
  type              = "ingress"
  protocol          = "TCP"
  port              = "22"
  cidr_ip           = var.admin_cidr
  policy            = "accept"
  description       = "SSH from admin"
}

# mTLS HTTPS 公网
resource "tencentcloud_security_group_lite_rule" "mtls" {
  security_group_id = tencentcloud_security_group.broker.id
  type              = "ingress"
  protocol          = "TCP"
  port              = "8443"
  cidr_ip           = "0.0.0.0/0"
  policy            = "accept"
  description       = "mTLS HTTPS (client cert auth)"
}

# 出站
resource "tencentcloud_security_group_lite_rule" "egress" {
  security_group_id = tencentcloud_security_group.broker.id
  type              = "egress"
  protocol          = "ALL"
  port              = "ALL"
  cidr_ip           = "0.0.0.0/0"
  policy            = "accept"
}

# ============================
# CVM - 单实例跑 broker
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

# 选 Ubuntu 22.04 镜像
data "tencentcloud_images" "ubuntu" {
  image_type = ["PUBLIC_IMAGE"]
  image_name_regex = ["^Ubuntu Server 22.04 LTS 64位$"]
}

resource "tencentcloud_instance" "broker" {
  instance_name              = "secret-broker"
  availability_zone          = "${var.region}1"
  image_id                   = data.tencentcloud_images.ubuntu.images[0].image_id
  instance_type              = data.tencentcloud_instance_types.broker.instance_types[0].instance_type
  vpc_id                     = tencentcloud_vpc.broker.id
  subnet_id                  = tencentcloud_subnet.broker.id
  security_groups            = [tencentcloud_security_group.broker.id]
  internet_max_bandwidth_out = 10
  allocate_public_ip         = false  # 用 EIP 关联
  password                   = var.ssh_password
  instance_charge_type       = "POSTPAID_BY_HOUR"
  system_disk_type           = "CLOUD_PREMIUM"
  system_disk_size           = 40

  data_disks {
    data_disk_type = "CLOUD_PREMIUM"
    data_disk_size = 50
    encrypt        = true
  }
}

# EIP
resource "tencentcloud_eip" "broker" {
  name                  = "secret-broker-eip"
  internet_max_bandwidth_out = 10
  internet_charge_type  = "TRAFFIC_POSTPAID_BY_HOUR"
  instance_type         = "EIP"
  type                  = "EIP"
}

resource "tencentcloud_eip_association" "broker" {
  eip_id      = tencentcloud_eip.broker.id
  instance_id = tencentcloud_instance.broker.id
}

# ============================
# Outputs
# ============================

output "broker_public_ip" {
  value       = tencentcloud_eip.broker.ip_address
  description = "Secret Broker 公网 IP（灾备，平时不用）"
}

output "broker_ssh_cmd" {
  value       = "ssh ubuntu@${tencentcloud_eip.broker.ip_address}"
}

output "failover_note" {
  value = <<-EOT
  Failover 流程：
  1. 阿里云 broker 故障时，把 broker.${var.broker_domain} 的 DNS A 记录指向 ${tencentcloud_eip.broker.ip_address}
  2. 在腾讯云 ECS 上：
     - rsync secrets/, pki/, age/  from 阿里云
     - docker compose up -d broker
  3. 反向 failover 同样
  详细：scripts/broker/failover.sh
  EOT
}
