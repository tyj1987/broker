# infra/aliyun/broker.tf
# Aliyun 部署 Secret Broker
# 跑一个单 ECS 实例（2C2G），Docker Compose 启动 broker
# 安全组：22 (ssh, IP 白名单) + 8443 (mTLS HTTPS)
#
# 用法：
#   terraform init
#   terraform plan -var-file=broker.tfvars
#   terraform apply -var-file=broker.tfvars
# 然后 SSH 上 ECS：
#   ssh root@<eip>
#   cd /opt/secret-broker
#   ./scripts/broker/init-ca.sh
#   ./scripts/broker/issue-server-cert.sh
#   docker compose up -d broker

terraform {
  required_version = ">= 1.5"

  required_providers {
    alicloud = {
      source  = "aliyun/alicloud"
      version = "~> 1.200"
    }
  }

  # 共享 backend（不同 key 区分 state）
  backend "oss" {
    bucket = "my-tf-state-prod"
    key    = "secret-broker/aliyun/terraform.tfstate"
    region = "cn-hangzhou"
  }
}

provider "alicloud" {
  region = var.region
}

# ============================
# Network
# ============================

data "alicloud_regions" "current" {
  current = true
}

resource "alicloud_vpc" "broker" {
  vpc_name   = "secret-broker-vpc"
  cidr_block = "10.10.0.0/16"
}

resource "alicloud_vswitch" "broker" {
  vpc_id     = alicloud_vpc.broker.id
  zone_id    = "${var.region}a"
  cidr_block = "10.10.1.0/24"
}

resource "alicloud_security_group" "broker" {
  vpc_id              = alicloud_vpc.broker.id
  security_group_name = "secret-broker-sg"
  description         = "Secret Broker - mTLS HTTPS only"
}

# SSH 入口 - 仅你办公 IP 可访问（用变量配置）
resource "alicloud_security_group_rule" "ssh" {
  type              = "ingress"
  ip_protocol       = "tcp"
  port_range        = "22/22"
  security_group_id = alicloud_security_group.broker.id
  cidr_ip           = var.admin_cidr
  description       = "SSH from admin IP only"
}

# mTLS HTTPS - 公网开放，靠客户端证书鉴权
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

# ============================
# ECS - 单实例跑 broker
# ============================

# 选一个便宜的按量付费实例类型
data "alicloud_instance_types" "broker" {
  cpu_core_count    = 2
  memory_size       = 2
  instance_type_family = "ecs.t6"
  availability_zone = "${var.region}a"
}

resource "alicloud_instance" "broker" {
  instance_name              = "secret-broker"
  instance_type              = data.alicloud_instance_types.broker.instance_types[0].id
  image_id                   = var.image_id
  vswitch_id                 = alicloud_vswitch.broker.id
  security_group_ids         = [alicloud_security_group.broker.id]
  internet_max_bandwidth_out = 10   # 10 Mbps, 够用
  password                   = var.ssh_password  # 用 password 简化，prod 应该用 key pair
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

# EIP
resource "alicloud_eip" "broker" {
  bandwidth            = 10
  bandwidth_package_id = null
  internet_charge_type = "PayByTraffic"
  payment_type         = "PayAsYouGo"
  description          = "Secret Broker public IP"
}

resource "alicloud_eip_association" "broker" {
  allocation_id = alicloud_eip.broker.id
  instance_id   = alicloud_instance.broker.id
}

# ============================
# 启动脚本：cloud-init 安装 Docker + clone 仓库
# ============================

data "cloudinit_config" "broker" {
  gzip          = true
  base64_encode = true

  part {
    filename     = "init.sh"
    content_type = "text/x-shellscript"
    content = templatefile("${path.module}/cloud-init.sh", {
      eip          = alicloud_eip.broker.ip_address
      ssh_password = var.ssh_password
      domain       = var.broker_domain
    })
  }
}

# Outputs
# ============================

output "broker_public_ip" {
  value       = alicloud_eip.broker.ip_address
  description = "Secret Broker 公网 IP（先用 IP 测试，再绑域名）"
}

output "broker_ssh_cmd" {
  value       = "ssh root@${alicloud_eip.broker.ip_address}"
  description = "SSH 登录命令"
}

output "broker_url" {
  value       = "https://${var.broker_domain}:8443"
  description = "mTLS endpoint（用 domain + 自签 CA 客户端证书）"
}

output "next_steps" {
  value = <<-EOT
  1. SSH 上 ECS: ssh root@${alicloud_eip.broker.ip_address} (password in broker.tfvars)
  2. cd /opt/secret-broker
  3. ./scripts/broker/init-ca.sh
  4. ./scripts/broker/issue-server-cert.sh --domain ${var.broker_domain}
  5. ./scripts/broker/issue-client-cert.sh --cn client.tyj-laptop
  6. 编辑 secrets/broker.yaml，加 SOPS 加密后放回 secrets/
  7. docker compose up -d broker
  8. 本地: secret-broker health --endpoint https://${var.broker_domain}:8443
  EOT
}
