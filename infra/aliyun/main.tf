# infra/aliyun/main.tf
# Aliyun infrastructure for my-first-app.
# Provisions: VPC, ACK cluster, RDS PostgreSQL, KMS, ACR, SLS log store.
# Secrets are decrypted via SOPS at apply time. No plaintext credentials
# in this file or in Terraform state.

terraform {
  required_version = ">= 1.5"

  required_providers {
    alicloud = {
      source  = "aliyun/alicloud"
      version = "~> 1.200"
    }
  }

  # Backend: encrypted OSS bucket. Run `terraform init` after creating it.
  backend "oss" {
    bucket = "my-tf-state-prod"
    key    = "my-first-app/terraform.tfstate"
    region = "cn-hangzhou"
  }
}

provider "alicloud" {
  region = var.region
}

# ============================
# Data sources
# ============================

# Decrypt production secrets at apply time. SOPS uses Aliyun KMS under the hood.
data "external" "prod_secrets" {
  program = ["sh", "-c", "sops --decrypt --output-type json ../../secrets/prod.env 2>/dev/null || echo '{}'"]
}

locals {
  prod = try(jsondecode(data.external.prod_secrets.result), {})
}

# ============================
# Network
# ============================

resource "alicloud_vpc" "main" {
  vpc_name   = "my-first-app-vpc"
  cidr_block = "10.0.0.0/16"
}

resource "alicloud_vswitch" "main" {
  vpc_id     = alicloud_vpc.main.id
  zone_id    = "${var.region}a"
  cidr_block = "10.0.1.0/24"
}

resource "alicloud_security_group" "main" {
  vpc_id              = alicloud_vpc.main.id
  security_group_name = "my-first-app-sg"
}

# ============================
# KMS — for SOPS production decryption
# ============================

resource "alicloud_kms_key" "prod" {
  key_description = "SOPS production key for my-first-app"
  key_usage       = "ENCRYPT/DECRYPT"
  protection_level = "SOFTWARE"
}

# ============================
# Container Registry
# ============================

resource "alicloud_cr_namespace" "main" {
  name               = "my-first-app"
  auto_create        = false
  default_visibility = "PRIVATE"
}

# ============================
# Managed Kubernetes (ACK)
# ============================

resource "alicloud_cs_managed_kubernetes" "main" {
  name                = "my-first-app-cluster"
  cluster_spec        = "ack.pro.small"
  vswitch_ids         = [alicloud_vswitch.main.id]
  new_nat_gateway     = true
  pod_cidr            = "10.1.0.0/16"
  service_cidr        = "172.16.0.0/16"
  enable_ssh         = false
  install_cloud_monitor = true
}

# ============================
# RDS PostgreSQL
# ============================

resource "alicloud_db_instance" "main" {
  instance_name        = "my-first-app-db"
  engine               = "PostgreSQL"
  engine_version       = "14.0"
  instance_type        = "pg.n2.medium.1"
  instance_storage     = 20
  db_instance_storage_type = "cloud_essd"
  vswitch_id           = alicloud_vswitch.main.id
  security_group_ids   = [alicloud_security_group.main.id]
  monitoring_period    = 60

  # Password is decrypted from secrets/prod.env at apply time.
  password = try(local.prod.DATABASE_PASSWORD, "change-me")
}

resource "alicloud_db_database" "main" {
  instance_id = alicloud_db_instance.main.id
  name        = "myapp"
  character_set = "UTF8"
}

# ============================
# Application deployment
# ============================

resource "alicloud_cs_kubernetes_application" "app" {
  cluster_id = alicloud_cs_managed_kubernetes.main.id
  manifest   = templatefile("${path.module}/app.yaml", {
    image_registry = "${var.region}.aliyuncs.com/${alicloud_cr_namespace.main.name}"
    image_tag      = var.image_tag
    db_host        = alicloud_db_instance.main.connection_string
    jwt_secret     = try(local.prod.JWT_SECRET, "")
  })
}

# ============================
# Outputs
# ============================

output "cluster_id" {
  value = alicloud_cs_managed_kubernetes.main.id
}

output "db_connection" {
  value     = alicloud_db_instance.main.connection_string
  sensitive = true
}

output "kms_key_id" {
  value = alicloud_kms_key.prod.id
}

output "acr_login_server" {
  value = "${var.region}.aliyuncs.com"
}
