# infra/tencent/main.tf
# Tencent Cloud infrastructure for my-first-app.
# Mirror of infra/aliyun — same shape, different provider.
# Use this for HA: deploy to both, route DNS to whichever is healthy.

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
    key    = "my-first-app/terraform.tfstate"
    region = "ap-shanghai"
  }
}

provider "tencentcloud" {
  region = var.region
}

# Decrypt production secrets via SOPS using Tencent KMS.
data "external" "prod_secrets" {
  program = ["sh", "-c", "sops --decrypt --output-type json ../../secrets/prod.env 2>/dev/null || echo '{}'"]
}

locals {
  prod = try(jsondecode(data.external.prod_secrets.result), {})
}

# ============================
# Network
# ============================

resource "tencentcloud_vpc" "main" {
  name       = "my-first-app-vpc"
  cidr_block = "10.0.0.0/16"
}

resource "tencentcloud_subnet" "main" {
  vpc_id            = tencentcloud_vpc.main.id
  name              = "my-first-app-subnet"
  cidr_block        = "10.0.1.0/24"
  availability_zone = "${var.region}1"
}

# ============================
# KMS
# ============================

resource "tencentcloud_kms_key" "prod" {
  key_name  = "my-first-app-prod"
  key_usage = "ENCRYPT_DECRYPT"
  description = "SOPS production key for my-first-app"
}

# ============================
# TCR (Tencent Container Registry)
# ============================

resource "tencentcloud_tcr_instance" "main" {
  name          = "my-first-app"
  instance_type = "basic"
  delete_bucket = false
}

resource "tencentcloud_tcr_namespace" "main" {
  instance_id    = tencentcloud_tcr_instance.main.id
  name           = "my-first-app"
  is_public      = false
}

# ============================
# TKE (Tencent Kubernetes Engine)
# ============================

resource "tencentcloud_kubernetes_cluster" "main" {
  vpc_id                  = tencentcloud_vpc.main.id
  cluster_cidr            = "10.1.0.0/16"
  cluster_max_pod_num     = 32
  cluster_name            = "my-first-app"
  cluster_desc            = "Production cluster for my-first-app"
  cluster_version         = "1.28"
  cluster_deploy_type     = "MANAGED_CLUSTER"
  subnet_id               = tencentcloud_subnet.main.id
  is_auto_upgrade         = false
}

# ============================
# TencentDB for PostgreSQL
# ============================

resource "tencentcloud_postgresql_instance" "main" {
  name              = "my-first-app-db"
  availability_zone = "${var.region}1"
  vpc_id            = tencentcloud_vpc.main.id
  subnet_id         = tencentcloud_subnet.main.id
  engine_version    = "14.4"
  root_user         = "appuser"
  root_password     = try(local.prod.DATABASE_PASSWORD, "change-me")
  charset           = "UTF8"
  project_id        = 0
  memory            = 2
  storage           = 20
}

# ============================
# Application deployment
# ============================

resource "tencentcloud_kubernetes_cluster_attachment" "app" {
  cluster_id = tencentcloud_kubernetes_cluster.main.id
  manifest   = templatefile("${path.module}/app.yaml", {
    image_registry = tencentcloud_tcr_instance.main.id
    image_tag      = var.image_tag
  })
  depends_on = [tencentcloud_tcr_namespace.main]
}

# ============================
# Outputs
# ============================

output "cluster_id" {
  value = tencentcloud_kubernetes_cluster.main.id
}

output "tcr_login_server" {
  value = tencentcloud_tcr_instance.main.id
}

output "kms_key_id" {
  value = tencentcloud_kms_key.prod.id
}
