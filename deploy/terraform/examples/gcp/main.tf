###############################################################################
# GCP example: deploy broker on GKE + Workload Identity + Cloud DNS
###############################################################################
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.20.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# 1. GKE cluster with Workload Identity
resource "google_container_cluster" "broker" {
  name     = var.cluster_name
  location = var.region
  initial_node_count = 2
  workload_pool = "${var.project_id}.svc.id.goog"
  node_config {
    machine_type = "e2-standard-2"
    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }
}

# 2. Google-managed SSL cert
resource "google_compute_managed_ssl_certificate" "broker" {
  name = "broker-cert"
  managed {
    domains = ["broker.${var.domain}"]
  }
}

# 3. Backend service
resource "google_compute_backend_service" "broker" {
  name      = "broker-backend"
  protocol  = "HTTPS"
  timeout_sec = 30
  health_checks = [google_compute_health_check.broker.id]
}

resource "google_compute_health_check" "broker" {
  name = "broker-hc"
  check_interval_sec  = 30
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3
  https_health_check {
    port         = 8443
    request_path = "/health"
  }
}

# 4. Deploy broker with Workload Identity
provider "kubernetes" {
  host                   = "https://${google_container_cluster.broker.endpoint}"
  token                  = data.google_client_config.current.access_token
  cluster_ca_certificate = base64decode(google_container_cluster.broker.master_auth[0].cluster_ca_certificate)
}

data "google_client_config" "current" {}

# GCP service account for Workload Identity
resource "google_service_account" "broker" {
  account_id   = "broker-workload"
  display_name = "Broker Workload Identity"
}

resource "google_project_iam_member" "broker_workload" {
  project = var.project_id
  role    = "roles/iam.workloadIdentityUser"
  member  = "serviceAccount:${var.project_id}.svc.id.goog[broker/broker]"
}

module "broker" {
  source        = "../modules/broker"
  name          = "broker"
  replicas      = 2
  broker_config = file("${path.module}/broker.yaml")
  tls_cert_pem  = file("${path.module}/tls.crt")
  tls_key_pem   = file("${path.module}/tls.key")
  ca_cert_pem   = file("${path.module}/ca.crt")
}

variable "project_id" { type = string }
variable "region" { default = "us-central1" }
variable "cluster_name" { default = "broker-gke" }
variable "domain" { default = "example.com" }
