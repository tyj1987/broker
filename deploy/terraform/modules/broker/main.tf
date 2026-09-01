###############################################################################
# Secret Broker Terraform module
#
# Deploys the broker as Kubernetes manifests (Deployment + Service + ConfigMap
# + Secret + PVC + ServiceAccount + HPA + PDB) using the official Helm chart's
# resource shape. Use this when you want pure-Terraform (no Helm) deployment.
#
# For cloud-specific networking (AWS ALB / Azure Front Door / GCP Ingress),
# see the `examples/aws`, `examples/azure`, `examples/gcp` directories.
###############################################################################

resource "kubernetes_namespace" "broker" {
  metadata {
    name = var.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "pod-security.kubernetes.io/enforce" = "restricted"
    }
  }
}

resource "kubernetes_service_account" "broker" {
  metadata {
    name      = var.name
    namespace = kubernetes_namespace.broker.metadata[0].name
  }
  automount_service_account_token = true
}

# -------------------------------------------------------------------
# ConfigMap: non-sensitive broker config
# -------------------------------------------------------------------
resource "kubernetes_config_map_v1" "broker" {
  metadata {
    name      = var.name
    namespace = kubernetes_namespace.broker.metadata[0].name
  }
  data = {
    "config.yaml" = <<-YAML
      broker:
        version: "4.1.0"
      auto_rotate:
        enabled: false
      mfa_policy:
        enabled: true
        factors:
          - totp
          - webauthn
        risk_threshold: 60
      websocket:
        enabled: true
        heartbeat_interval_ms: 30000
      ssh_proxy:
        enabled: true
      alerting:
        enabled: true
        default_channel: console
    YAML
  }
}

# -------------------------------------------------------------------
# Secret: SOPS-encrypted broker.yaml + TLS material
# -------------------------------------------------------------------
resource "kubernetes_secret_v1" "broker" {
  metadata {
    name      = var.name
    namespace = kubernetes_namespace.broker.metadata[0].name
  }
  type = "Opaque"
  data = {
    "broker.yaml" = var.broker_config
  }
}

resource "kubernetes_secret_v1" "broker_tls" {
  metadata {
    name      = "${var.name}-tls"
    namespace = kubernetes_namespace.broker.metadata[0].name
  }
  type = "kubernetes.io/tls"
  data = {
    "tls.crt" = var.tls_cert_pem
    "tls.key" = var.tls_key_pem
    "ca.crt"  = var.ca_cert_pem
  }
}

# -------------------------------------------------------------------
# PVC: SOPS data persistence
# -------------------------------------------------------------------
resource "kubernetes_persistent_volume_claim_v1" "broker" {
  metadata {
    name      = "${var.name}-data"
    namespace = kubernetes_namespace.broker.metadata[0].name
  }
  spec {
    access_modes = ["ReadWriteOnce"]
    resources {
      requests = {
        storage = var.pvc_size
      }
    }
  }
}

# -------------------------------------------------------------------
# Deployment
# -------------------------------------------------------------------
resource "kubernetes_deployment_v1" "broker" {
  metadata {
    name      = var.name
    namespace = kubernetes_namespace.broker.metadata[0].name
    labels = {
      "app.kubernetes.io/name"       = var.name
      "app.kubernetes.io/instance"   = var.name
      "app.kubernetes.io/component"  = "secret-broker"
      "app.kubernetes.io/part-of"    = "ai-first-platform"
    }
  }
  spec {
    replicas = var.replicas
    selector {
      match_labels = {
        "app.kubernetes.io/name"     = var.name
        "app.kubernetes.io/instance" = var.name
      }
    }
    template {
      metadata {
        labels = {
          "app.kubernetes.io/name"     = var.name
          "app.kubernetes.io/instance" = var.name
        }
        annotations = {
          "prometheus.io/scrape" = "true"
          "prometheus.io/port"   = tostring(var.metrics_port)
          "prometheus.io/path"   = "/metrics"
        }
      }
      spec {
        service_account_name = kubernetes_service_account.broker.metadata[0].name
        security_context {
          fs_group             = 1000
          run_as_non_root      = true
          run_as_user          = 1000
        }
        container {
          name  = "broker"
          image = var.image
          image_pull_policy = "IfNotPresent"
          port {
            name           = "mtls"
            container_port = var.container_port
            protocol       = "TCP"
          }
          port {
            name           = "metrics"
            container_port = var.metrics_port
            protocol       = "TCP"
          }
          env {
            name  = "BROKER_CONFIG_PATH"
            value = "/etc/broker/broker.yaml"
          }
          env {
            name  = "BROKER_TLS_CERT"
            value = "/etc/broker/tls/tls.crt"
          }
          env {
            name  = "BROKER_TLS_KEY"
            value = "/etc/broker/tls/tls.key"
          }
          env {
            name  = "BROKER_CA_CERT"
            value = "/etc/broker/tls/ca.crt"
          }
          env {
            name  = "NODE_ENV"
            value = "production"
          }
          resources {
            requests = {
              cpu    = "200m"
              memory = "256Mi"
            }
            limits = {
              cpu    = var.cpu
              memory = var.memory
            }
          }
          liveness_probe {
            http_get {
              path   = "/health"
              port   = "mtls"
              scheme = "HTTPS"
            }
            initial_delay_seconds = 30
            period_seconds        = 30
            timeout_seconds       = 5
            failure_threshold     = 3
          }
          readiness_probe {
            http_get {
              path   = "/health"
              port   = "mtls"
              scheme = "HTTPS"
            }
            initial_delay_seconds = 10
            period_seconds        = 10
            timeout_seconds       = 3
            failure_threshold     = 3
          }
          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            run_as_non_root             = true
            run_as_user                 = 1000
            capabilities {
              drop = ["ALL"]
            }
          }
          volume_mount {
            name       = "config"
            mount_path = "/etc/broker"
            read_only  = true
          }
          volume_mount {
            name       = "tls"
            mount_path = "/etc/broker/tls"
            read_only  = true
          }
          volume_mount {
            name       = "data"
            mount_path = "/var/lib/broker"
          }
          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
        }
        volume {
          name = "config"
          projected {
            sources {
              config_map {
                name = kubernetes_config_map_v1.broker.metadata[0].name
              }
              secret {
                name = kubernetes_secret_v1.broker.metadata[0].name
                items {
                  key  = "broker.yaml"
                  path = "broker.yaml"
                }
              }
            }
          }
        }
        volume {
          name = "tls"
          secret {
            secret_name = kubernetes_secret_v1.broker_tls.metadata[0].name
            default_mode = "0400"
          }
        }
        volume {
          name = "data"
          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim_v1.broker.metadata[0].name
          }
        }
        volume {
          name = "tmp"
          empty_dir {}
        }
      }
    }
  }
}

# -------------------------------------------------------------------
# Service (ClusterIP)
# -------------------------------------------------------------------
resource "kubernetes_service_v1" "broker" {
  metadata {
    name      = var.name
    namespace = kubernetes_namespace.broker.metadata[0].name
  }
  spec {
    type = "ClusterIP"
    port {
      name        = "mtls"
      port        = var.container_port
      target_port = "mtls"
      protocol    = "TCP"
    }
    port {
      name        = "metrics"
      port        = var.metrics_port
      target_port = "metrics"
      protocol    = "TCP"
    }
    selector = {
      "app.kubernetes.io/name"     = var.name
      "app.kubernetes.io/instance" = var.name
    }
  }
}

# -------------------------------------------------------------------
# PodDisruptionBudget
# -------------------------------------------------------------------
resource "kubernetes_pod_disruption_budget_v1" "broker" {
  metadata {
    name      = var.name
    namespace = kubernetes_namespace.broker.metadata[0].name
  }
  spec {
    min_available = 1
    selector {
      match_labels = {
        "app.kubernetes.io/name"     = var.name
        "app.kubernetes.io/instance" = var.name
      }
    }
  }
}

# -------------------------------------------------------------------
# HPA
# -------------------------------------------------------------------
resource "kubernetes_horizontal_pod_autoscaler_v2" "broker" {
  count = var.replicas > 1 ? 1 : 0
  metadata {
    name      = var.name
    namespace = kubernetes_namespace.broker.metadata[0].name
  }
  spec {
    scale_target_ref {
      api_version = "apps/v1"
      kind       = "Deployment"
      name       = kubernetes_deployment_v1.broker.metadata[0].name
    }
    min_replicas = 2
    max_replicas = 5
    metric {
      type = "Resource"
      resource {
        name = "cpu"
        target {
          type                = "Utilization"
          average_utilization = 80
        }
      }
    }
  }
}
