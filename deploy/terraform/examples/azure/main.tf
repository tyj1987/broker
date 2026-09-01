###############################################################################
# Azure example: deploy broker on AKS + Azure Key Vault cert + Front Door
###############################################################################
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.70.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.20.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# 1. AKS cluster (or use existing)
resource "azurerm_resource_group" "broker" {
  name     = "${var.name}-rg"
  location = var.location
}

resource "azurerm_kubernetes_cluster" "broker" {
  name                = var.cluster_name
  location            = azurerm_resource_group.broker.location
  resource_group_name = azurerm_resource_group.broker.name
  dns_prefix          = var.name
  default_node_pool {
    name       = "default"
    node_count = 2
    vm_size    = "Standard_B2ms"
  }
  identity {
    type = "SystemAssigned"
  }
}

# 2. Key Vault for broker TLS cert
data "azurerm_key_vault" "broker" {
  name                = var.key_vault_name
  resource_group_name = var.key_vault_rg
}

data "azurerm_key_vault_certificate" "broker" {
  name         = "broker-tls"
  key_vault_id = data.azurerm_key_vault.broker.id
}

# 3. Deploy broker
provider "kubernetes" {
  host                   = azurerm_kubernetes_cluster.broker.kube_config[0].host
  client_certificate     = base64decode(azurerm_kubernetes_cluster.broker.kube_config[0].client_certificate)
  client_key             = base64decode(azurerm_kubernetes_cluster.broker.kube_config[0].client_key)
  cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.broker.kube_config[0].cluster_ca_certificate)
}

module "broker" {
  source        = "../modules/broker"
  name          = "broker"
  replicas      = 2
  broker_config = file("${path.module}/broker.yaml")
  tls_cert_pem  = data.azurerm_key_vault_certificate.broker.certificate_data
  tls_key_pem   = data.azurerm_key_vault_certificate.broker.certificate_data  # PFX; use azurerm_key_vault_certificate_data for separate key
  ca_cert_pem   = data.azurerm_key_vault_certificate.broker.certificate_data
}

variable "name" { default = "broker" }
variable "cluster_name" { default = "broker-aks" }
variable "location" { default = "eastus" }
variable "key_vault_name" { type = string }
variable "key_vault_rg" { type = string }
