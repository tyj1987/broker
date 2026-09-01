###############################################################################
# AWS example: deploy broker on EKS + AWS ACM cert + ALB ingress
###############################################################################
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.20.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.10.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# 1. EKS cluster (or use existing)
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"
  name    = var.cluster_name
  region  = var.region
  vpc_id  = var.vpc_id
  subnet_ids = var.subnet_ids
  eks_managed_node_groups = {
    main = {
      instance_types = ["t3.medium"]
      min_size       = 1
      max_size       = 3
    }
  }
}

# 2. ACM cert for broker
resource "aws_acm_certificate" "broker" {
  domain_name       = "broker.${var.domain}"
  validation_method = "DNS"
  lifecycle {
    create_before_destroy = true
  }
}

# 3. Deploy broker via local-path module
module "broker" {
  source = "../modules/broker"
  name   = "broker"
  replicas = 2
  broker_config = templatefile("${path.module}/broker.yaml.tpl", {
    region = var.region
  })
  tls_cert_pem = aws_acm_certificate.broker.certificate_body
  tls_key_pem  = aws_acm_certificate.broker.private_key
  ca_cert_pem  = file("${path.module}/ca.crt")
  depends_on = [module.eks]
}

# 4. ALB Ingress Controller chart (optional)
resource "helm_release" "aws_load_balancer_controller" {
  name      = "aws-load-balancer-controller"
  namespace = "kube-system"
  chart     = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  set {
    name  = "clusterName"
    value = var.cluster_name
  }
  set {
    name  = "serviceAccount.create"
    value = "false"
  }
  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }
  depends_on = [module.eks]
}

variable "region" {
  default = "us-east-1"
}

variable "cluster_name" {
  default = "broker-cluster"
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "domain" {
  default = "example.com"
}
