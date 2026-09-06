# Packer template for Secret Broker AWS Marketplace AMI
#
# Build: packer init . && packer build -var-file=variables.pkrvars.hcl .
# Output: AMI in us-east-1 / us-west-2 / eu-west-1 (configurable)
#
# Tested with: Packer 1.11.x, AWS plugin 1.2.x
# AMI base: Ubuntu 22.04 LTS (Canonical, free-tier eligible)
# Broker: V4.1.x (parameterized via broker_version variable)

packer {
  required_plugins {
    amazon = {
      version = ">= 1.2.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

# === Variables ===
variable "region" {
  type    = string
  default = "us-east-1"
}

variable "broker_version" {
  type    = string
  default = "4.1.1"
}

variable "instance_type" {
  type    = string
  default = "t3.small"  # 2 vCPU / 2 GB RAM (smallest viable for broker)
}

variable "ssh_username" {
  type    = string
  default = "ubuntu"
}

variable "ami_name_prefix" {
  type    = string
  default = "secret-broker"
}

variable "share_account_ids" {
  type    = list(string)
  default = []  # AWS Marketplace will register this AMI under the marketplace seller account
  description = "Additional AWS account IDs to share the AMI with (e.g. for testing)"
}

# === Source: Ubuntu 22.04 LTS ===
source "amazon-ebs" "broker" {
  ami_name      = "${var.ami_name_prefix}-${var.broker_version}-{{timestamp}}"
  ami_description = "Secret Broker ${var.broker_version} — mTLS credential proxy for AI clients"
  ami_regions    = [var.region]

  # Ubuntu 22.04 LTS (Canonical)
  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    most_recent = true
    owners      = ["099720109477"]  # Canonical
  }

  instance_type = var.instance_type
  ssh_username  = var.ssh_username
  region        = var.region

  # Tag the AMI (required by AWS Marketplace)
  tags = {
    Name              = "secret-broker-${var.broker_version}"
    Version           = var.broker_version
    OS                = "Ubuntu-22.04"
    Application       = "secret-broker"
    Architecture      = "x86_64"
    Maintainer        = "tyj1987"
    "License Type"    = "MIT"
  }

  # Snapshot tags (for billing / cost allocation)
  snapshot_tags = {
    Name    = "secret-broker-${var.broker_version}"
    Version = var.broker_version
  }

  # Wait for cloud-init to complete before AMIs are created
  wait_after_create = "60s"
  enable_ipv6       = false
}

# === Build ===
build {
  name    = "secret-broker-ami"
  sources = ["source.amazon-ebs.broker"]

  # 1. Base system update + install prerequisites
  provisioner "shell" {
    inline = [
      "set -euxo pipefail",
      "sudo apt-get update -y",
      "sudo apt-get install -y curl wget apt-transport-https ca-certificates gnupg lsb-release",
    ]
  }

  # 2. Install Node.js 20.x (broker runtime)
  provisioner "shell" {
    inline = [
      "set -euxo pipefail",
      "curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -",
      "sudo apt-get install -y nodejs",
      "node --version  # verify v20.x",
    ]
  }

  # 3. Install SOPS + age (secret encryption)
  provisioner "shell" {
    inline = [
      "set -euxo pipefail",
      "SOPS_VERSION=3.9.4",
      "AGE_VERSION=1.2.0",
      "curl -fsSL -o /tmp/sops https://github.com/getsops/sops/releases/download/v${SOPS_VERSION}/sops-v${SOPS_VERSION}.linux.amd64",
      "sudo install -m 0755 /tmp/sops /usr/local/bin/sops",
      "sops --version  # verify",
      "curl -fsSL -o /tmp/age.tar.gz https://github.com/FiloSottile/age/releases/download/v${AGE_VERSION}/age-v${AGE_VERSION}-linux-amd64.tar.gz",
      "tar -xzf /tmp/age.tar.gz -C /tmp/",
      "sudo install -m 0755 /tmp/age/age /tmp/age/age-keygen /usr/local/bin/",
      "age --version  # verify",
    ]
  }

  # 4. Download + install broker V4.1.x
  provisioner "shell" {
    environment_vars = ["DEBIAN_FRONTEND=noninteractive"]
    inline = [
      "set -euxo pipefail",
      "BROKER_VERSION=${var.broker_version}",
      "cd /tmp",
      "wget -q https://github.com/tyj1987/broker/releases/download/v${BROKER_VERSION}/broker-${BROKER_VERSION}.tar.gz",
      "sudo mkdir -p /opt/secret-broker",
      "sudo tar -xzf broker-${BROKER_VERSION}.tar.gz -C /opt/secret-broker --strip-components=1",
      "cd /opt/secret-broker",
      "sudo npm install --omit=dev --omit=optional",
      "sudo /opt/secret-broker/scripts/broker/install-ecs.sh --no-start 2>/dev/null || true",
    ]
  }

  # 5. Create broker user (uid 1000, no shell)
  provisioner "shell" {
    inline = [
      "set -euxo pipefail",
      "sudo useradd -r -u 1000 -s /usr/sbin/nologin -d /var/lib/secret-broker -m broker || true",
      "sudo mkdir -p /var/lib/secret-broker /var/log/secret-broker /etc/secret-broker",
      "sudo chown -R broker:broker /var/lib/secret-broker /var/log/secret-broker /etc/secret-broker",
    ]
  }

  # 6. Generate mTLS PKI stub (CA + server cert) — user rotates on first launch
  provisioner "shell" {
    inline = [
      "set -euxo pipefail",
      "sudo -u broker bash -c 'set -eux; cd /etc/secret-broker; mkdir -p pki/{ca,server,clients}; openssl genrsa -out pki/ca/ca.key 4096; openssl req -x509 -new -nodes -key pki/ca/ca.key -sha256 -days 3650 -subj \"/CN=secret-broker-default-ca\" -out pki/ca/ca.crt; openssl genrsa -out pki/server/server.key 2048; openssl req -new -key pki/server/server.key -subj \"/CN=secret-broker-server\" -out pki/server/server.csr; openssl x509 -req -in pki/server/server.csr -CA pki/ca/ca.crt -CAkey pki/ca/ca.key -CAcreateserial -out pki/server/server.crt -days 365 -sha256'",
      "echo '⚠️  This is a DEFAULT PKI for first launch. ROTATE before production!' | sudo tee /etc/secret-broker/pki/ROTATE-BEFORE-PRODUCTION.txt",
    ]
  }

  # 7. Install systemd unit
  provisioner "file" {
    source      = "files/broker.service"
    destination = "/tmp/broker.service"
  }

  provisioner "shell" {
    inline = [
      "set -euxo pipefail",
      "sudo mv /tmp/broker.service /etc/systemd/system/secret-broker.service",
      "sudo chmod 0644 /etc/systemd/system/secret-broker.service",
      "sudo systemctl daemon-reload",
      "sudo systemctl disable secret-broker  # don't auto-start, user enables on first launch",
    ]
  }

  # 8. Install cloud-init user-data (runs on first launch)
  provisioner "file" {
    source      = "files/cloud-init-user-data.sh"
    destination = "/tmp/cloud-init-user-data.sh"
  }

  provisioner "shell" {
    inline = [
      "set -euxo pipefail",
      "sudo mv /tmp/cloud-init-user-data.sh /var/lib/cloud/secret-broker-init.sh",
      "sudo chmod 0755 /var/lib/cloud/secret-broker-init.sh",
    ]
  }

  # 9. AMI cleanup (remove temp files, SSH keys, etc.)
  provisioner "shell" {
    inline = [
      "set -euxo pipefail",
      "sudo apt-get clean",
      "sudo rm -rf /tmp/* /var/tmp/*",
      "sudo rm -f /var/log/wtmp /var/log/btmp",
      "sudo history -c  # clear shell history",
      "sudo shred -u /etc/ssh/*_key /etc/ssh/*_key.pub 2>/dev/null || true",
    ]
  }
}

# === Post-process: Share AMI to additional accounts (for testing) ===
post-processor "manifest" {
  output     = "manifest.json"
  strip_path = true
  custom_data = {
    broker_version = var.broker_version
    build_time     = timestamp()
  }
}
