# Cloud Marketplace Images — 5-Marketplace Strategy & Spec

> **Status**: P1 #3 partial — 5-marketplace 整体 spec + 1 marketplace 实际 Packer config shipped
> **ROADMAP**: target 2026-10-31 (5 listings live, install count tracked in BrokerCacheStat)
> **Source**: [ROADMAP-post-1.0.md §3](../ROADMAP-post-1.0.md#3-cloud-marketplace-images-w27-w32)

---

## 1. Goals

Publish Secret Broker to **5 cloud marketplaces** so users can launch
pre-configured broker instances in 1-click from their cloud console:

| Marketplace | Region | Format | Target launch | Status (2026-09-06) |
|-------------|--------|--------|---------------|--------------------|
| **AWS Marketplace** | Global | AMI (Packer build) | 2026-10-15 | 🔄 Packer template drafted in this PR |
| **Azure Marketplace** | Global | VHD (Packer build) | 2026-10-22 | ⏳ After AWS |
| **Google Cloud Marketplace** | Global | Container on Marketplace | 2026-10-29 | ⏳ After Azure |
| **Aliyun 镜像市场** (China) | cn-shanghai / cn-beijing | VHD (Packer build) | 2026-10-31 | ⏳ After GCP |
| **Tencent Cloud 镜像市场** (China) | ap-shanghai / ap-beijing | VHD (Packer build) | 2026-10-31 | ⏳ After Aliyun |

## 2. Why 5 marketplaces

- **Global reach**: AWS / Azure / GCP = 70% of cloud workloads (Gartner 2026)
- **China reach**: Aliyun + Tencent = 80% of China cloud (IDC 2026)
- **1-click UX**: marketplace launches are easier than BYO VM + docker
- **Compliance shortcut**: marketplace images often pre-cleared for regulated industries (HIPAA, PCI, SOC 2)

**Out of scope** (Phase 2+):
- IBM Cloud Marketplace (low market share)
- Oracle Cloud Marketplace (low market share)
- Huawei Cloud (similar to Aliyun/Tencent, would require additional certifications)
- Bare-metal marketplace (Packet / Equinix — already covered by [DEPLOY-52TRZ.md](../DEPLOY-52TRZ.md))

## 3. Standardized build pipeline (all 5 marketplaces)

Each marketplace listing needs **3 artifacts**:

1. **Marketplace image** (Packer build):
   - Base OS (Ubuntu 22.04 LTS or Amazon Linux 2023)
   - Pre-installed: Docker, Node.js 20, SOPS, age, broker V4.1.x binary
   - Pre-configured: mTLS PKI stub, audit log directory, broker user (uid 1000)
   - **No secrets bundled** (user must set up their own SOPS age key)
   - Test: `cloud-init` user-data runs `systemctl status broker` and checks for `/health` endpoint

2. **Deployment template** (CloudFormation / ARM / Deployment Manager / ROS):
   - 1-click launch: user picks instance type + size + region
   - Auto-creates: security group (only 443 public, broker 8443 loopback via ALB),
     IAM role (cloud-storage permissions, no admin), CloudWatch log group
   - Outputs: broker HTTPS URL, mTLS CA cert (PEM), mTLS enrollment QR (admin)

3. **Documentation** (`docs/cloud-marketplace/{aws,azure,gcp,alibyte,tencent}.md`):
   - 1-click launch walkthrough
   - Post-launch setup (mTLS enrollment, SOPS age key, first service)
   - Pricing model (BYOL = bring your own license, free; or hourly = pay per instance hour)
   - Support channel (GitHub Issues, security@)

## 4. AWS Marketplace (P1 #3a) — first to ship

### 4.1 Build artifacts in this PR

- `deploy/packer/aws-broker.pkr.hcl` — Packer template for Ubuntu 22.04 AMI
  - Source: `amazon-ebs` (Ubuntu 22.04 LTS base)
  - Provisioners: shell scripts (apt install docker + nodejs + sops + age; download broker V4.1.x tarball; extract to /opt/secret-broker; create systemd unit)
  - Post-processors: tag + share to specified AWS account
- `deploy/packer/cfn-template.yaml` — CloudFormation template for 1-click launch
  - Parameters: instance type, VPC, subnet, SSH key, broker version
  - Resources: EC2 instance + security group (443 public) + IAM role (CloudWatch + S3) + ALB (TLS termination)
  - Outputs: broker URL, CA cert download URL, mTLS enrollment URL
- `deploy/packer/README.md` — maintainer guide
  - How to build the AMI locally
  - How to upload to AWS Marketplace via AWS Marketplace Management Portal
  - Pricing model: BYOL default, $0.10/hour option
  - Support: GitHub Issues

### 4.2 Why AWS first

- Largest cloud market share (~32%)
- Most mature marketplace program (since 2012)
- Best developer tooling (Packer, CloudFormation, CDK)
- Easiest to launch + iterate

### 4.3 AWS Marketplace submission checklist

- [ ] `aws s3 cp secret-broker-v4.1.x.tar.gz s3://tyj1987-marketplace/`
- [ ] Packer build → AMI in us-east-1 + us-west-2 + eu-west-1
- [ ] Upload AMI to AWS Marketplace via "Upload from S3" or "Scan AMI"
- [ ] Create product: "Secret Broker — mTLS credential proxy for AI clients"
- [ ] Pricing: BYOL (free) + $0.10/hour (covers maintenance)
- [ ] EULA: standard AWS Marketplace EULA (no custom EULA needed)
- [ ] Support: contact broker@52trz.com, response 48h
- [ ] Categories: "Security" > "Identity & Access Management"
- [ ] Search keywords: mTLS, credentials, AI, secret management, OAuth, broker, proxy
- [ ] Logo: 200x200 PNG
- [ ] Screenshots: 5+ (dashboard, mTLS enrollment, audit log, alert, system tray)
- [ ] Description: 4000 char max
- [ ] Pricing dimensions: instance-hour + data transfer
- [ ] **Lead time**: AWS Marketplace review = 1-4 weeks

### 4.4 Cost estimate

- Packer build: 30 min × $0.05/min = $1.50/AMI × 3 regions = $4.50
- Marketplace listing fee: **$0** (AWS charges only on sales)
- Storage of 3 AMIs: 3 × 8 GB × $0.10/GB-month = $2.40/month
- Total upfront: ~$7 + first-month storage
- Royalty to AWS: 20% of hourly rate (so $0.02/hour of $0.10)

## 5. Azure Marketplace (P1 #3b) — after AWS

### 5.1 Build approach

- **VHD format** (Azure-specific, not AMI)
- Packer has `azure-arm` builder: source Azure Gallery image → customize → VHD → publish to Azure Compute Gallery
- CloudFormation equivalent: **ARM template** (Azure Resource Manager)
- 1-click: user clicks "Get It Now" → fills in VM size + region + admin → deploys

### 5.2 Submission checklist

- [ ] Azure account + Partner Center registration
- [ ] Packer `azure-arm` build → VHD in Azure Compute Gallery
- [ ] Azure Marketplace offer: "Secret Broker" (publisher: tyj1987-broker)
- [ ] Plan: BYOL + Pay-as-you-go
- [ ] Categories: "Security + Identity"
- [ ] Media: 5 screenshots, 1 logo, 1 video (optional)
- [ ] Lead time: Azure Marketplace review = 1-4 weeks

## 6. Google Cloud Marketplace (P1 #3c) — after Azure

### 6.1 Build approach

- **Container image** (not VM) — push to `gcr.io/tyj1987-public/broker` (or Artifact Registry)
- **Deployment Manager template** or **Terraform** (Google-recommended)
- 1-click: user clicks "Launch" → GCE instance + container + service account
- Easier than AWS/Azure (no VHD/AMI)

### 6.2 Submission checklist

- [ ] GCP project + Marketplace API enabled
- [ ] Container pushed to `gcr.io/tyj1987-public/broker:v4.1.1` (signed with cosign)
- [ ] Deployment Manager template (Python or Jinja2)
- [ ] GCP Marketplace partner registration
- [ ] Categories: "Security > Identity & Access Management"
- [ ] Media: 5 screenshots
- [ ] Lead time: GCP Marketplace review = 1-2 weeks (fastest)

## 7. Aliyun 镜像市场 (P1 #3d) — China

### 7.1 Build approach

- **VHD format** (same as Azure)
- Packer has `alibyte-ecs` builder
- 1-click: user clicks "立即购买" → ECS instance + security group + RAM role
- Aliyun-specific: RAM role (instead of IAM), 安全组 (security group), VPC + VSwitch

### 7.2 CN-specific docs

- `docs/zh-CN/CLOUD-MARKETPLACE-ALIYUN.md` — Simplified Chinese user guide
- `docs/zh-CN/QUICKSTART.md` — 全中文 QUICKSTART
- Translate key sections: README, QUICKSTART, ARCHITECTURE (摘要)

### 7.3 Submission checklist

- [ ] Aliyun account + 镜像市场 partner registration (需 营业执照 + ICP 备案)
- [ ] Packer `alibyte-ecs` build → VHD in cn-shanghai + cn-beijing
- [ ] Aliyun 镜像市场 offer: "Secret Broker — AI 凭据代理"
- [ ] 类别: "安全 > 身份认证"
- [ ] 媒体: 5 截图 (中文 UI)
- [ ] Lead time: Aliyun 审核 = 2-4 周 (含中文审核)

## 8. Tencent Cloud 镜像市场 (P1 #3e) — China

### 8.1 Build approach

- **VHD format** (same as Aliyun)
- Packer has `tencentcloud-cvm` builder
- 1-click: user clicks "立即开通" → CVM instance + 安全组 + CAM role
- Tencent-specific: CAM role (similar to RAM), 安全组, VPC + 子网

### 8.2 Submission checklist

- [ ] Tencent Cloud account + 镜像市场 partner registration (需 营业执照)
- [ ] Packer `tencentcloud-cvm` build → VHD in ap-shanghai + ap-beijing
- [ ] Tencent 镜像市场 offer: "Secret Broker — AI 凭据代理"
- [ ] 类别: "安全 > 身份认证"
- [ ] 媒体: 5 截图 (中文 UI)
- [ ] Lead time: Tencent 审核 = 2-4 周

## 9. Phased rollout (P1 #3)

| Phase | What | When | Status |
|-------|------|------|--------|
| 3a | AWS Marketplace | 2026-10-15 | 🔄 Packer template + CFN template (this PR) |
| 3b | Azure Marketplace | 2026-10-22 | ⏳ (after AWS) |
| 3c | Google Cloud Marketplace | 2026-10-29 | ⏳ (after Azure) |
| 3d | Aliyun 镜像市场 | 2026-10-31 | ⏳ (after GCP) |
| 3e | Tencent Cloud 镜像市场 | 2026-10-31 | ⏳ (after Aliyun) |
| 3f | Install count tracking | 2026-10-31 | ⏳ (BrokerCacheStat) |

**Sequencing rationale**: each marketplace vendor has its own quirks + review
process; doing them sequentially lets us learn from AWS (3a) and apply
patterns to Azure (3b) / GCP (3c) / Aliyun (3d) / Tencent (3e).

**Parallelization**: AWS + GCP can be parallelized (similar APIs); Aliyun +
Tencent can be parallelized (both Chinese, both Packer-based). But
submitting in parallel = 5x the maintainer time. Sequential is safer.

## 10. Maintainer workflow (per marketplace)

```
1. 写 Packer template (1 day)  → this PR for AWS
2. 写 deployment template (1 day)  → CFN for AWS
3. 写 user docs (1 day)  → docs/cloud-marketplace/aws.md (or zh-CN for Aliyun/Tencent)
4. 跑 Packer build (1 hour, $1.50/AMI)
5. 测试 marketplace image (1 day) — launch in own cloud account, run integration test
6. 准备 marketplace partner registration (1-4 weeks vendor review)
7. Submit listing (1 day)
8. 等 vendor review (1-4 weeks)
9. Promote to "Live" (1 day)
10. Track install count in BrokerCacheStat (ongoing)
```

**Per marketplace**: 2-3 days maintainer work + 1-4 weeks vendor review.

## 11. Post-launch monitoring

Once all 5 listings are live, track:

- **Install count**: each marketplace provides a dashboard; feed into broker's
  `BrokerCacheStat` endpoint (`GET /api/v1/stats/marketplace`)
- **Cloud-init success rate**: user-data script logs `broker_started_at` +
  `health_ok=true` to CloudWatch / Azure Monitor / Cloud Logging
- **Default config usage**: 80%+ users should use defaults (mTLS on,
  default port 8443, no service config); if <60%, simplify UX

## 12. Cost estimate (total P1 #3)

| Item | Cost |
|------|------|
| Packer builds (5 marketplaces × 3 regions) | $30 |
| Marketplace partner fees | $0 (most charge on sales only) |
| Storage (5 marketplaces × 3 regions × 8 GB) | $12/month |
| Translation (zh-CN docs) | $500-1000 (one-time) |
| Maintainer time (5 × 2-3 days) | volunteer / tyj1987 |
| **Total upfront** | **~$600** |
| **Total recurring** | **~$12/month** |

## 13. Refs

- [ROADMAP-post-1.0.md §3](../ROADMAP-post-1.0.md#3-cloud-marketplace-images-w27-w32)
- [AWS Marketplace Seller Guide](https://docs.aws.amazon.com/marketplace/latest/controllerguide/seller-guide.html)
- [Azure Marketplace Publisher Guide](https://learn.microsoft.com/en-us/azure/marketplace/marketplace-publishers-guide)
- [Google Cloud Marketplace](https://cloud.google.com/marketplace/docs/partners)
- [Aliyun 镜像市场 partner](https://market.aliyun.com/partner)
- [Tencent Cloud 镜像市场](https://market.cloud.tencent.com/)
- [Packer by HashiCorp](https://www.packer.io/)

## 14. License

This document is licensed under MIT — see [LICENSE](../LICENSE).
