# AWS Marketplace — Build & Publish (Maintainer)

## Prerequisites

- **Packer 1.11+** ([install](https://developer.hashicorp.com/packer/install))
- **AWS CLI v2** with `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` set
- **AWS account** with EC2 + IAM + S3 + CloudFormation + CloudWatch permissions
- **AWS Marketplace Seller registration** ([apply here](https://aws.amazon.com/marketplace/management/tour/))

## 1. Build the AMI

```bash
# 1. Install Packer plugins
packer init deploy/packer/

# 2. Set variables (optional, defaults are fine)
cat > variables.pkrvars.hcl <<EOF
region          = "us-east-1"
broker_version  = "4.1.1"
instance_type   = "t3.small"
ami_name_prefix = "secret-broker"
share_account_ids = ["123456789012"]  # your testing AWS account
EOF

# 3. Build
packer build -var-file=variables.pkrvars.hcl deploy/packer/aws-broker.pkr.hcl

# 4. Verify
aws ec2 describe-images --owners self --filters "Name=tag:Application,Values=secret-broker" \
  --query 'Images[*].[ImageId,Name,CreationDate]' --output table
```

## 2. Test the AMI

```bash
# 1. Launch via CloudFormation template (NOT yet in AWS Marketplace, but you can test directly)
aws cloudformation deploy \
  --template-file deploy/packer/cfn-template.yaml \
  --stack-name secret-broker-test \
  --parameter-overrides \
      InstanceType=t3.small \
      SSHKeyName=<your-keypair> \
      VpcId=<your-vpc> \
      SubnetId=<your-public-subnet> \
      BrokerVersion=4.1.1 \
  --capabilities CAPABILITY_IAM

# 2. Wait 5-10 min for stack creation
aws cloudformation wait stack-create-complete --stack-name secret-broker-test

# 3. Get broker URL
aws cloudformation describe-stacks --stack-name secret-broker-test \
  --query 'Stacks[0].Outputs[?OutputKey==`BrokerURL`].OutputValue' --output text

# 4. Test /health
BROKER_URL=$(aws cloudformation describe-stacks --stack-name secret-broker-test \
  --query 'Stacks[0].Outputs[?OutputKey==`BrokerURL`].OutputValue' --output text)
curl -k "$BROKER_URL/health"
# Expect: {"status":"ok","version":"4.1.1",...}

# 5. Cleanup
aws cloudformation delete-stack --stack-name secret-broker-test
```

## 3. Publish to AWS Marketplace

### 3.1 Prerequisites

1. **AWS Marketplace Seller account**: register at https://aws.amazon.com/marketplace/management/tour/
2. **Tax + banking info** in AWS Marketplace Management Portal
3. **Product logo** (200x200 PNG)
4. **5+ screenshots** of the broker dashboard
5. **Product description** (4000 char max)
6. **Pricing model**: BYOL (free) + $0.10/hour option
7. **Support contact**: broker@52trz.com, 48h response

### 3.2 Submit

1. AWS Marketplace Management Portal → "Server" → "Create new server product"
2. **Delivery method**: "Amazon Machine Image (AMI)"
3. **Region**: start with us-east-1, add us-west-2 + eu-west-1 after approval
4. **AMI**: select the Packer-built AMI (or "Scan AMI" if you want AWS to verify)
5. **Version**: V4.1.1
6. **Categories**: "Security" → "Identity & Access Management"
7. **Search keywords**: mTLS, credentials, AI, secret management, OAuth, broker, proxy, zero-knowledge
8. **Pricing**: 
   - Free BYOL: $0
   - Hourly: $0.10/hour (covers maintenance + support)
9. **EULA**: standard AWS Marketplace EULA
10. **Support**: broker@52trz.com, 48h response
11. **Submit** → wait 1-4 weeks for AWS review

### 3.3 Track install count

After launch, AWS Marketplace provides a dashboard with install count.
Feed into broker's `BrokerCacheStat`:

```bash
# Get install count (from AWS Marketplace Management Portal)
INSTALL_COUNT=$(aws marketplace-catalog list-entities --entity-type "AmiProduct" --query '...')

# POST to broker's stats endpoint
curl -k -X POST -H "X-Admin-Token: <admin-token>" \
  -d "{\"marketplace\": \"aws\", \"version\": \"4.1.1\", \"installs\": $INSTALL_COUNT}" \
  https://broker.52trz.com:8443/api/v1/stats/marketplace
```

## 4. Cost estimate

| Item | Cost |
|------|------|
| Packer build (per region) | $0.50 (5 min × $0.05/min) |
| Storage (per AMI) | $0.80/month (8 GB × $0.10/GB) |
| Marketplace listing fee | $0 (AWS charges only on sales) |
| AWS Marketplace royalty | 20% of hourly rate |
| **Total upfront** | **~$1-3** |
| **Total recurring** | **~$0.80-2.40/month per region** |

## 5. Update for new broker version

```bash
# 1. Update broker_version in variables.pkrvars.hcl
broker_version = "4.1.2"  # or 4.2.0, etc.

# 2. Build new AMI
packer build -var-file=variables.pkrvars.hcl deploy/packer/aws-broker.pkr.hcl

# 3. Submit as new version in AWS Marketplace Management Portal
#    (V4.1.1 stays available; V4.1.2 added as new version)
```

## 6. Refs

- [AWS Marketplace Seller Guide](https://docs.aws.amazon.com/marketplace/latest/controllerguide/seller-guide.html)
- [Packer AWS Builder](https://www.packer.io/plugins/builders/amazon)
- [docs/CLOUD-MARKETPLACE.md](../../docs/CLOUD-MARKETPLACE.md) (5-marketplace strategy)
- [ROADMAP-post-1.0.md §3](../../ROADMAP-post-1.0.md#3-cloud-marketplace-images-w27-w32)
