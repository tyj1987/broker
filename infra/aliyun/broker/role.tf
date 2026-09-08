# infra/aliyun/broker/role.tf
# RAM Role + Policy + attachment for the broker ECS instance.
# The broker fetches STS tokens from IMDS at request time, never stores AKs on disk.
#
# 最小权限：只给 broker 真正需要的 API 权限

# ============================
# RAM Role（ECS instance 信任）
# ============================

resource "alicloud_ram_role" "broker" {
  role_name   = "secret-broker-instance-role"
  description = "Role attached to the secret-broker ECS instance. Allows broker to call Aliyun APIs via STS."
  force       = true

  assume_role_policy_document = <<-EOT
    {
      "Statement": [
        {
          "Action": "sts:AssumeRole",
          "Effect": "Allow",
          "Principal": {
            "Service": [
              "ecs.aliyuncs.com"
            ]
          }
        }
      ],
      "Version": "1"
    }
  EOT
}

# ============================
# Policy：broker 能调什么
# ============================

resource "alicloud_ram_policy" "broker" {
  policy_name = "secret-broker-policy"
  description = "Read-only discovery permissions for the secret-broker instance. Mutations require separate operation roles."
  force       = true

  policy_document = jsonencode({
    Version = "1"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sts:AssumeRole"]
      Resource = var.operation_role_arns
    }]
  })
}

# ============================
# 绑定 policy 到 role
# ============================

resource "alicloud_ram_role_policy_attachment" "broker" {
  role_name   = alicloud_ram_role.broker.role_name
  policy_name = alicloud_ram_policy.broker.policy_name
  policy_type = "Custom"
}

# ============================
# 绑定 RAM role 到 ECS 实例
# 新版 provider 用 ecs_ram_role_attachment
# ============================

resource "alicloud_ecs_ram_role_attachment" "broker" {
  ram_role_name = alicloud_ram_role.broker.role_name
  instance_id   = alicloud_instance.broker.id
}
