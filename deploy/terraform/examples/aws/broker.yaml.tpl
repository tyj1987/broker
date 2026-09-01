# AWS example broker.yaml
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
workload_identity:
  enabled: true
  providers:
    aws:
      cluster_oidc_issuer: "https://oidc.eks.${region}.amazonaws.com/id/EXAMPLE"
      role_arns: ["arn:aws:iam::123456789012:role/broker-app-role"]
alerting:
  enabled: true
  default_channel: slack
  channels:
    - type: slack_webhook
      url: "https://hooks.slack.com/services/REDACTED/REDACTED/REDACTED"
      events: ["secret.expired", "secret.warn"]
