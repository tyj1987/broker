# Secret Broker — Grafana dashboard & Prometheus alerts

Pre-built Grafana dashboard JSON + Prometheus alert rules for
[Secret Broker V4](https://github.com/tyj1987/broker).

## Install

### Option A: Grafana sidecar import

1. Open Grafana → Dashboards → Import
2. Upload `dashboard.json`
3. Select Prometheus + Loki datasources
4. Done.

### Option B: Kubernetes ConfigMap

```bash
kubectl create configmap broker-dashboard \
  --from-file=dashboard.json \
  --namespace monitoring

# Then add as Grafana sidecar datasource
```

### Option C: Helm values (Grafana chart)

```yaml
grafana:
  sidecar:
    dashboards:
      enabled: true
      searchNamespace: monitoring
  dashboardProviders:
    dashboardproviders.yaml:
      apiVersion: 1
      providers:
        - name: default
          orgId: 1
          folder: ''
          type: file
          disableDeletion: false
          editable: true
          options:
            path: /var/lib/grafana/dashboards
```

Mount the dashboard JSON via ConfigMap.

## Prometheus alerts

```bash
# PrometheusRule CRD (requires prometheus-operator)
kubectl apply -f alerts.yml
```

Or add to your `prometheus.yml`:

```yaml
rule_files:
  - /etc/prometheus/rules/broker-alerts.yml
```

## Metrics exposed by the broker

| Metric | Type | Description |
|--------|------|-------------|
| `broker_info` | gauge | Build / version info |
| `broker_up` | gauge | Per-instance health (1=up, 0=down) |
| `broker_mtls_clients_total` | gauge | Connected mTLS clients |
| `broker_http_requests_total{route,method,status}` | counter | HTTP request count |
| `broker_http_request_duration_seconds_bucket` | histogram | Request latency |
| `broker_secrets_resolved_total` | counter | Secret resolutions |
| `broker_secrets_resolve_errors_total` | counter | Resolution errors |
| `broker_proxy_requests_total{service}` | counter | Proxy requests |
| `broker_proxy_request_errors_total{service}` | counter | Proxy errors |
| `broker_workload_identity_assume_total{provider}` | counter | STS exchanges |
| `broker_workload_identity_assume_errors_total{provider}` | counter | STS errors |
| `broker_workload_identity_cache_entries{provider}` | gauge | Cache size |
| `broker_ws_subscribers` | gauge | Active WS subscribers |
| `broker_ws_broadcasts_total` | counter | Events broadcast |
| `broker_ssh_operations_total{action,status}` | counter | SSH proxy ops |
| `broker_ssh_tunnels_active` | gauge | Open tunnels |
| `broker_rotation_state_count{state}` | gauge | Secrets by rotation state |
| `broker_rotation_failures_total` | counter | Auto-rotate failures |
| `broker_auth_failures_total{client_cn}` | counter | Auth failures (brute force detect) |
| `broker_mfa_failures_total{client_cn}` | counter | MFA failures |
| `broker_api_key_rate_limit_hits_total{client_cn}` | counter | Rate limit hits |
| `broker_redaction_misses_total` | counter | Patterns the redact engine missed (should be 0) |
| `broker_risk_score` | histogram | Risk score distribution |
| `process_cpu_seconds_total` | counter | Standard process metric |
| `process_resident_memory_bytes` | gauge | Standard process metric |

## Dashboard panels

1. **Top row** — Version, uptime, mTLS clients, healthy/unhealthy, rate-limit hits, risk score
2. **Secret Resolutions / sec** — resolved vs errors
3. **Proxy Requests / sec (by service)** — multi-series
4. **HTTP Latency p50/p95/p99** — per route
5. **Workload Identity STS Cache** — by provider
6. **Workload Identity Assumes / sec** — by provider
7. **WebSocket Subscribers** — current + broadcast rate
8. **SSH Proxy Operations / sec** — by action
9. **Auto-Rotate Status** — by state (fresh/warn/expired)
10. **Top Clients by Volume** (1h) — table
11. **Top Services by Errors** (1h) — table
12. **Recent Audit Events (no secret values)** — Loki logs panel

## Notes

- The dashboard uses templating `DS_PROMETHEUS` and `DS_LOKI` so it auto-binds
  to any datasource of those types in your Grafana.
- The audit logs panel is filtered to `|= "audit"` and applies `line_format` to
  show only the message field. Secret values are redacted by the broker's
  audit logger before they hit Loki, so no cleartext credentials appear in
  the dashboard.

## License

MIT
