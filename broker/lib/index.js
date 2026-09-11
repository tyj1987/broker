// broker/lib/index.js — public surface for extracted helpers

export { sopsDecrypt, sopsEncryptAtomic } from './sops.js';
export { send, readBody, jsonError } from './http.js';
export { aliyunRpcVersion, mergeAliyunQuery, ALIYUN_RPC_VERSION_BY_HOST } from './aliyun-rpc.js';
export { resolveHostnameDoH, dohConnect, shouldSkipDoH, clearDoHCache } from './doh.js';
export { defaultServiceTest, matchServiceTemplate, describeUpstreamStatus } from './service-test.js';
export { relayConfig, shouldRelay, applyRelay, RELAY_SECRET_HEADER } from './outbound-relay.js';
export { defaultHealthBind, startLocalHealthServer, describeHealthBind } from './local-health.js';
export { applyAdminVisibility, isAdminIdentity } from './admin-visibility.js';
export { buildZip, computeCrc32 } from './zip.js';
export { createAudit } from './audit.js';
export { parseRateLimit, createRateLimiter } from './rate-limit.js';
export { createPinnedHttpsRequest, PinnedRequestError, PINNED_HTTPS_LIMITS } from './pinned-https-request.js';
export { isIpAllowed, normalizeIp, matchIpRule } from './ip-allowlist.js';
// V4 任务 1 配套: 凭据零接触安全基础
export { redact, redactDeep, redactJson, hasLikelySecret, SUPPORTED_PATTERNS } from './redact.js';
// V4 任务 2: 风险评分 + MFA 决策
export { calcRiskScore, SENSITIVE_ACTIONS } from './risk-score.js';
export { decideMfaRequirement, checkMfaProgress, loadMfaPolicy, DEFAULT_POLICY as DEFAULT_MFA_POLICY } from './mfa-policy.js';
// V4 任务 1 配套: 可插拔 SMS provider
export { SmsRegistry, stubSmsProvider, makeWebhookSmsProvider, generateSmsCode } from './sms-provider.js';
export {
  createSessionStore,
  SESSION_TTL_MS,
  SESSION_HEADER,
  MAX_LOGIN_FAILS,
  LOGIN_LOCKOUT_MS,
} from './session.js';
export {
  inc,
  observeMs,
  snapshot,
  prometheusText,
  timedRequest,
  getCounter,
} from './metrics.js';
export { log } from './log.js';
export {
  parseTraceparent,
  continueOrCreateTrace,
  outboundTraceHeaders,
  resolveRequestId,
  newTraceId,
  newSpanId,
} from './trace.js';
export {
  getRequestContext,
  getRequestId,
  getTraceparent,
  runWithRequestContext,
  setResponseTraceHeaders,
} from './request-context.js';
export {
  shouldSampleAudit,
  withAuditSampling,
  pruneAuditFiles,
  auditPolicyFromEnv,
} from './audit-policy.js';
export {
  installGracefulShutdown,
  rejectIfShuttingDown,
} from './shutdown.js';
// V4.1.1: HTTP security headers (CSP, HSTS, X-Frame-Options, ...)
export {
  securityHeaders,
  applySecurityHeaders,
  snapshotHeaders,
} from './security-headers.js';
// V4.1.1: Identity resolver (mTLS / session / API key) — extracted from server.js
export { createIdentityResolver } from './mtls.js';
// V4.1.1: Async audit helpers (high-throughput deployments)
export { createAuditAsync, AsyncAuditWriteError } from './audit-async.js';
// V4.1.1: Audit hash chain for tamper-evidence
export {
  computeHash,
  buildAuditEvent,
  sealEvent,
  verifyChain,
  verifyAuditDir,
  createChainWriter,
  loadAuditChainProofSync,
  loadAuditChainStateSync,
  GENESIS_HASH,
} from './audit-hash-chain.js';
export {
  ANCHOR_PURPOSE,
  ANCHOR_VERSION,
  SIGNATURE_ALGORITHMS,
  AuditAnchorError,
  attachAuditAnchorSignature,
  createAuditAnchorRequest,
  createAuditAnchorSigningInput,
  verifyAuditAnchorEnvelope,
} from './audit-anchor.js';
export {
  LOCAL_AUDIT_ANCHOR_SIGNER_CONTRACT,
  LocalAuditAnchorSignerError,
  createLocalAuditAnchorSignerClient,
} from './local-audit-anchor-signer-client.js';
export {
  AuditAnchorExporterError,
  createAuditAnchorExporter,
} from './audit-anchor-exporter.js';
export {
  validateBrokerConfig,
  requireValidBrokerConfig,
  preflightPaths,
  formatValidationReport,
} from './config-validate.js';
export {
  buildBackupManifest,
  redactConfigForExport,
  writeBackupManifest,
} from './backup.js';
export {
  probeTcp,
  probeHttp,
  runProbes,
  probesFromConfig,
} from './probes.js';
// V4.1 任务 11: Workload Identity (K8s/ECS/GKE OIDC -> STS 临时凭证)
export {
  getCredentials as getWorkloadCredentials,
  invalidateCache as invalidateWorkloadCache,
  listCache as listWorkloadCache,
  validateConfig as validateWorkloadConfig,
  PROVIDER_NAMES as WORKLOAD_PROVIDER_NAMES,
  REFRESH_SKEW_MS as WORKLOAD_REFRESH_SKEW_MS,
  defaultHttpClient as defaultWorkloadHttpClient,
} from './workload-identity.js';
// V4.1 任务 12: SSH Proxy (broker 持私钥,AI 不接触)
export {
  sshExec,
  sshTunnel,
  stopTunnel,
  listTunnels,
  parseSshTarget,
  validateCommand,
} from '../ssh-proxy.js';
// V4.1 任务 13: WebSocket 实时事件流
export {
  attachWebSocket,
  broadcastEvent as broadcastWsEvent,
  subscribeClient as wsSubscribeClient,
  unsubscribeClient as wsUnsubscribeClient,
  updateClientFilter as wsUpdateClientFilter,
  getStats as wsGetStats,
  listSubscribers as wsListSubscribers,
  HEARTBEAT_INTERVAL_MS as WS_HEARTBEAT_MS,
  CLIENT_TIMEOUT_MS as WS_CLIENT_TIMEOUT_MS,
} from './ws.js';
