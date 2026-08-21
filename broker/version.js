// broker/version.js — single source of truth for broker version strings
// Import this from server.js, MCP, CLI, and tests instead of hardcoding.

export const BROKER_VERSION = '3.4.0';
export const BROKER_NAME = 'secret-broker';

/** Header value for X-Broker-Version */
export function versionHeader() {
  return BROKER_VERSION;
}
