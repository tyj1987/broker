// broker/version.js — single source of truth for broker version strings

export const BROKER_VERSION = '4.1.5';
export const BROKER_NAME = 'secret-broker';

/** Header value for X-Broker-Version */
export function versionHeader() {
  return BROKER_VERSION;
}
