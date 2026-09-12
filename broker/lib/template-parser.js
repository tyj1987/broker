// broker/lib/template-parser.js — V4 SDK Sync parser
// Parse OpenAPI specs and provider docs into V4 service template format.
// Uses the `yaml` package (already in broker/package.json) for full YAML 1.2
// support including deep nesting and sequences.

import { parse as yamlParse } from 'yaml';

function tryParse(text) {
  // First try JSON (strict)
  try { return JSON.parse(text); }
  catch (_e) { /* fall through to YAML */ }
  // Then YAML
  const doc = yamlParse(text, { strict: true });
  if (doc === null || doc === undefined) {
    throw new Error('empty document');
  }
  return doc;
}

/**
 * Parse an OpenAPI 3.x spec (JSON or YAML) into a V4 service template.
 * Best-effort: returns the most useful fields it can find; downstream code
 * (admin UI) is expected to review and complete.
 *
 * @param {string} specText   raw OpenAPI spec text
 * @returns {{
 *   upstream: string|null,
 *   auth_type: string,
 *   inject_headers: object,
 *   default_secret_type: string|null,
 *   default_secret_field: string|null,
 *   default_actions: Array<{label:string,method:string,path:string,query?:object}>,
 *   template_version: string|null,
 *   source: 'openapi',
 * }}
 */
export function parseOpenAPI(specText) {
  if (!specText || typeof specText !== 'string') {
    throw new Error('parseOpenAPI: specText must be a non-empty string');
  }
  let spec;
  try { spec = tryParse(specText); }
  catch (e) {
    const error = new Error('openapi_spec_invalid');
    error.cause = e;
    throw error;
  }
  if (!spec || typeof spec !== 'object') {
    throw new Error('parseOpenAPI: spec root is not an object');
  }

  // 1. upstream
  const upstream = (spec.servers && spec.servers[0] && spec.servers[0].url) || null;

  // 2. auth_type — scan securitySchemes
  const schemes = (spec.components && spec.components.securitySchemes) || {};
  let auth_type = 'bearer';  // default
  let default_secret_field = 'value';
  const inject_headers = {};

  for (const [name, s] of Object.entries(schemes)) {
    if (!s || typeof s !== 'object') continue;
    const t = (s.type || '').toLowerCase();
    if (t === 'http' && (s.scheme || '').toLowerCase() === 'bearer') {
      auth_type = 'bearer';
      default_secret_field = 'token';
    } else if (t === 'http' && (s.scheme || '').toLowerCase() === 'basic') {
      auth_type = 'basic';
    } else if (t === 'apikey' && (s.in || '').toLowerCase() === 'header') {
      auth_type = 'header';
      inject_headers[s.name] = `<${name}>`;
      default_secret_field = 'value';
    } else if (t === 'oauth2' || t === 'openidconnect') {
      auth_type = 'bearer';
    }
  }

  // 3. default_actions — pick 3 safe GET paths
  const default_actions = [];
  const paths = spec.paths || {};
  for (const [path, ops] of Object.entries(paths)) {
    if (default_actions.length >= 3) break;
    if (!ops || typeof ops !== 'object') continue;
    const get = ops.get;
    if (!get || typeof get !== 'object') continue;
    // Skip paths with required params in path template
    if (/\{[^}]+\}/.test(path)) continue;
    default_actions.push({
      label: get.summary || `GET ${path}`,
      method: 'GET',
      path,
    });
  }

  return {
    upstream,
    auth_type,
    inject_headers,
    default_secret_type: null,  // user picks
    default_secret_field,
    default_actions,
    template_version: (spec.info && spec.info.version) || null,
    source: 'openapi',
  };
}

/**
 * Extract a basic auth shape from a docs page (e.g. curl example block).
 * Heuristic — looks for "Authorization: Bearer XXX" or "Basic XXX" patterns.
 *
 * @param {string} html
 * @returns {{auth_type: string, sample: string|null}}
 */
export function extractAuthFromDocs(html) {
  if (!html) return { auth_type: 'bearer', sample: null };
  const bearer = /Authorization:\s*Bearer\s+[^\s<"]+/i.exec(html);
  if (bearer) {
    return { auth_type: 'bearer', sample: 'Authorization: Bearer <redacted>' };
  }
  const basic = /Authorization:\s*Basic\s+[A-Za-z0-9+/=]+/i.exec(html);
  if (basic) {
    return { auth_type: 'basic', sample: 'Authorization: Basic <redacted>' };
  }
  const apikey = /x-api-key:\s*[^\s<"]+/i.exec(html);
  if (apikey) {
    return { auth_type: 'header', sample: 'x-api-key: <redacted>' };
  }
  return { auth_type: 'bearer', sample: null };
}

/**
 * Extract the upstream host from a docs page (looks for example curl URLs).
 *
 * @param {string} html
 * @returns {string|null}
 */
export function extractUpstreamFromDocs(html) {
  if (!html) return null;
  // Prefer "https://api.xxx.com" or "https://xxx.com/api"
  const m = /https:\/\/(api\.[a-z0-9.-]+|[\w.-]+\.amazonaws\.com|[\w.-]+\.googleapis\.com|[\w.-]+\.aliyuncs\.com|[\w.-]+\.tencentcloudapi\.com)/i.exec(html);
  if (m) return 'https://' + m[1];
  return null;
}
