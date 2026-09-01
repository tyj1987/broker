// broker/signing/wechat-pay.js — V4 微信支付 V3 签名
// Reference: https://pay.weixin.qq.com/wiki/doc/apiv3/wechatpay/wechatpay3_0.shtml
//
// Required headers:
//   Authorization: WECHATPAY2-SHA256-RSA2048 mchid="...",nonce_str="...",timestamp="...",serial_no="...",signature="..."
//   Content-Type: application/json
//   Accept: application/json
//   User-Agent: broker/4.0

import { createSign } from 'node:crypto';
import { randomBytes } from 'node:crypto';

function buildMessage({ method, path, body, timestamp, nonce_str }) {
  return `${method}\n${path}\n${timestamp}\n${nonce_str}\n${body || ''}\n`;
}

/**
 * @param {{
 *   method: string,
 *   path: string,                  // e.g. '/v3/pay/transactions/jsapi'
 *   body?: string,
 *   timestamp?: number,            // unix seconds
 *   nonce_str?: string,
 *   secret: { mch_id: string, cert_serial: string, private_key: string },
 * }} args
 * @returns {object} headers
 */
export function signWechatPayV3(args) {
  const ts = args.timestamp || Math.floor(Date.now() / 1000);
  const nonce = args.nonce_str || randomBytes(16).toString('hex');
  const body = args.body || '';
  const msg = buildMessage({ method: args.method.toUpperCase(), path: args.path, body, timestamp: ts, nonce_str: nonce });

  const signer = createSign('RSA-SHA256');
  signer.update(msg, 'utf8');
  const signature = signer.sign(args.secret.private_key, 'base64');

  return {
    'Authorization': `WECHATPAY2-SHA256-RSA2048 mchid="${args.secret.mch_id}",nonce_str="${nonce}",timestamp="${ts}",serial_no="${args.secret.cert_serial}",signature="${signature}"`,
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'User-Agent': 'secret-broker/4.0',
  };
}

export async function signWechatPayV3Async(args) {
  return signWechatPayV3(args);
}

export default { signWechatPayV3, signWechatPayV3Async };
