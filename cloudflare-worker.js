/**
 * 買い物チェックリスト — Cloudflare Worker
 *
 * 必要な設定:
 *   KV 名前空間  : PUSH_SUBS  (binding name) ← これだけ
 *   ※ VAPIDキーはこのコードに直接埋め込み済み。Cloudflareの変数・Secret設定は不要。
 *
 * エンドポイント:
 *   GET  /key        — VAPID公開鍵を返す（アプリが取得して購読に使う）
 *   POST /subscribe  — プッシュ購読を登録
 *   POST /notify     — ルーム内の他端末に通知を送信
 */

// ── VAPIDキー（公開鍵と秘密鍵は同一ペア。手作業コピー不要・不一致なし） ──
const VAPID_PUBLIC_KEY = "BEujRUBxUzOeWUuya7d3HSmpTOfbchabRGdeB-vQiSSdCwvsRI5Y6WQTD6e6iaqyT7B1505QZBw_GfhmpoCu3Ws";
const VAPID_JWK = {
  kty: "EC", crv: "P-256",
  x: "S6NFQHFTM55ZS7Jrt3cdKalM59tyFptEZ14H69CJJJ0",
  y: "CwvsRI5Y6WQTD6e6iaqyT7B1505QZBw_GfhmpoCu3Ws",
  d: "fhar1FMFep7L5WDABAyC4McUyI3WH5SRBZXXR5F9ZXk",
};
const VAPID_SUB = "mailto:taiga1216270@icloud.com";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });

    if (request.method === 'GET' && url.pathname === '/key') {
      return new Response(VAPID_PUBLIC_KEY, { headers: { ...cors, 'Content-Type': 'text/plain' } });
    }

    if (request.method === 'POST' && url.pathname === '/subscribe') {
      const { roomId, deviceId, subscription } = await request.json();
      if (!roomId || !deviceId || !subscription)
        return new Response('missing', { status: 400, headers: cors });
      await env.PUSH_SUBS.put(
        `${roomId}:${deviceId}`,
        JSON.stringify(subscription),
        { expirationTtl: 30 * 24 * 60 * 60 }
      );
      return new Response('ok', { headers: cors });
    }

    if (request.method === 'POST' && url.pathname === '/notify') {
      const { roomId, senderDeviceId, payload } = await request.json();
      if (!roomId || !payload)
        return new Response('missing', { status: 400, headers: cors });

      const prefix = `${roomId}:`;
      const list = await env.PUSH_SUBS.list({ prefix });

      let total = 0, sent = 0, failed = 0, lastErr = '';
      await Promise.all(list.keys.map(async ({ name }) => {
        if (name.slice(prefix.length) === senderDeviceId) return;
        const raw = await env.PUSH_SUBS.get(name);
        if (!raw) return;
        total++;
        try {
          await sendWebPush(JSON.parse(raw), payload, VAPID_JWK, VAPID_PUBLIC_KEY);
          sent++;
        } catch (e) {
          failed++;
          lastErr = String(e.status || e.message || e);
          if (e.status === 410 || e.status === 404) await env.PUSH_SUBS.delete(name);
        }
      }));

      return new Response(
        JSON.stringify({ total, sent, failed, lastErr }),
        { headers: { ...cors, 'Content-Type': 'application/json' } }
      );
    }

    return new Response('Not Found', { status: 404, headers: cors });
  }
};

/* ── Web Push (RFC 8291 aes128gcm) ── */

async function sendWebPush(sub, payloadStr, vapidJwk, vapidPubKey) {
  const clientPub = b64uDec(sub.keys.p256dh);
  const authSecret = b64uDec(sub.keys.auth);
  const payload    = new TextEncoder().encode(payloadStr);

  // Server ECDH keypair
  const serverKP = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
  );
  const serverPubRaw = new Uint8Array(
    await crypto.subtle.exportKey('raw', serverKP.publicKey)
  );

  // Shared secret
  const clientKey = await crypto.subtle.importKey(
    'raw', clientPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  const sharedSecret = new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'ECDH', public: clientKey }, serverKP.privateKey, 256)
  );

  // RFC 8291: IKM = HKDF(auth, sharedSecret, "WebPush: info\x00" || clientPub || serverPub, 32)
  const prk1 = await hkdfExtract(authSecret, sharedSecret);
  const info1 = concat(enc('WebPush: info\x00'), clientPub, serverPubRaw);
  const ikm   = await hkdfExpand(prk1, info1, 32);

  // RFC 8188: salt → CEK + nonce
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk2 = await hkdfExtract(salt, ikm);
  const cek   = await hkdfExpand(prk2, enc('Content-Encoding: aes128gcm\x00'), 16);
  const nonce = await hkdfExpand(prk2, enc('Content-Encoding: nonce\x00'), 12);

  // Encrypt: payload || 0x02  (final record delimiter)
  const plain = concat(payload, new Uint8Array([0x02]));
  const aesKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const cipher = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, plain)
  );

  // aes128gcm header: salt(16) + rs(4) + keylen(1) + serverPub(65) + cipher
  const rs = new Uint8Array(4); new DataView(rs.buffer).setUint32(0, 4096, false);
  const body = concat(salt, rs, new Uint8Array([serverPubRaw.length]), serverPubRaw, cipher);

  // VAPID JWT
  const aud   = new URL(sub.endpoint).origin;
  const token = await vapidJwt(vapidJwk, aud);

  const res = await fetch(sub.endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Encoding': 'aes128gcm',
      'TTL': '86400',
      'Urgency': 'high',
      'Authorization': `vapid t=${token}, k=${vapidPubKey}`,
    },
    body,
  });

  if (!res.ok && res.status !== 201) {
    const e = new Error(`push ${res.status}`);
    e.status = res.status;
    throw e;
  }
}

/* ── HKDF helpers ── */

async function hkdfExtract(salt, ikm) {
  const key = await crypto.subtle.importKey('raw', salt, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, ikm));
}

async function hkdfExpand(prk, info, len) {
  const out = new Uint8Array(len);
  let t = new Uint8Array(0), pos = 0, ctr = 1;
  while (pos < len) {
    const data = concat(t, info, new Uint8Array([ctr++]));
    const key  = await crypto.subtle.importKey('raw', prk, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    t = new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
    out.set(t.subarray(0, Math.min(len - pos, t.length)), pos);
    pos += t.length;
  }
  return out;
}

/* ── VAPID JWT (ES256) ── */

async function vapidJwt(jwk, audience) {
  const hdr = b64uEnc(new TextEncoder().encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const pay = b64uEnc(new TextEncoder().encode(JSON.stringify({
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 43200,
    sub: VAPID_SUB,
  })));
  const unsigned = `${hdr}.${pay}`;
  const key = await crypto.subtle.importKey(
    'jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(unsigned)
  );
  return `${unsigned}.${b64uEnc(new Uint8Array(sig))}`;
}

/* ── utils ── */

function enc(str) { return new TextEncoder().encode(str); }

function concat(...arrays) {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const a of arrays) { out.set(a, pos); pos += a.length; }
  return out;
}

function b64uEnc(buf) {
  let s = '';
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function b64uDec(str) {
  const pad = '='.repeat((4 - str.length % 4) % 4);
  return Uint8Array.from(atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad), c => c.charCodeAt(0));
}
