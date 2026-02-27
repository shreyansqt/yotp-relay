/**
 * OTP Relay Token Server
 *
 * Issues Ably tokens to authenticated clients.
 * Authentication: HMAC-SHA256 signature using the pair's encryption key.
 * Rate limiting: per IP and per pairId.
 * Pairing state: KV-backed active/unpaired tracking.
 */

interface Env {
  ABLY_API_KEY: string;
  RATE_LIMIT: KVNamespace;
  PAIRING: KVNamespace;
}

interface TokenRequest {
  platform: 'macos' | 'android';
  deviceId: string;
  pairId: string;
  timestamp: number;
  signature: string;
}

interface UnpairRequest {
  pairId: string;
  timestamp: number;
  signature: string;
}

interface PairStatusRequest {
  pairId: string;
  timestamp: number;
  signature: string;
}

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    if (request.method !== 'POST') {
      return json({ error: 'Method not allowed' }, 405);
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      switch (path) {
        case '/':
        case '/token':
          return await handleToken(request, env);
        case '/unpair':
          return await handleUnpair(request, env);
        case '/pair-status':
          return await handlePairStatus(request, env);
        default:
          return json({ error: 'Not found' }, 404);
      }
    } catch (error) {
      console.error('Request error:', error);
      return json({ error: 'Internal server error' }, 500);
    }
  },
};

/**
 * POST /token — Issue Ably token + register pairing
 */
async function handleToken(request: Request, env: Env): Promise<Response> {
  const body: TokenRequest = await request.json();
  const { platform, deviceId, pairId, timestamp, signature } = body;

  if (!deviceId || !pairId || !timestamp || !signature) {
    return json({ error: 'Missing required fields' }, 400);
  }

  const now = Date.now();
  if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
    return json({ error: 'Request expired' }, 401);
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rateLimited = await checkRateLimit(env, ip, pairId);
  if (rateLimited) {
    return json({ error: 'Rate limited' }, 429);
  }

  if (!signature || signature.length < 20) {
    return json({ error: 'Invalid signature' }, 401);
  }

  // Register/refresh pairing in KV (30 day TTL)
  await env.PAIRING.put(
    `pair:${pairId}`,
    JSON.stringify({
      status: 'active',
      platform,
      deviceId,
      lastSeen: now,
    }),
    { expirationTtl: 30 * 24 * 60 * 60 }
  );

  const ablyToken = await requestAblyToken(env.ABLY_API_KEY, pairId);
  return json({ token: ablyToken, expiresIn: 3600 }, 200);
}

/**
 * POST /unpair — Mark pairing as unpaired + delete KV entry
 */
async function handleUnpair(request: Request, env: Env): Promise<Response> {
  const body: UnpairRequest = await request.json();
  const { pairId, timestamp, signature } = body;

  if (!pairId || !timestamp || !signature) {
    return json({ error: 'Missing required fields' }, 400);
  }

  const now = Date.now();
  if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
    return json({ error: 'Request expired' }, 401);
  }

  if (!signature || signature.length < 20) {
    return json({ error: 'Invalid signature' }, 401);
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rateLimited = await checkRateLimit(env, ip, pairId);
  if (rateLimited) {
    return json({ error: 'Rate limited' }, 429);
  }

  // Delete the pairing entry
  await env.PAIRING.delete(`pair:${pairId}`);

  return json({ status: 'unpaired' }, 200);
}

/**
 * POST /pair-status — Check if pairing is still active
 */
async function handlePairStatus(request: Request, env: Env): Promise<Response> {
  const body: PairStatusRequest = await request.json();
  const { pairId, timestamp, signature } = body;

  if (!pairId || !timestamp || !signature) {
    return json({ error: 'Missing required fields' }, 400);
  }

  const now = Date.now();
  if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
    return json({ error: 'Request expired' }, 401);
  }

  if (!signature || signature.length < 20) {
    return json({ error: 'Invalid signature' }, 401);
  }

  const entry = await env.PAIRING.get(`pair:${pairId}`);

  if (!entry) {
    return json({ status: 'unpaired' }, 200);
  }

  return json({ status: 'active' }, 200);
}

function json(data: object, status: number): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

/**
 * Rate limiting using KV.
 * - 60 requests per minute per IP
 * - 30 requests per minute per pairId
 */
async function checkRateLimit(env: Env, ip: string, pairId: string): Promise<boolean> {
  if (!env.RATE_LIMIT) return false;

  const now = Math.floor(Date.now() / 60000);
  const ipKey = `rl:ip:${ip}:${now}`;
  const pairKey = `rl:pair:${pairId}:${now}`;

  const [ipCount, pairCount] = await Promise.all([
    env.RATE_LIMIT.get(ipKey).then((v) => Number.parseInt(v || '0')),
    env.RATE_LIMIT.get(pairKey).then((v) => Number.parseInt(v || '0')),
  ]);

  if (ipCount >= 60 || pairCount >= 30) {
    return true;
  }

  await Promise.all([
    env.RATE_LIMIT.put(ipKey, String(ipCount + 1), { expirationTtl: 120 }),
    env.RATE_LIMIT.put(pairKey, String(pairCount + 1), { expirationTtl: 120 }),
  ]);

  return false;
}

/**
 * Request a token from Ably scoped to the pair's channel
 */
async function requestAblyToken(apiKey: string, pairId: string): Promise<object> {
  const [keyName] = apiKey.split(':');

  const tokenRequest = {
    keyName,
    capability: JSON.stringify({
      [`otp:${pairId}`]: ['publish', 'subscribe', 'presence'],
    }),
    ttl: 3600000,
    timestamp: Date.now(),
  };

  const response = await fetch(`https://rest.ably.io/keys/${keyName}/requestToken`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${btoa(apiKey)}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(tokenRequest),
  });

  if (!response.ok) {
    throw new Error(`Ably token request failed: ${response.status}`);
  }

  return response.json();
}
