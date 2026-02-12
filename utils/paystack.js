const crypto = require('crypto');

const REQUEST_TIMEOUT_MS = Number(process.env.PAYSTACK_REQUEST_TIMEOUT_MS) > 0
  ? Number(process.env.PAYSTACK_REQUEST_TIMEOUT_MS)
  : 10_000;

const getBaseUrl = () => {
  const raw = String(process.env.PAYSTACK_BASE_URL || '').trim();
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('Paystack configuration error');
  }
  if (url.protocol !== 'https:') {
    throw new Error('Paystack configuration error');
  }
  return url.toString().replace(/\/+$/, '');
};

const getSecretKey = () => {
  const key = String(process.env.PAYSTACK_SECRET_KEY || '').trim();
  if (!key) {
    throw new Error('Paystack configuration error');
  }
  return key;
};

const toKobo = (amount) => {
  const num = Number(amount);
  if (!Number.isFinite(num) || num <= 0) {
    throw new Error('Invalid amount');
  }
  return Math.round(num * 100);
};

const verifyWebhookSignature = (rawBody, signature) => {
  const webhookSecret = process.env.PAYSTACK_WEBHOOK_SECRET;
  if (!webhookSecret || !rawBody || !signature) return false;
  const trimmedSignature = String(signature).trim().toLowerCase();
  if (!/^[a-f0-9]{128}$/.test(trimmedSignature)) return false;
  const hash = crypto
    .createHmac('sha512', webhookSecret)
    .update(rawBody, 'utf8')
    .digest('hex');
  const expected = Buffer.from(hash, 'hex');
  const provided = Buffer.from(trimmedSignature, 'hex');
  if (expected.length !== provided.length) return false;
  return crypto.timingSafeEqual(expected, provided);
};

const parsePayloadSafely = async (response) => {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
};

const paystackRequest = async ({ path, method, body }) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(`${getBaseUrl()}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${getSecretKey()}`,
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });

    const payload = await parsePayloadSafely(response);
    if (!response.ok || !payload || payload.status !== true || !payload.data) {
      throw new Error('Paystack request failed');
    }
    return payload.data;
  } catch (err) {
    if (err && err.name === 'AbortError') {
      throw new Error('Paystack request timed out');
    }
    throw new Error('Paystack request failed');
  } finally {
    clearTimeout(timeout);
  }
};

const initializeTransaction = async ({ email, amount, reference, callbackUrl, metadata }) => {
  return paystackRequest({
    path: '/transaction/initialize',
    method: 'POST',
    body: {
      email,
      amount: toKobo(amount),
      reference,
      currency: 'NGN',
      callback_url: callbackUrl || undefined,
      metadata: metadata || undefined,
    },
  });
};

const verifyTransaction = async (reference) => {
  return paystackRequest({
    path: `/transaction/verify/${encodeURIComponent(reference)}`,
    method: 'GET',
  });
};

const chargeAuthorization = async ({ email, amount, authorizationCode, reference, metadata }) => {
  return paystackRequest({
    path: '/transaction/charge_authorization',
    method: 'POST',
    body: {
      email,
      amount: toKobo(amount),
      authorization_code: authorizationCode,
      reference,
      currency: 'NGN',
      metadata: metadata || undefined,
    },
  });
};

module.exports = {
  initializeTransaction,
  verifyTransaction,
  chargeAuthorization,
  verifyWebhookSignature,
};
