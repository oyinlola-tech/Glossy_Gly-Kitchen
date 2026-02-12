const crypto = require('crypto');

const getBaseUrl = () => process.env.PAYSTACK_BASE_URL;
const getSecretKey = () => process.env.PAYSTACK_SECRET_KEY;

const toKobo = (amount) => {
  const num = Number(amount);
  if (!Number.isFinite(num) || num <= 0) {
    throw new Error('Invalid amount');
  }
  return Math.round(num * 100);
};

const verifyWebhookSignature = (rawBody, signature) => {
  if (!rawBody || !signature) return false;
  const hash = crypto
    .createHmac('sha512', process.env.PAYSTACK_WEBHOOK_SECRET)
    .update(rawBody, 'utf8')
    .digest('hex');
  const expected = Buffer.from(hash, 'hex');
  let provided;
  try {
    provided = Buffer.from(String(signature).trim(), 'hex');
  } catch {
    return false;
  }
  if (expected.length !== provided.length) return false;
  return crypto.timingSafeEqual(expected, provided);
};

const initializeTransaction = async ({ email, amount, reference, callbackUrl, metadata }) => {
  const response = await fetch(`${getBaseUrl()}/transaction/initialize`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${getSecretKey()}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      email,
      amount: toKobo(amount),
      reference,
      currency: 'NGN',
      callback_url: callbackUrl || undefined,
      metadata: metadata || undefined,
    }),
  });

  const payload = await response.json();
  if (!response.ok || payload.status !== true) {
    const message = payload && payload.message ? payload.message : 'Paystack initialize failed';
    throw new Error(message);
  }

  return payload.data;
};

const verifyTransaction = async (reference) => {
  const response = await fetch(`${getBaseUrl()}/transaction/verify/${encodeURIComponent(reference)}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${getSecretKey()}`,
    },
  });

  const payload = await response.json();
  if (!response.ok || payload.status !== true) {
    const message = payload && payload.message ? payload.message : 'Paystack verify failed';
    throw new Error(message);
  }

  return payload.data;
};

const chargeAuthorization = async ({ email, amount, authorizationCode, reference, metadata }) => {
  const response = await fetch(`${getBaseUrl()}/transaction/charge_authorization`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${getSecretKey()}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      email,
      amount: toKobo(amount),
      authorization_code: authorizationCode,
      reference,
      currency: 'NGN',
      metadata: metadata || undefined,
    }),
  });

  const payload = await response.json();
  if (!response.ok || payload.status !== true) {
    const message = payload && payload.message ? payload.message : 'Paystack charge authorization failed';
    throw new Error(message);
  }

  return payload.data;
};

module.exports = {
  initializeTransaction,
  verifyTransaction,
  chargeAuthorization,
  verifyWebhookSignature,
};
