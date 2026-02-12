const crypto = require('crypto');

const attempts = new Map();
const MAX_KEYS = 10_000;

const WINDOW_MS = Number(process.env.OTP_ATTEMPT_WINDOW_MS) > 0
  ? Number(process.env.OTP_ATTEMPT_WINDOW_MS)
  : 10 * 60 * 1000;

const LOCK_MS = Number(process.env.OTP_LOCKOUT_MS) > 0
  ? Number(process.env.OTP_LOCKOUT_MS)
  : 15 * 60 * 1000;

const MAX_ATTEMPTS = Number(process.env.OTP_MAX_ATTEMPTS) > 0
  ? Number(process.env.OTP_MAX_ATTEMPTS)
  : 5;

const keyFor = (scope, identity) => {
  const raw = `${scope}:${String(identity || '').trim().toLowerCase()}`;
  if (raw.length <= 160) return raw;
  return crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
};

const prune = () => {
  const now = Date.now();
  for (const [key, entry] of attempts.entries()) {
    if (
      (entry.lockedUntil && entry.lockedUntil <= now) ||
      (entry.windowStart && now > entry.windowStart + WINDOW_MS + LOCK_MS)
    ) {
      attempts.delete(key);
    }
  }
};

const isLocked = (scope, identity) => {
  const key = keyFor(scope, identity);
  const now = Date.now();
  const entry = attempts.get(key);
  if (!entry) return { locked: false, retryAfterSec: 0 };

  if (entry.lockedUntil && entry.lockedUntil > now) {
    return {
      locked: true,
      retryAfterSec: Math.ceil((entry.lockedUntil - now) / 1000),
    };
  }

  if (entry.lockedUntil && entry.lockedUntil <= now) {
    attempts.delete(key);
  }
  return { locked: false, retryAfterSec: 0 };
};

const recordFailure = (scope, identity) => {
  if (attempts.size >= MAX_KEYS) {
    prune();
  }
  const key = keyFor(scope, identity);
  const now = Date.now();
  let entry = attempts.get(key);

  if (!entry || now > entry.windowStart + WINDOW_MS) {
    entry = {
      count: 0,
      windowStart: now,
      lockedUntil: 0,
    };
  }

  entry.count += 1;
  if (entry.count >= MAX_ATTEMPTS) {
    entry.lockedUntil = now + LOCK_MS;
  }

  attempts.set(key, entry);
  return isLocked(scope, identity);
};

const clearFailures = (scope, identity) => {
  attempts.delete(keyFor(scope, identity));
};

module.exports = {
  isLocked,
  recordFailure,
  clearFailures,
};
