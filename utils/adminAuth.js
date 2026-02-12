const crypto = require('crypto');

const hashKey = (value) => {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
};

const safeEqual = (a, b) => {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aBuf = Buffer.from(a, 'utf8');
  const bBuf = Buffer.from(b, 'utf8');
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
};

const requireAdminKey = (req, res, next) => {
  const expected = process.env.ADMIN_API_KEY;
  if (!expected) {
    return res.status(500).json({ error: 'Admin key not configured' });
  }

  const provided = req.get('x-admin-key');
  if (!provided || !safeEqual(provided, expected)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  req.admin = { keyId: hashKey(provided) };
  return next();
};

const isAdminRequest = (req) => {
  const expected = process.env.ADMIN_API_KEY;
  if (!expected) return false;
  const provided = req.get('x-admin-key');
  return Boolean(provided && safeEqual(provided, expected));
};

module.exports = {
  requireAdminKey,
  isAdminRequest,
  hashKey,
  safeEqual,
};
