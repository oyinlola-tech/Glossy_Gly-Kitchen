const crypto = require('crypto');

const hashKey = (value) => {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
};

const requireAdminKey = (req, res, next) => {
  const expected = process.env.ADMIN_API_KEY;
  if (!expected) {
    return res.status(500).json({ error: 'Admin key not configured' });
  }

  const provided = req.get('x-admin-key');
  if (!provided || provided !== expected) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  req.admin = { keyId: hashKey(provided) };
  return next();
};

const isAdminRequest = (req) => {
  const expected = process.env.ADMIN_API_KEY;
  if (!expected) return false;
  const provided = req.get('x-admin-key');
  return Boolean(provided && provided === expected);
};

module.exports = {
  requireAdminKey,
  isAdminRequest,
  hashKey,
};
