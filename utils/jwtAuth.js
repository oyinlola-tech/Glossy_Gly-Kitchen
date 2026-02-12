const jwt = require('jsonwebtoken');
const db = require('../config/db');
const { isUuid } = require('./validation');

const getTokenFromHeader = (req) => {
  const header = req.get('authorization');
  if (!header) return null;
  const [scheme, token] = header.trim().split(/\s+/);
  if (!scheme || scheme.toLowerCase() !== 'bearer' || !token) return null;
  return token.trim();
};

const requireAuth = async (req, res, next) => {
  const token = getTokenFromHeader(req);
  if (!token) {
    return res.status(401).json({ error: 'Authorization token required' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: process.env.JWT_ISSUER,
      algorithms: ['HS256'],
    });
    if (!payload || !payload.sub || !isUuid(payload.sub)) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    if (payload.typ && payload.typ !== 'access') {
      return res.status(401).json({ error: 'Invalid token' });
    }

    const [users] = await db.query('SELECT id, email, phone, verified, is_suspended FROM users WHERE id = ?', [payload.sub]);
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    if (!users[0].verified) {
      return res.status(403).json({ error: 'User not verified' });
    }
    if (users[0].is_suspended) {
      return res.status(403).json({ error: 'Account is suspended' });
    }

    req.user = {
      id: users[0].id,
      email: users[0].email,
      phone: users[0].phone,
    };
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

module.exports = {
  requireAuth,
};
