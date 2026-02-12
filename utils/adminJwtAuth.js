const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('../config/db');
const { isUuid } = require('./validation');

const adminIssuer = () => process.env.ADMIN_JWT_ISSUER;

const hashAdminAuditId = (adminId) => crypto.createHash('sha256').update(adminId, 'utf8').digest('hex');

const getTokenFromHeader = (req) => {
  const header = req.get('authorization');
  if (!header) return null;
  const [scheme, token] = header.trim().split(/\s+/);
  if (!scheme || scheme.toLowerCase() !== 'bearer' || !token) return null;
  return token.trim();
};

const requireAdminAuth = async (req, res, next) => {
  const token = getTokenFromHeader(req);
  if (!token) {
    return res.status(401).json({ error: 'Admin authorization token required' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: adminIssuer(),
      algorithms: ['HS256'],
    });

    if (!payload || payload.typ !== 'admin' || !payload.sub || !isUuid(payload.sub)) {
      return res.status(401).json({ error: 'Invalid admin token' });
    }

    const [admins] = await db.query(
      'SELECT id, email, full_name, role, is_active FROM admin_users WHERE id = ?',
      [payload.sub]
    );

    if (admins.length === 0 || !admins[0].is_active) {
      return res.status(401).json({ error: 'Invalid admin token' });
    }

    req.admin = {
      id: admins[0].id,
      email: admins[0].email,
      fullName: admins[0].full_name,
      role: admins[0].role,
      keyId: hashAdminAuditId(admins[0].id),
    };

    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid admin token' });
  }
};

const requireSuperAdmin = (req, res, next) => {
  if (!req.admin || req.admin.role !== 'super_admin') {
    return res.status(403).json({ error: 'Super admin access required' });
  }
  return next();
};

module.exports = {
  requireAdminAuth,
  requireSuperAdmin,
  adminIssuer,
};
