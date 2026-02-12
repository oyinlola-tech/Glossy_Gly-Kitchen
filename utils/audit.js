const { v4: uuidv4 } = require('uuid');
const db = require('../config/db');

const auditAdminAction = (action) => {
  return (req, res, next) => {
    const start = Date.now();
    res.on('finish', async () => {
      if (!req.admin || !req.admin.keyId) return;
      const durationMs = Date.now() - start;
      const entityId = req.params && req.params.id ? req.params.id : null;

      try {
        await db.query(
          `INSERT INTO audit_logs
           (id, admin_key_hash, action, method, path, status_code, ip_address, user_agent, entity_id, duration_ms, request_id, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
          [
            uuidv4(),
            req.admin.keyId,
            action,
            req.method,
            req.originalUrl,
            res.statusCode,
            req.ip,
            req.get('user-agent') || null,
            entityId,
            durationMs,
            req.requestId || null,
          ]
        );
      } catch (err) {
        console.error('Audit log insert failed:', err.message);
      }
    });
    next();
  };
};

module.exports = {
  auditAdminAction,
};
