const crypto = require('crypto');

const buildCorsOrigins = () => {
  if (!process.env.CORS_ORIGIN) return [];
  return process.env.CORS_ORIGIN
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
};

const securityHeaders = (req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-site');
  res.setHeader('X-DNS-Prefetch-Control', 'off');
  res.setHeader('X-Download-Options', 'noopen');

  if (req.path.startsWith('/api-docs')) {
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none';"
    );
  } else {
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none';");
  }
  next();
};

const cors = () => {
  const allowedOrigins = buildCorsOrigins();
  return (req, res, next) => {
    const origin = req.headers.origin;
    if (!origin) {
      return next();
    }

    if (allowedOrigins.length === 0) {
      // Development/default mode: allow requesting origin.
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
      res.setHeader(
        'Access-Control-Allow-Headers',
        'Content-Type, Authorization, X-Admin-Bootstrap-Key, X-User-Id, X-Device-Id'
      );
      if (req.method === 'OPTIONS') {
        return res.status(204).end();
      }
      return next();
    }

    if (!allowedOrigins.includes(origin)) {
      return res.status(403).json({ error: 'Origin not allowed' });
    }

    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, X-Admin-Bootstrap-Key, X-User-Id, X-Device-Id'
    );

    if (req.method === 'OPTIONS') {
      return res.status(204).end();
    }

    next();
  };
};

const requireJson = (req, res, next) => {
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    if (!req.is('application/json')) {
      return res.status(415).json({ error: 'Content-Type must be application/json' });
    }
  }
  next();
};

const rateLimit = ({ windowMs, max, keyGenerator } = {}) => {
  const hits = new Map();
  let lastPrune = 0;
  const windowMsSafe = Number(windowMs) > 0 ? Number(windowMs) : 60 * 1000;
  const maxSafe = Number(max) > 0 ? Number(max) : 60;
  const pruneInterval = 60 * 1000;
  const maxKeys = 10_000;

  const normalizeKey = (input) => {
    const raw = String(input || 'unknown');
    if (raw.length <= 128) return raw;
    return crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
  };

  return (req, res, next) => {
    const now = Date.now();

    if (now - lastPrune > pruneInterval) {
      for (const [key, entry] of hits.entries()) {
        if (entry.resetAt <= now) {
          hits.delete(key);
        }
      }
      lastPrune = now;
    }

    const key = normalizeKey(keyGenerator ? keyGenerator(req) : req.ip);
    const entry = hits.get(key);

    if (!entry || entry.resetAt <= now) {
      if (hits.size >= maxKeys) {
        for (const [k, v] of hits.entries()) {
          if (v.resetAt <= now) {
            hits.delete(k);
          }
          if (hits.size < maxKeys) break;
        }
      }
      hits.set(key, { count: 1, resetAt: now + windowMsSafe });
      return next();
    }

    entry.count += 1;
    if (entry.count > maxSafe) {
      const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
      res.setHeader('Retry-After', String(retryAfter));
      return res.status(429).json({ error: 'Too many requests' });
    }

    return next();
  };
};

module.exports = {
  securityHeaders,
  cors,
  requireJson,
  rateLimit,
};
