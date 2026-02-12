const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const sanitizeHeaderValue = (value, max = 64) => {
  if (typeof value !== 'string') return null;
  const cleaned = value.replace(/[^A-Za-z0-9._:-]/g, '').slice(0, max);
  return cleaned || null;
};

const sanitizeLogField = (value, max = 512) => {
  const raw = String(value || '');
  return raw.replace(/[\r\n\t]/g, ' ').slice(0, max);
};

const redactSensitiveQueryParams = (url) => {
  const raw = String(url || '');
  return raw.replace(
    /([?&](?:token|refreshToken|otp|password|authorizationCode)=)[^&]*/gi,
    '$1[redacted]'
  );
};

const requestId = (req, res, next) => {
  const incoming = sanitizeHeaderValue(req.get('x-request-id'), 64);
  const id = incoming || uuidv4();
  req.requestId = id;
  res.setHeader('X-Request-Id', id);
  next();
};

const writeLog = (line) => {
  const file = process.env.LOG_FILE;
  if (!file) return;
  const target = path.isAbsolute(file) ? file : path.join(process.cwd(), file);
  const dir = path.dirname(target);
  fs.mkdir(dir, { recursive: true }, (err) => {
    if (err) {
      console.error('Failed to create log directory:', err.message);
      return;
    }
    fs.appendFile(target, `${line}\n`, (appendErr) => {
      if (appendErr) {
        console.error('Failed to write log file:', appendErr.message);
      }
    });
  });
};

const requestLogger = (req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const durationMs = Date.now() - start;
    const userId = req.user && req.user.id ? req.user.id : 'anonymous';
    const adminTag = req.admin && req.admin.keyId ? ` admin=${req.admin.keyId.slice(0, 8)}` : '';
    const safeMethod = sanitizeLogField(req.method, 16);
    const safeUrl = sanitizeLogField(redactSensitiveQueryParams(req.originalUrl), 300);
    const safeUserId = sanitizeLogField(userId, 64);
    const safeIp = sanitizeLogField(req.ip, 64);
    const safeReqId = sanitizeLogField(req.requestId || 'n/a', 64);
    const line = `[${new Date().toISOString()}] ${safeMethod} ${safeUrl} ${res.statusCode} ${durationMs}ms user=${safeUserId}${adminTag} ip=${safeIp} reqId=${safeReqId}`;
    console.log(line);
    writeLog(line);
  });
  next();
};

module.exports = {
  requestId,
  requestLogger,
};
