const requireEnv = (key) => {
  if (!process.env[key] || String(process.env[key]).trim() === '') {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return process.env[key];
};

const validateConfig = () => {
  requireEnv('DB_HOST');
  requireEnv('DB_USER');
  requireEnv('DB_PASSWORD');
  requireEnv('DB_NAME');
  requireEnv('EMAIL_USER');
  requireEnv('EMAIL_PASS');
  requireEnv('EMAIL_FROM');
  requireEnv('ADMIN_API_KEY');
  requireEnv('JWT_SECRET');
};

module.exports = {
  validateConfig,
};
