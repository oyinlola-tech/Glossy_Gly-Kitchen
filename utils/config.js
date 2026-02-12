const requireEnv = (key) => {
  if (!process.env[key] || String(process.env[key]).trim() === '') {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return process.env[key];
};

const requirePositiveNumberEnv = (key) => {
  const raw = requireEnv(key);
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`Invalid numeric environment variable: ${key}`);
  }
  return value;
};

const requireEnumEnv = (key, allowed) => {
  const value = requireEnv(key);
  if (!allowed.includes(value)) {
    throw new Error(`Invalid environment variable ${key}. Allowed values: ${allowed.join(', ')}`);
  }
  return value;
};

const requireMinLengthEnv = (key, minLength) => {
  const value = requireEnv(key);
  if (value.length < minLength) {
    throw new Error(`Environment variable ${key} must be at least ${minLength} characters`);
  }
  return value;
};

const rejectValuesInProduction = (key, blockedValues) => {
  if (process.env.NODE_ENV !== 'production') return;
  const value = requireEnv(key);
  if (blockedValues.includes(value)) {
    throw new Error(`Unsafe production value for ${key}`);
  }
};

const validateConfig = () => {
  requirePositiveNumberEnv('PORT');
  requireEnumEnv('NODE_ENV', ['development', 'production', 'test']);
  requireEnv('DB_HOST');
  requireEnv('DB_USER');
  requireEnv('DB_PASSWORD');
  requireEnv('DB_NAME');
  requireEnv('EMAIL_USER');
  requireEnv('EMAIL_PASS');
  requireEnv('EMAIL_FROM');
  requireEnv('ADMIN_BOOTSTRAP_KEY');
  requireEnv('JWT_SECRET');
  requireEnv('JWT_EXPIRES_IN');
  requireEnv('JWT_ISSUER');
  requireEnv('ADMIN_JWT_ISSUER');
  requireEnv('ADMIN_JWT_EXPIRES_IN');
  requirePositiveNumberEnv('REFRESH_TOKEN_EXPIRES_DAYS');
  requirePositiveNumberEnv('ADMIN_REFRESH_TOKEN_EXPIRES_DAYS');
  requirePositiveNumberEnv('PASSWORD_MIN_LENGTH');
  requirePositiveNumberEnv('BCRYPT_ROUNDS');
  requirePositiveNumberEnv('RATE_LIMIT_MAX');
  requirePositiveNumberEnv('AUTH_RATE_LIMIT_MAX');
  requirePositiveNumberEnv('ADMIN_AUTH_RATE_LIMIT_MAX');
  requireEnv('TRUST_PROXY');
  requireEnv('LOG_FILE');
  requireEnv('SWAGGER_SERVER_URL');
  requireEnv('DEFAULT_ADMIN_EMAIL');
  requireEnv('DEFAULT_ADMIN_PASSWORD');
  requireEnv('DEFAULT_ADMIN_FULL_NAME');
  requireEnv('PAYSTACK_SECRET_KEY');
  requireEnv('PAYSTACK_PUBLIC_KEY');
  requireEnv('PAYSTACK_WEBHOOK_SECRET');
  requireEnv('PAYSTACK_BASE_URL');

  if (process.env.NODE_ENV === 'production') {
    requireEnv('CORS_ORIGIN');
    requireMinLengthEnv('JWT_SECRET', 32);
    rejectValuesInProduction('JWT_SECRET', ['change_me']);
    rejectValuesInProduction('ADMIN_BOOTSTRAP_KEY', ['change_me_bootstrap']);
    rejectValuesInProduction('DEFAULT_ADMIN_PASSWORD', ['ChangeThisStrongAdminPassword123!']);
  }
};

module.exports = {
  validateConfig,
};
