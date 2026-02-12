const crypto = require('crypto');

const createRefreshToken = () => {
  return crypto.randomBytes(48).toString('hex');
};

const hashToken = (token) => {
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
};

const refreshExpiryDate = () => {
  const days = Number(process.env.REFRESH_TOKEN_EXPIRES_DAYS);
  const safeDays = Number.isFinite(days) && days > 0 && days <= 365 ? days : 30;
  return new Date(Date.now() + safeDays * 24 * 60 * 60 * 1000);
};

const adminRefreshExpiryDate = () => {
  const days = Number(process.env.ADMIN_REFRESH_TOKEN_EXPIRES_DAYS);
  const safeDays = Number.isFinite(days) && days > 0 && days <= 365 ? days : 30;
  return new Date(Date.now() + safeDays * 24 * 60 * 60 * 1000);
};

module.exports = {
  createRefreshToken,
  hashToken,
  refreshExpiryDate,
  adminRefreshExpiryDate,
};
