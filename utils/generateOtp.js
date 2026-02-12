const crypto = require('crypto');

/**
 * Generate a 6-digit OTP
 * @returns {string} 6-digit OTP code
 */
const generateOtp = () => {
  const n = crypto.randomInt(0, 1_000_000);
  return String(n).padStart(6, '0');
};

module.exports = generateOtp;
