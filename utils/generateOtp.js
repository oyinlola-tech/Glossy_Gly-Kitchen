/**
 * Generate a 6-digit OTP
 * @returns {string} 6-digit OTP code
 */
const generateOtp = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

module.exports = generateOtp;