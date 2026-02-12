/**
 * Generate a unique referral code for a new user
 * Format: CHUKS + 6 random alphanumeric characters
 * @returns {string} Referral code
 */
const generateReferralCode = () => {
  const suffix = Math.random().toString(36).substring(2, 8).toUpperCase();
  return `CHUKS${suffix}`;
};

/**
 * Validate a referral code (exists and user is verified)
 * @param {object} db - Database connection/pool
 * @param {string} code - Referral code to validate
 * @returns {Promise<string|null>} - User ID of referrer or null
 */
const validateReferralCode = async (db, code) => {
  if (!code) return null;
  const [rows] = await db.query(
    'SELECT id FROM users WHERE referral_code = ? AND verified = 1',
    [code]
  );
  return rows.length ? rows[0].id : null;
};

module.exports = {
  generateReferralCode,
  validateReferralCode,
};