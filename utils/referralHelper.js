const crypto = require('crypto');

const randomBase36 = (length) => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const bytes = crypto.randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i += 1) {
    out += alphabet[bytes[i] % alphabet.length];
  }
  return out;
};

/**
 * Generate a unique referral code for a new user
 * Format: CHUKS + 6 random alphanumeric characters
 * @returns {string} Referral code
 */
const generateReferralCode = () => {
  const suffix = randomBase36(6);
  return `CHUKS${suffix}`;
};

const generateUniqueReferralCode = async (db, attempts = 10) => {
  for (let i = 0; i < attempts; i += 1) {
    const candidate = generateReferralCode();
    const [rows] = await db.query('SELECT id FROM users WHERE referral_code = ? LIMIT 1', [candidate]);
    if (rows.length === 0) {
      return candidate;
    }
  }
  throw new Error('Could not generate unique referral code');
};

/**
 * Validate a referral code (exists and user is verified)
 * @param {object} db - Database connection/pool
 * @param {string} code - Referral code to validate
 * @returns {Promise<string|null>} - User ID of referrer or null
 */
const validateReferralCode = async (db, code) => {
  if (!code) return null;
  const normalized = String(code).trim().toUpperCase();
  if (!normalized) return null;
  const [rows] = await db.query(
    'SELECT id FROM users WHERE referral_code = ? AND verified = 1',
    [normalized]
  );
  return rows.length ? rows[0].id : null;
};

module.exports = {
  generateReferralCode,
  generateUniqueReferralCode,
  validateReferralCode,
};
