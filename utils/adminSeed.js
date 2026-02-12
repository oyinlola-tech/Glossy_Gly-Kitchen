const { v4: uuidv4 } = require('uuid');
const db = require('../config/db');
const { hashPassword, validatePassword } = require('./password');

const getSeedEmail = () => process.env.DEFAULT_ADMIN_EMAIL;
const getSeedName = () => process.env.DEFAULT_ADMIN_FULL_NAME;

const ensureSeedAdmin = async () => {
  const email = getSeedEmail();
  const fullName = getSeedName();
  const password = process.env.DEFAULT_ADMIN_PASSWORD;

  if (!password) {
    console.warn('DEFAULT_ADMIN_PASSWORD is not set. Skipping admin seed.');
    return;
  }

  const passwordError = validatePassword(password);
  if (passwordError) {
    throw new Error(`DEFAULT_ADMIN_PASSWORD is invalid: ${passwordError}`);
  }

  let existing;
  try {
    [existing] = await db.query('SELECT id FROM admin_users WHERE email = ?', [email]);
  } catch (err) {
    if (err && err.code === 'ER_NO_SUCH_TABLE') {
      console.warn('admin_users table not found yet. Skipping admin seed until migrations are applied.');
      return;
    }
    throw err;
  }
  if (existing.length > 0) {
    return;
  }

  const passwordHash = await hashPassword(password);
  await db.query(
    `INSERT INTO admin_users (id, email, full_name, password_hash, role, is_active, created_at, updated_at)
     VALUES (?, ?, ?, ?, 'super_admin', 1, NOW(), NOW())`,
    [uuidv4(), email, fullName, passwordHash]
  );

  console.log(`Seed admin created for ${email}`);
};

module.exports = {
  ensureSeedAdmin,
};
