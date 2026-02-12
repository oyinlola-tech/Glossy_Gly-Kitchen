const db = require('../config/db');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { isUuid, isValidEmail, toInt, toNumber } = require('../utils/validation');
const { validatePassword, hashPassword, comparePassword } = require('../utils/password');
const { createRefreshToken, hashToken, adminRefreshExpiryDate } = require('../utils/tokens');
const { isTransitionAllowed } = require('../utils/statusTransitions');
const { adminIssuer } = require('../utils/adminJwtAuth');
const { safeEqual } = require('../utils/adminAuth');
const generateOtp = require('../utils/generateOtp');
const { sendMail } = require('../utils/mailer');
const { isLocked, recordFailure, clearFailures } = require('../utils/otpGuard');

const DUMMY_PASSWORD_HASH = '$2a$10$7EqJtq98hPqEX7fNZaFWoOaJY8fDeihh5Z8SGvtQvE4H14R/2uOe';
const COUPON_CODE_REGEX = /^[A-Z0-9_-]{4,40}$/;
const REFERRAL_CODE_REGEX = /^[A-Z0-9]{6,20}$/;
const REFRESH_TOKEN_REGEX = /^[a-f0-9]{96}$/i;

const normalizeRefreshToken = (value) => {
  if (typeof value !== 'string') return null;
  const token = value.trim();
  if (!REFRESH_TOKEN_REGEX.test(token)) return null;
  return token;
};

const parsePaging = (req) => {
  const page = Math.max(toInt(req.query.page) || 1, 1);
  const limit = Math.min(Math.max(toInt(req.query.limit) || 20, 1), 100);
  const offset = (page - 1) * limit;
  return { page, limit, offset };
};

const parseDateTimeOrNull = (value) => {
  if (value === undefined || value === null || value === '') return null;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  return d;
};

const generateCode = (prefix, length) => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const bytes = crypto.randomBytes(length);
  let suffix = '';
  for (let i = 0; i < length; i += 1) {
    suffix += alphabet[bytes[i] % alphabet.length];
  }
  return `${prefix}${suffix}`;
};

const generateUniqueCouponCode = async (connection, attempts = 10) => {
  for (let i = 0; i < attempts; i += 1) {
    const candidate = generateCode('CPN', 9);
    const [rows] = await connection.query('SELECT id FROM coupons WHERE code = ? LIMIT 1', [candidate]);
    if (rows.length === 0) return candidate;
  }
  throw new Error('Could not generate unique coupon code');
};

const generateUniqueUserReferralCode = async (connection, attempts = 10) => {
  for (let i = 0; i < attempts; i += 1) {
    const candidate = generateCode('REF', 8);
    const [rows] = await connection.query('SELECT id FROM users WHERE referral_code = ? LIMIT 1', [candidate]);
    if (rows.length === 0) return candidate;
  }
  throw new Error('Could not generate unique referral code');
};

const getDeviceFingerprint = (req, bodyDeviceId) => {
  const headerDeviceId = req.get('x-device-id');
  const deviceIdentityRaw = headerDeviceId || bodyDeviceId || req.get('user-agent') || 'unknown-device';
  const deviceIdentity = String(deviceIdentityRaw).slice(0, 512);
  return crypto.createHash('sha256').update(deviceIdentity, 'utf8').digest('hex');
};

const sendAdminOtpEmail = async (email, otp) => {
  await sendMail({
    to: email,
    subject: 'Glossy_Gly-Kitchen - Admin Login OTP Verification',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #0f766e;">Glossy_Gly-Kitchen Admin Security Check</h2>
        <p>A login was detected from a new device or IP. Use this OTP to continue:</p>
        <div style="background: #f5f5f5; padding: 15px; font-size: 24px; font-weight: bold; text-align: center; letter-spacing: 5px;">
          ${otp}
        </div>
        <p>This code expires in 10 minutes.</p>
      </div>
    `,
  });
};

const markDeviceTrusted = async (adminId, deviceHash, req, deviceLabel) => {
  await db.query(
    `INSERT INTO admin_trusted_devices (id, admin_id, device_hash, device_label, last_ip, last_seen_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, NOW(), NOW(), NOW())
     ON DUPLICATE KEY UPDATE
       device_label = VALUES(device_label),
       last_ip = VALUES(last_ip),
       last_seen_at = NOW(),
       updated_at = NOW()`,
    [uuidv4(), adminId, deviceHash, deviceLabel || null, req.ip]
  );
};

const issueAdminAccessToken = (admin) => {
  return jwt.sign(
    { sub: admin.id, email: admin.email, role: admin.role, typ: 'admin' },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.ADMIN_JWT_EXPIRES_IN,
      issuer: adminIssuer(),
    }
  );
};

const issueAdminRefreshToken = async (adminId, req, queryable = db) => {
  const token = createRefreshToken();
  const tokenHash = hashToken(token);
  const expiresAt = adminRefreshExpiryDate();

  await queryable.query(
    `INSERT INTO admin_refresh_tokens
     (id, admin_id, token_hash, expires_at, created_ip, user_agent, created_at)
     VALUES (?, ?, ?, ?, ?, ?, NOW())`,
    [uuidv4(), adminId, tokenHash, expiresAt, req.ip, req.get('user-agent') || null]
  );

  return token;
};

const issueAdminTokens = async (admin, req, queryable = db) => {
  const accessToken = issueAdminAccessToken(admin);
  const refreshToken = await issueAdminRefreshToken(admin.id, req, queryable);
  return { accessToken, refreshToken };
};

exports.bootstrap = async (req, res) => {
  const expectedBootstrapKey = process.env.ADMIN_BOOTSTRAP_KEY;
  if (!expectedBootstrapKey) {
    return res.status(500).json({ error: 'ADMIN_BOOTSTRAP_KEY is not configured' });
  }

  const providedKey = req.get('x-admin-bootstrap-key');
  if (!providedKey || !safeEqual(providedKey, expectedBootstrapKey)) {
    return res.status(401).json({ error: 'Unauthorized bootstrap request' });
  }

  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const { password, fullName, role } = req.body;
  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ error: 'Valid email is required' });
  }
  if (!fullName || typeof fullName !== 'string' || !fullName.trim()) {
    return res.status(400).json({ error: 'fullName is required' });
  }
  const passwordError = validatePassword(password);
  if (passwordError) {
    return res.status(400).json({ error: passwordError });
  }

  const allowedRoles = ['super_admin', 'operations_admin', 'support_admin'];
  const roleValue = role && allowedRoles.includes(role) ? role : 'super_admin';

  try {
    const [existing] = await db.query('SELECT id FROM admin_users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(409).json({ error: 'Admin email already exists' });
    }

    const [countRows] = await db.query('SELECT COUNT(*) AS count FROM admin_users');
    if (countRows[0].count > 0 && roleValue === 'super_admin') {
      return res.status(403).json({ error: 'Super admin already initialized. Use admin APIs to create more admins.' });
    }

    const adminId = uuidv4();
    const passwordHash = await hashPassword(password);

    await db.query(
      `INSERT INTO admin_users (id, email, full_name, password_hash, role, is_active, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 1, NOW(), NOW())`,
      [adminId, email, fullName.trim(), passwordHash, roleValue]
    );

    const admin = { id: adminId, email, role: roleValue };
    const tokens = await issueAdminTokens(admin, req);

    return res.status(201).json({
      message: 'Admin account created',
      admin: {
        id: adminId,
        email,
        fullName: fullName.trim(),
        role: roleValue,
      },
      ...tokens,
    });
  } catch (err) {
    console.error('Admin bootstrap error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.login = async (req, res) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const { password, otp, deviceId, deviceLabel } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  try {
    const [admins] = await db.query(
      'SELECT id, email, full_name, role, password_hash, is_active FROM admin_users WHERE email = ?',
      [email]
    );
    if (admins.length === 0) {
      await comparePassword(password, DUMMY_PASSWORD_HASH);
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const admin = admins[0];
    if (!admin.is_active) {
      await comparePassword(password, admin.password_hash || DUMMY_PASSWORD_HASH);
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const ok = await comparePassword(password, admin.password_hash || DUMMY_PASSWORD_HASH);
    if (!ok) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const deviceHash = getDeviceFingerprint(req, deviceId);
    const [trustedRows] = await db.query(
      'SELECT id, last_ip FROM admin_trusted_devices WHERE admin_id = ? AND device_hash = ?',
      [admin.id, deviceHash]
    );

    const trustedDevice = trustedRows.length > 0 ? trustedRows[0] : null;
    const requiresOtp = !trustedDevice || (trustedDevice.last_ip && trustedDevice.last_ip !== req.ip);

    if (requiresOtp) {
      const otpScope = `admin-login-otp:${admin.id}:${deviceHash}:${req.ip}`;
      const lockState = isLocked('admin-login-otp', otpScope);
      if (lockState.locked) {
        res.setHeader('Retry-After', String(lockState.retryAfterSec));
        return res.status(429).json({ error: 'Too many invalid OTP attempts. Try again later.' });
      }
      if (!otp) {
        const otpCode = generateOtp();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

        await db.query(
          `UPDATE admin_login_otps
           SET consumed_at = NOW()
           WHERE admin_id = ? AND device_hash = ? AND ip_address = ? AND consumed_at IS NULL`,
          [admin.id, deviceHash, req.ip]
        );

        await db.query(
          `INSERT INTO admin_login_otps (id, admin_id, device_hash, ip_address, otp_code, otp_expires, created_at)
           VALUES (?, ?, ?, ?, ?, ?, NOW())`,
          [uuidv4(), admin.id, deviceHash, req.ip, otpCode, otpExpires]
        );

        await sendAdminOtpEmail(admin.email, otpCode);
        return res.status(202).json({
          message: 'OTP verification required for this device or IP. Please submit login again with otp.',
          otpRequired: true,
        });
      }
      if (!/^\d{6}$/.test(String(otp).trim())) {
        const afterFailure = recordFailure('admin-login-otp', otpScope);
        if (afterFailure.locked) {
          res.setHeader('Retry-After', String(afterFailure.retryAfterSec));
          return res.status(429).json({ error: 'Too many invalid OTP attempts. Try again later.' });
        }
        return res.status(400).json({ error: 'Invalid or expired admin OTP' });
      }

      const [otpRows] = await db.query(
        `SELECT id, otp_code, otp_expires
         FROM admin_login_otps
         WHERE admin_id = ? AND device_hash = ? AND ip_address = ? AND consumed_at IS NULL
         ORDER BY created_at DESC
         LIMIT 1`,
        [admin.id, deviceHash, req.ip]
      );

      if (
        otpRows.length === 0 ||
        otpRows[0].otp_code !== String(otp) ||
        new Date(otpRows[0].otp_expires) <= new Date()
      ) {
        const afterFailure = recordFailure('admin-login-otp', otpScope);
        if (afterFailure.locked) {
          res.setHeader('Retry-After', String(afterFailure.retryAfterSec));
          return res.status(429).json({ error: 'Too many invalid OTP attempts. Try again later.' });
        }
        return res.status(400).json({ error: 'Invalid or expired admin OTP' });
      }

      await db.query('UPDATE admin_login_otps SET consumed_at = NOW() WHERE id = ?', [otpRows[0].id]);
      clearFailures('admin-login-otp', otpScope);
    }

    await markDeviceTrusted(admin.id, deviceHash, req, deviceLabel);
    await db.query('UPDATE admin_users SET last_login_at = NOW(), updated_at = NOW() WHERE id = ?', [admin.id]);
    const tokens = await issueAdminTokens(admin, req);

    return res.json({
      message: 'Admin login successful',
      admin: {
        id: admin.id,
        email: admin.email,
        fullName: admin.full_name,
        role: admin.role,
      },
      ...tokens,
    });
  } catch (err) {
    console.error('Admin login error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.refresh = async (req, res) => {
  const refreshToken = normalizeRefreshToken(req.body && req.body.refreshToken);
  if (!refreshToken) {
    return res.status(400).json({ error: 'Valid refreshToken is required' });
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    const tokenHash = hashToken(refreshToken);
    const [rows] = await connection.query(
      `SELECT id, admin_id, expires_at, revoked_at
       FROM admin_refresh_tokens
       WHERE token_hash = ?
       FOR UPDATE`,
      [tokenHash]
    );

    if (rows.length === 0) {
      await connection.rollback();
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    const tokenRow = rows[0];
    if (tokenRow.revoked_at) {
      await connection.rollback();
      return res.status(401).json({ error: 'Refresh token revoked' });
    }
    if (new Date(tokenRow.expires_at) <= new Date()) {
      await connection.rollback();
      return res.status(401).json({ error: 'Refresh token expired' });
    }

    await connection.query('UPDATE admin_refresh_tokens SET revoked_at = NOW() WHERE id = ?', [tokenRow.id]);

    const [admins] = await connection.query(
      'SELECT id, email, role, is_active FROM admin_users WHERE id = ? FOR UPDATE',
      [tokenRow.admin_id]
    );
    if (admins.length === 0 || !admins[0].is_active) {
      await connection.rollback();
      return res.status(401).json({ error: 'Invalid admin' });
    }

    const tokens = await issueAdminTokens(admins[0], req, connection);
    await connection.commit();
    return res.json({ message: 'Token refreshed', ...tokens });
  } catch (err) {
    await connection.rollback();
    console.error('Admin refresh error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
};

exports.logout = async (req, res) => {
  const refreshToken = normalizeRefreshToken(req.body && req.body.refreshToken);
  const adminId = req.admin && req.admin.id;
  if (!adminId || !isUuid(adminId)) {
    return res.status(401).json({ error: 'Admin authorization token required' });
  }
  if (!refreshToken) {
    return res.status(400).json({ error: 'Valid refreshToken is required' });
  }

  try {
    const tokenHash = hashToken(refreshToken);
    await db.query(
      'UPDATE admin_refresh_tokens SET revoked_at = NOW() WHERE token_hash = ? AND admin_id = ?',
      [tokenHash, adminId]
    );
    return res.json({ message: 'Logged out' });
  } catch (err) {
    console.error('Admin logout error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.logoutAll = async (req, res) => {
  const adminId = req.admin && req.admin.id;
  if (!adminId || !isUuid(adminId)) {
    return res.status(401).json({ error: 'Admin authorization token required' });
  }

  try {
    await db.query(
      'UPDATE admin_refresh_tokens SET revoked_at = NOW() WHERE admin_id = ? AND revoked_at IS NULL',
      [adminId]
    );
    return res.json({ message: 'All admin sessions logged out' });
  } catch (err) {
    console.error('Admin logout all error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.me = async (req, res) => {
  return res.json({
    id: req.admin.id,
    email: req.admin.email,
    fullName: req.admin.fullName,
    role: req.admin.role,
  });
};

exports.createAdmin = async (req, res) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const { password, fullName, role } = req.body;
  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ error: 'Valid email is required' });
  }
  if (!fullName || typeof fullName !== 'string' || !fullName.trim()) {
    return res.status(400).json({ error: 'fullName is required' });
  }
  const passwordError = validatePassword(password);
  if (passwordError) {
    return res.status(400).json({ error: passwordError });
  }

  const allowedRoles = ['super_admin', 'operations_admin', 'support_admin'];
  const roleValue = allowedRoles.includes(role) ? role : 'support_admin';

  try {
    const [existing] = await db.query('SELECT id FROM admin_users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(409).json({ error: 'Admin email already exists' });
    }

    const adminId = uuidv4();
    const passwordHash = await hashPassword(password);
    await db.query(
      `INSERT INTO admin_users (id, email, full_name, password_hash, role, is_active, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 1, NOW(), NOW())`,
      [adminId, email, fullName.trim(), passwordHash, roleValue]
    );

    return res.status(201).json({
      id: adminId,
      email,
      fullName: fullName.trim(),
      role: roleValue,
      isActive: true,
    });
  } catch (err) {
    console.error('Create admin error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.createCoupon = async (req, res) => {
  const {
    code,
    description,
    discountType,
    discountValue,
    maxRedemptions,
    startsAt,
    expiresAt,
    isActive,
  } = req.body || {};

  const normalizedType = String(discountType || '').trim().toLowerCase();
  if (!['percentage', 'fixed'].includes(normalizedType)) {
    return res.status(400).json({ error: 'discountType must be percentage or fixed' });
  }

  const discount = toNumber(discountValue);
  if (discount === null || discount <= 0) {
    return res.status(400).json({ error: 'discountValue must be a positive number' });
  }
  if (normalizedType === 'percentage' && discount > 100) {
    return res.status(400).json({ error: 'percentage discountValue cannot exceed 100' });
  }

  const maxUses = maxRedemptions === undefined || maxRedemptions === null || maxRedemptions === ''
    ? null
    : toInt(maxRedemptions);
  if (maxUses !== null && maxUses <= 0) {
    return res.status(400).json({ error: 'maxRedemptions must be a positive integer' });
  }

  const startsDate = parseDateTimeOrNull(startsAt);
  const expiresDate = parseDateTimeOrNull(expiresAt);
  if (startsAt !== undefined && startsDate === null) {
    return res.status(400).json({ error: 'Invalid startsAt datetime' });
  }
  if (expiresAt !== undefined && expiresDate === null) {
    return res.status(400).json({ error: 'Invalid expiresAt datetime' });
  }
  if (startsDate && expiresDate && expiresDate <= startsDate) {
    return res.status(400).json({ error: 'expiresAt must be after startsAt' });
  }

  let normalizedCode = null;
  if (code !== undefined && code !== null && String(code).trim() !== '') {
    normalizedCode = String(code).trim().toUpperCase();
    if (!COUPON_CODE_REGEX.test(normalizedCode)) {
      return res.status(400).json({ error: 'Invalid coupon code format' });
    }
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    const couponCode = normalizedCode || await generateUniqueCouponCode(connection);
    const [existing] = await connection.query('SELECT id FROM coupons WHERE code = ? LIMIT 1', [couponCode]);
    if (existing.length > 0) {
      await connection.rollback();
      return res.status(409).json({ error: 'Coupon code already exists' });
    }

    const couponId = uuidv4();
    await connection.query(
      `INSERT INTO coupons
       (id, code, description, discount_type, discount_value, max_redemptions, redemptions_count, starts_at, expires_at, is_active, created_by_admin_id, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, NOW(), NOW())`,
      [
        couponId,
        couponCode,
        description ? String(description).trim().slice(0, 255) : null,
        normalizedType,
        discount,
        maxUses,
        startsDate,
        expiresDate,
        isActive === undefined ? 1 : (isActive ? 1 : 0),
        req.admin.id,
      ]
    );

    const [rows] = await connection.query(
      `SELECT id, code, description, discount_type, discount_value, max_redemptions, redemptions_count, starts_at, expires_at, is_active, created_by_admin_id, created_at, updated_at
       FROM coupons WHERE id = ?`,
      [couponId]
    );

    await connection.commit();
    return res.status(201).json(rows[0]);
  } catch (err) {
    await connection.rollback();
    console.error('Create coupon error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
};

exports.listCoupons = async (req, res) => {
  const { page, limit, offset } = parsePaging(req);
  const where = [];
  const values = [];

  if (req.query.active === 'true' || req.query.active === 'false') {
    where.push('is_active = ?');
    values.push(req.query.active === 'true' ? 1 : 0);
  }
  if (req.query.code) {
    const code = String(req.query.code).trim().toUpperCase();
    where.push('code = ?');
    values.push(code);
  }

  const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  try {
    const [countRows] = await db.query(`SELECT COUNT(*) AS total FROM coupons ${whereClause}`, values);
    const [rows] = await db.query(
      `SELECT id, code, description, discount_type, discount_value, max_redemptions, redemptions_count, starts_at, expires_at, is_active, created_by_admin_id, created_at, updated_at
       FROM coupons
       ${whereClause}
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [...values, limit, offset]
    );

    return res.json({
      page,
      limit,
      total: countRows[0].total,
      coupons: rows,
    });
  } catch (err) {
    console.error('List coupons error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.createUserReferralCode = async (req, res) => {
  const { userId, code } = req.body || {};
  if (!isUuid(userId)) {
    return res.status(400).json({ error: 'Valid userId is required' });
  }

  let normalizedCode = null;
  if (code !== undefined && code !== null && String(code).trim() !== '') {
    normalizedCode = String(code).trim().toUpperCase();
    if (!REFERRAL_CODE_REGEX.test(normalizedCode)) {
      return res.status(400).json({ error: 'Invalid referral code format' });
    }
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    const [users] = await connection.query(
      'SELECT id FROM users WHERE id = ? FOR UPDATE',
      [userId]
    );
    if (users.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'User not found' });
    }

    const referralCode = normalizedCode || await generateUniqueUserReferralCode(connection);
    const [dup] = await connection.query(
      'SELECT id FROM users WHERE referral_code = ? AND id <> ? LIMIT 1',
      [referralCode, userId]
    );
    if (dup.length > 0) {
      await connection.rollback();
      return res.status(409).json({ error: 'Referral code already exists' });
    }

    await connection.query(
      'UPDATE users SET referral_code = ?, updated_at = NOW() WHERE id = ?',
      [referralCode, userId]
    );

    await connection.commit();
    return res.status(201).json({
      message: 'Referral code created successfully',
      userId,
      referralCode,
    });
  } catch (err) {
    await connection.rollback();
    console.error('Create user referral code error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
};

exports.listUserReferralCodes = async (req, res) => {
  const { page, limit, offset } = parsePaging(req);
  const where = ['u.referral_code IS NOT NULL'];
  const values = [];

  if (req.query.userId) {
    if (!isUuid(req.query.userId)) {
      return res.status(400).json({ error: 'Invalid userId' });
    }
    where.push('u.id = ?');
    values.push(req.query.userId);
  }
  if (req.query.code) {
    where.push('u.referral_code = ?');
    values.push(String(req.query.code).trim().toUpperCase());
  }

  const whereClause = `WHERE ${where.join(' AND ')}`;
  try {
    const [countRows] = await db.query(`SELECT COUNT(*) AS total FROM users u ${whereClause}`, values);
    const [rows] = await db.query(
      `SELECT
         u.id AS user_id,
         u.email,
         u.referral_code,
         u.created_at,
         u.updated_at,
         (
           SELECT COUNT(*)
           FROM users ru
           WHERE ru.referred_by = u.id
         ) AS referred_customers,
         (
           SELECT COUNT(*)
           FROM orders o
           JOIN users ru2 ON ru2.id = o.user_id
           WHERE ru2.referred_by = u.id
             AND o.status <> 'cancelled'
         ) AS referred_orders_count
       FROM users u
       ${whereClause}
       ORDER BY u.updated_at DESC
       LIMIT ? OFFSET ?`,
      [...values, limit, offset]
    );

    return res.json({
      page,
      limit,
      total: countRows[0].total,
      referralCodes: rows,
    });
  } catch (err) {
    console.error('List referral codes error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.listUsers = async (req, res) => {
  const { page, limit, offset } = parsePaging(req);
  const search = req.query.search ? `%${String(req.query.search).trim()}%` : null;
  const verified = req.query.verified;
  const suspended = req.query.suspended;

  const where = [];
  const values = [];

  if (search) {
    where.push('(email LIKE ? OR phone LIKE ?)');
    values.push(search, search);
  }
  if (verified === 'true' || verified === 'false') {
    where.push('verified = ?');
    values.push(verified === 'true' ? 1 : 0);
  }
  if (suspended === 'true' || suspended === 'false') {
    where.push('is_suspended = ?');
    values.push(suspended === 'true' ? 1 : 0);
  }

  const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';

  try {
    const [countRows] = await db.query(`SELECT COUNT(*) AS total FROM users ${whereClause}`, values);
    const [rows] = await db.query(
      `SELECT id, email, phone, verified, is_suspended, created_at, updated_at
       FROM users
       ${whereClause}
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [...values, limit, offset]
    );

    return res.json({
      page,
      limit,
      total: countRows[0].total,
      users: rows,
    });
  } catch (err) {
    console.error('List users error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.getUserById = async (req, res) => {
  const { id } = req.params;
  if (!isUuid(id)) {
    return res.status(400).json({ error: 'Invalid user id' });
  }

  try {
    const [users] = await db.query(
      `SELECT id, email, phone, verified, is_suspended, referral_code, referred_by, created_at, updated_at
       FROM users WHERE id = ?`,
      [id]
    );
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const [orderStats] = await db.query(
      `SELECT COUNT(*) AS total_orders, COALESCE(SUM(total_amount),0) AS total_spent
       FROM orders WHERE user_id = ?`,
      [id]
    );

    return res.json({
      ...users[0],
      stats: orderStats[0],
    });
  } catch (err) {
    console.error('Get user error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.updateUserStatus = async (req, res) => {
  const { id } = req.params;
  const { verified, isSuspended } = req.body;

  if (!isUuid(id)) {
    return res.status(400).json({ error: 'Invalid user id' });
  }
  if (verified === undefined && isSuspended === undefined) {
    return res.status(400).json({ error: 'At least one of verified or isSuspended is required' });
  }

  const fields = [];
  const values = [];

  if (verified !== undefined) {
    if (typeof verified !== 'boolean') {
      return res.status(400).json({ error: 'verified must be boolean' });
    }
    fields.push('verified = ?');
    values.push(verified ? 1 : 0);
  }
  if (isSuspended !== undefined) {
    if (typeof isSuspended !== 'boolean') {
      return res.status(400).json({ error: 'isSuspended must be boolean' });
    }
    fields.push('is_suspended = ?');
    values.push(isSuspended ? 1 : 0);
  }

  fields.push('updated_at = NOW()');

  try {
    const [result] = await db.query(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`, [...values, id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const [rows] = await db.query(
      'SELECT id, email, phone, verified, is_suspended, created_at, updated_at FROM users WHERE id = ?',
      [id]
    );
    return res.json(rows[0]);
  } catch (err) {
    console.error('Update user status error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.listOrders = async (req, res) => {
  const { page, limit, offset } = parsePaging(req);
  const where = [];
  const values = [];

  if (req.query.status) {
    where.push('o.status = ?');
    values.push(String(req.query.status));
  }
  if (req.query.userId) {
    if (!isUuid(req.query.userId)) {
      return res.status(400).json({ error: 'Invalid userId' });
    }
    where.push('o.user_id = ?');
    values.push(req.query.userId);
  }

  const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';

  try {
    const [countRows] = await db.query(`SELECT COUNT(*) AS total FROM orders o ${whereClause}`, values);
    const [rows] = await db.query(
      `SELECT o.id, o.user_id, o.total_amount, o.status, o.created_at, o.updated_at, u.email
       FROM orders o
       JOIN users u ON u.id = o.user_id
       ${whereClause}
       ORDER BY o.created_at DESC
       LIMIT ? OFFSET ?`,
      [...values, limit, offset]
    );

    return res.json({ page, limit, total: countRows[0].total, orders: rows });
  } catch (err) {
    console.error('List orders error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.getOrderById = async (req, res) => {
  const { id } = req.params;
  if (!isUuid(id)) {
    return res.status(400).json({ error: 'Invalid order id' });
  }

  try {
    const [orders] = await db.query(
      `SELECT o.*, u.email, u.phone
       FROM orders o
       JOIN users u ON o.user_id = u.id
       WHERE o.id = ?`,
      [id]
    );

    if (orders.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const [items] = await db.query(
      `SELECT oi.*, fi.name
       FROM order_items oi
       JOIN food_items fi ON fi.id = oi.food_id
       WHERE oi.order_id = ?`,
      [id]
    );

    return res.json({ ...orders[0], items });
  } catch (err) {
    console.error('Get admin order error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.updateOrderStatus = async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  if (!isUuid(id)) {
    return res.status(400).json({ error: 'Invalid order id' });
  }
  if (!status) {
    return res.status(400).json({ error: 'status is required' });
  }

  try {
    const [orders] = await db.query('SELECT status FROM orders WHERE id = ?', [id]);
    if (orders.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const currentStatus = orders[0].status;
    if (!isTransitionAllowed(currentStatus, status)) {
      return res.status(400).json({ error: `Cannot transition order from '${currentStatus}' to '${status}'` });
    }

    await db.query('UPDATE orders SET status = ?, updated_at = NOW() WHERE id = ?', [status, id]);
    return res.json({ message: 'Order status updated successfully', orderId: id, newStatus: status });
  } catch (err) {
    console.error('Admin update order status error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.createDispute = async (req, res) => {
  const { orderId, userId, title, description, priority, category, assignedAdminId } = req.body;
  if (!title || typeof title !== 'string' || !title.trim()) {
    return res.status(400).json({ error: 'title is required' });
  }
  if (!description || typeof description !== 'string' || !description.trim()) {
    return res.status(400).json({ error: 'description is required' });
  }
  if (orderId && !isUuid(orderId)) {
    return res.status(400).json({ error: 'Invalid orderId' });
  }
  if (userId && !isUuid(userId)) {
    return res.status(400).json({ error: 'Invalid userId' });
  }
  if (assignedAdminId && !isUuid(assignedAdminId)) {
    return res.status(400).json({ error: 'Invalid assignedAdminId' });
  }

  const priorityValue = ['low', 'medium', 'high', 'urgent'].includes(priority) ? priority : 'medium';

  try {
    if (orderId) {
      const [orders] = await db.query('SELECT id FROM orders WHERE id = ?', [orderId]);
      if (orders.length === 0) return res.status(404).json({ error: 'Order not found' });
    }
    if (userId) {
      const [users] = await db.query('SELECT id FROM users WHERE id = ?', [userId]);
      if (users.length === 0) return res.status(404).json({ error: 'User not found' });
    }
    if (assignedAdminId) {
      const [admins] = await db.query('SELECT id FROM admin_users WHERE id = ? AND is_active = 1', [assignedAdminId]);
      if (admins.length === 0) return res.status(404).json({ error: 'Assigned admin not found' });
    }

    const disputeId = uuidv4();
    await db.query(
      `INSERT INTO disputes
       (id, order_id, user_id, raised_by_type, raised_by_id, title, description, status, priority, category, assigned_admin_id, created_at, updated_at)
       VALUES (?, ?, ?, 'admin', ?, ?, ?, 'open', ?, ?, ?, NOW(), NOW())`,
      [
        disputeId,
        orderId || null,
        userId || null,
        req.admin.id,
        title.trim(),
        description.trim(),
        priorityValue,
        category || null,
        assignedAdminId || null,
      ]
    );

    const [rows] = await db.query('SELECT * FROM disputes WHERE id = ?', [disputeId]);
    return res.status(201).json(rows[0]);
  } catch (err) {
    console.error('Create dispute error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.listDisputes = async (req, res) => {
  const { page, limit, offset } = parsePaging(req);
  const where = [];
  const values = [];

  if (req.query.status) {
    where.push('d.status = ?');
    values.push(String(req.query.status));
  }
  if (req.query.priority) {
    where.push('d.priority = ?');
    values.push(String(req.query.priority));
  }
  if (req.query.assignedAdminId) {
    if (!isUuid(req.query.assignedAdminId)) {
      return res.status(400).json({ error: 'Invalid assignedAdminId' });
    }
    where.push('d.assigned_admin_id = ?');
    values.push(req.query.assignedAdminId);
  }

  const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';

  try {
    const [countRows] = await db.query(`SELECT COUNT(*) AS total FROM disputes d ${whereClause}`, values);
    const [rows] = await db.query(
      `SELECT d.*, au.full_name AS assigned_admin_name
       FROM disputes d
       LEFT JOIN admin_users au ON au.id = d.assigned_admin_id
       ${whereClause}
       ORDER BY d.created_at DESC
       LIMIT ? OFFSET ?`,
      [...values, limit, offset]
    );

    return res.json({ page, limit, total: countRows[0].total, disputes: rows });
  } catch (err) {
    console.error('List disputes error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.getDisputeById = async (req, res) => {
  const { id } = req.params;
  if (!isUuid(id)) {
    return res.status(400).json({ error: 'Invalid dispute id' });
  }

  try {
    const [rows] = await db.query(
      `SELECT d.*, au.full_name AS assigned_admin_name
       FROM disputes d
       LEFT JOIN admin_users au ON au.id = d.assigned_admin_id
       WHERE d.id = ?`,
      [id]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Dispute not found' });
    }

    const [comments] = await db.query(
      `SELECT id, dispute_id, author_type, author_id, is_internal, comment, created_at
       FROM dispute_comments
       WHERE dispute_id = ?
       ORDER BY created_at ASC`,
      [id]
    );

    return res.json({ ...rows[0], comments });
  } catch (err) {
    console.error('Get dispute error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.updateDispute = async (req, res) => {
  const { id } = req.params;
  const { status, priority, category, assignedAdminId, resolutionNotes } = req.body;
  if (!isUuid(id)) {
    return res.status(400).json({ error: 'Invalid dispute id' });
  }
  if (
    status === undefined &&
    priority === undefined &&
    category === undefined &&
    assignedAdminId === undefined &&
    resolutionNotes === undefined
  ) {
    return res.status(400).json({ error: 'No fields to update' });
  }

  const fields = [];
  const values = [];

  if (status !== undefined) {
    if (!['open', 'investigating', 'resolved', 'rejected', 'closed'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    fields.push('status = ?');
    values.push(status);
    if (status === 'resolved' || status === 'closed') {
      fields.push('resolved_at = NOW()');
    }
  }
  if (priority !== undefined) {
    if (!['low', 'medium', 'high', 'urgent'].includes(priority)) {
      return res.status(400).json({ error: 'Invalid priority' });
    }
    fields.push('priority = ?');
    values.push(priority);
  }
  if (category !== undefined) {
    fields.push('category = ?');
    values.push(category || null);
  }
  if (assignedAdminId !== undefined) {
    if (assignedAdminId !== null && !isUuid(assignedAdminId)) {
      return res.status(400).json({ error: 'Invalid assignedAdminId' });
    }
    if (assignedAdminId) {
      const [admins] = await db.query('SELECT id FROM admin_users WHERE id = ? AND is_active = 1', [assignedAdminId]);
      if (admins.length === 0) {
        return res.status(404).json({ error: 'Assigned admin not found' });
      }
    }
    fields.push('assigned_admin_id = ?');
    values.push(assignedAdminId || null);
  }
  if (resolutionNotes !== undefined) {
    fields.push('resolution_notes = ?');
    values.push(resolutionNotes || null);
  }

  fields.push('updated_at = NOW()');

  try {
    const [result] = await db.query(`UPDATE disputes SET ${fields.join(', ')} WHERE id = ?`, [...values, id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Dispute not found' });
    }

    const [rows] = await db.query('SELECT * FROM disputes WHERE id = ?', [id]);
    return res.json(rows[0]);
  } catch (err) {
    console.error('Update dispute error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.addDisputeComment = async (req, res) => {
  const { id } = req.params;
  const { comment, isInternal } = req.body;
  if (!isUuid(id)) {
    return res.status(400).json({ error: 'Invalid dispute id' });
  }
  if (!comment || typeof comment !== 'string' || !comment.trim()) {
    return res.status(400).json({ error: 'comment is required' });
  }

  try {
    const [disputes] = await db.query('SELECT id FROM disputes WHERE id = ?', [id]);
    if (disputes.length === 0) {
      return res.status(404).json({ error: 'Dispute not found' });
    }

    const commentId = uuidv4();
    await db.query(
      `INSERT INTO dispute_comments (id, dispute_id, author_type, author_id, is_internal, comment, created_at)
       VALUES (?, ?, 'admin', ?, ?, ?, NOW())`,
      [commentId, id, req.admin.id, isInternal === undefined ? 1 : (isInternal ? 1 : 0), comment.trim()]
    );

    const [rows] = await db.query(
      `SELECT id, dispute_id, author_type, author_id, is_internal, comment, created_at
       FROM dispute_comments WHERE id = ?`,
      [commentId]
    );

    return res.status(201).json(rows[0]);
  } catch (err) {
    console.error('Add dispute comment error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.resolveDispute = async (req, res) => {
  const { id } = req.params;
  const { resolutionNotes } = req.body;

  if (!isUuid(id)) {
    return res.status(400).json({ error: 'Invalid dispute id' });
  }
  if (!resolutionNotes || typeof resolutionNotes !== 'string' || !resolutionNotes.trim()) {
    return res.status(400).json({ error: 'resolutionNotes is required' });
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    const [rows] = await connection.query(
      'SELECT id, status, assigned_admin_id FROM disputes WHERE id = ? FOR UPDATE',
      [id]
    );
    if (rows.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Dispute not found' });
    }

    const dispute = rows[0];
    if (!['open', 'investigating'].includes(dispute.status)) {
      await connection.rollback();
      return res.status(400).json({ error: `Cannot resolve dispute in '${dispute.status}' status` });
    }

    await connection.query(
      `UPDATE disputes
       SET status = 'resolved',
           resolution_notes = ?,
           resolved_at = NOW(),
           assigned_admin_id = COALESCE(assigned_admin_id, ?),
           updated_at = NOW()
       WHERE id = ?`,
      [resolutionNotes.trim(), req.admin.id, id]
    );

    await connection.query(
      `INSERT INTO dispute_comments (id, dispute_id, author_type, author_id, is_internal, comment, created_at)
       VALUES (?, ?, 'admin', ?, 1, ?, NOW())`,
      [uuidv4(), id, req.admin.id, `Resolved: ${resolutionNotes.trim()}`]
    );

    const [updated] = await connection.query('SELECT * FROM disputes WHERE id = ?', [id]);
    await connection.commit();
    return res.json({
      message: 'Dispute resolved successfully',
      dispute: updated[0],
    });
  } catch (err) {
    await connection.rollback();
    console.error('Resolve dispute error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
};

exports.listAuditLogs = async (req, res) => {
  const { page, limit, offset } = parsePaging(req);
  const where = [];
  const values = [];

  if (req.query.action) {
    where.push('action = ?');
    values.push(String(req.query.action));
  }
  if (req.query.method) {
    where.push('method = ?');
    values.push(String(req.query.method).toUpperCase());
  }
  if (req.query.statusCode) {
    const statusCode = toInt(req.query.statusCode);
    if (statusCode === null) {
      return res.status(400).json({ error: 'statusCode must be an integer' });
    }
    where.push('status_code = ?');
    values.push(statusCode);
  }
  if (req.query.requestId) {
    where.push('request_id = ?');
    values.push(String(req.query.requestId));
  }
  if (req.query.from) {
    const fromDate = new Date(req.query.from);
    if (Number.isNaN(fromDate.getTime())) {
      return res.status(400).json({ error: 'Invalid from datetime' });
    }
    where.push('created_at >= ?');
    values.push(fromDate);
  }
  if (req.query.to) {
    const toDate = new Date(req.query.to);
    if (Number.isNaN(toDate.getTime())) {
      return res.status(400).json({ error: 'Invalid to datetime' });
    }
    where.push('created_at <= ?');
    values.push(toDate);
  }

  const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';

  try {
    const [countRows] = await db.query(
      `SELECT COUNT(*) AS total
       FROM audit_logs
       ${whereClause}`,
      values
    );

    const [rows] = await db.query(
      `SELECT id, admin_key_hash, action, method, path, status_code, ip_address, user_agent, entity_id, duration_ms, request_id, created_at
       FROM audit_logs
       ${whereClause}
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [...values, limit, offset]
    );

    return res.json({
      page,
      limit,
      total: countRows[0].total,
      logs: rows,
    });
  } catch (err) {
    console.error('List audit logs error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.dashboard = async (req, res) => {
  try {
    const [[usersRow]] = await db.query(
      `SELECT
         COUNT(*) AS total_users,
         SUM(CASE WHEN verified = 1 THEN 1 ELSE 0 END) AS verified_users,
         SUM(CASE WHEN is_suspended = 1 THEN 1 ELSE 0 END) AS suspended_users
       FROM users`
    );
    const [[ordersRow]] = await db.query(
      `SELECT
         COUNT(*) AS total_orders,
         SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending_orders,
         COALESCE(SUM(total_amount), 0) AS gross_order_value
       FROM orders`
    );
    const [[disputesRow]] = await db.query(
      `SELECT
         COUNT(*) AS total_disputes,
         SUM(CASE WHEN status IN ('open', 'investigating') THEN 1 ELSE 0 END) AS active_disputes
       FROM disputes`
    );

    return res.json({
      users: usersRow,
      orders: ordersRow,
      disputes: disputesRow,
      generatedAt: new Date().toISOString(),
    });
  } catch (err) {
    console.error('Admin dashboard error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};
