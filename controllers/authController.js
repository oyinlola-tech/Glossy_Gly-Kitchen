const db = require('../config/db');
const { v4: uuidv4 } = require('uuid');
const generateOtp = require('../utils/generateOtp');
const { generateUniqueReferralCode, validateReferralCode } = require('../utils/referralHelper');
const { isValidEmail, isValidPhone, isUuid } = require('../utils/validation');
const jwt = require('jsonwebtoken');
const { validatePassword, hashPassword, comparePassword } = require('../utils/password');
const { createRefreshToken, hashToken, refreshExpiryDate } = require('../utils/tokens');
const { sendMail } = require('../utils/mailer');
const { isLocked, recordFailure, clearFailures } = require('../utils/otpGuard');
const { verifyGoogleIdToken, verifyAppleIdentityToken } = require('../utils/socialAuth');
const {
  buildSignupVerificationEmail,
  buildLoginOtpEmail,
  buildPasswordResetOtpEmail,
  buildPasswordChangedEmail,
  buildNewDeviceLoginAlertEmail,
  buildWelcomeEmail,
  buildAccountDeletionOtpEmail,
  buildAccountDeletedGoodbyeEmail,
} = require('../utils/emailTemplates');

const DUMMY_PASSWORD_HASH = '$2a$10$7EqJtq98hPqEX7fNZaFWoOaJY8fDeihh5Z8SGvtQvE4H14R/2uOe';
const REFRESH_TOKEN_REGEX = /^[a-f0-9]{96}$/i;
const PASSWORD_RESET_SESSION_MINUTES = Number(process.env.PASSWORD_RESET_SESSION_MINUTES) > 0
  ? Number(process.env.PASSWORD_RESET_SESSION_MINUTES)
  : 15;

const isMissingTableError = (err) => {
  return Boolean(err && (err.code === 'ER_NO_SUCH_TABLE' || err.errno === 1146));
};

const runDeleteIfTableExists = async (connection, sql, params = []) => {
  try {
    await connection.query(sql, params);
  } catch (err) {
    if (isMissingTableError(err)) return;
    throw err;
  }
};

const normalizeRefreshToken = (value) => {
  if (typeof value !== 'string') return null;
  const token = value.trim();
  if (!REFRESH_TOKEN_REGEX.test(token)) return null;
  return token;
};

const getDeviceFingerprint = (req, bodyDeviceId) => {
  const source = req.get('x-device-id') || bodyDeviceId || req.get('user-agent') || 'unknown-device';
  return hashToken(String(source).slice(0, 512));
};

const issueAccessToken = (user) => {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('JWT secret not configured');
  }
  return jwt.sign(
    { sub: user.id, email: user.email || null, typ: 'access' },
    secret,
    { expiresIn: process.env.JWT_EXPIRES_IN, issuer: process.env.JWT_ISSUER }
  );
};

const issueRefreshToken = async (userId, req, queryable = db) => {
  const token = createRefreshToken();
  const tokenHash = hashToken(token);
  const expiresAt = refreshExpiryDate();

  await queryable.query(
    `INSERT INTO refresh_tokens
     (id, user_id, token_hash, expires_at, created_ip, user_agent, created_at)
     VALUES (?, ?, ?, ?, ?, ?, NOW())`,
    [
      uuidv4(),
      userId,
      tokenHash,
      expiresAt,
      req.ip,
      req.get('user-agent') || null,
    ]
  );

  return token;
};

const issueTokens = async (user, req, queryable = db) => {
  const accessToken = issueAccessToken(user);
  const refreshToken = await issueRefreshToken(user.id, req, queryable);
  return { accessToken, refreshToken };
};

// -------------------- Helper: Send OTP Email --------------------
const sendOtpEmail = async (email, otp) => {
  const template = buildSignupVerificationEmail({ otp });
  await sendMail({ to: email, subject: template.subject, html: template.html, text: template.text });
};

const sendLoginOtpEmail = async (email, otp) => {
  const template = buildLoginOtpEmail({ otp });
  await sendMail({ to: email, subject: template.subject, html: template.html, text: template.text });
};

const sendPasswordResetOtpEmail = async (email, otp) => {
  const template = buildPasswordResetOtpEmail({ otp });
  await sendMail({ to: email, subject: template.subject, html: template.html, text: template.text });
};

const sendPasswordChangedEmail = async ({ email, req }) => {
  if (!email) return;
  const template = buildPasswordChangedEmail({
    ip: req.ip,
    userAgent: req.get('user-agent') || null,
    changedAt: new Date().toISOString(),
  });
  await sendMail({ to: email, subject: template.subject, html: template.html, text: template.text });
};

const sendNewDeviceLoginAlert = async ({ email, req }) => {
  if (!email) return;
  const template = buildNewDeviceLoginAlertEmail({
    ip: req.ip,
    userAgent: req.get('user-agent') || null,
    loginAt: new Date().toISOString(),
  });
  await sendMail({ to: email, subject: template.subject, html: template.html, text: template.text });
};

const sendWelcomeEmail = async ({ email }) => {
  if (!email) return;
  const template = buildWelcomeEmail({ email });
  await sendMail({ to: email, subject: template.subject, html: template.html, text: template.text });
};

const sendAccountDeletionOtpEmail = async ({ email, otp }) => {
  if (!email) return;
  const template = buildAccountDeletionOtpEmail({ otp });
  await sendMail({ to: email, subject: template.subject, html: template.html, text: template.text });
};

const sendAccountDeletedGoodbyeEmail = async ({ email }) => {
  if (!email) return;
  const template = buildAccountDeletedGoodbyeEmail({ email });
  await sendMail({ to: email, subject: template.subject, html: template.html, text: template.text });
};

const registerUserDeviceLogin = async ({ user, req, deviceId }) => {
  if (!user || !user.id) return { isNewDeviceOrIp: false };

  try {
    const deviceHash = getDeviceFingerprint(req, deviceId);
    const [rows] = await db.query(
      'SELECT id, last_ip FROM user_trusted_devices WHERE user_id = ? AND device_hash = ? LIMIT 1',
      [user.id, deviceHash]
    );

    const isNewDevice = rows.length === 0;
    const isIpChanged = rows.length > 0 && rows[0].last_ip && rows[0].last_ip !== req.ip;
    const isNewDeviceOrIp = isNewDevice || isIpChanged;

    await db.query(
      `INSERT INTO user_trusted_devices
       (id, user_id, device_hash, last_ip, last_user_agent, last_seen_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, NOW(), NOW(), NOW())
       ON DUPLICATE KEY UPDATE
         last_ip = VALUES(last_ip),
         last_user_agent = VALUES(last_user_agent),
         last_seen_at = NOW(),
         updated_at = NOW()`,
      [
        uuidv4(),
        user.id,
        deviceHash,
        req.ip,
        req.get('user-agent') || null,
      ]
    );

    return { isNewDeviceOrIp };
  } catch (err) {
    if (isMissingTableError(err)) {
      console.warn('user_trusted_devices table not found. Skipping new-device detection.');
      return { isNewDeviceOrIp: false };
    }
    throw err;
  }
};

const createPasswordResetSession = async (connection, userId) => {
  const token = createRefreshToken();
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + PASSWORD_RESET_SESSION_MINUTES * 60 * 1000);

  await connection.query(
    `INSERT INTO user_password_reset_sessions
     (id, user_id, token_hash, expires_at, consumed_at, created_at)
     VALUES (?, ?, ?, ?, NULL, NOW())`,
    [uuidv4(), userId, tokenHash, expiresAt]
  );

  return { token, expiresAt };
};

const normalizeSocialEmail = (value) => {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  if (!email || !isValidEmail(email)) return null;
  return email;
};

const normalizeEmailVerified = (value) => {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') return value.toLowerCase() === 'true';
  return false;
};

const loadSocialUser = async (connection, provider, providerUserId) => {
  const [rows] = await connection.query(
    `SELECT u.id, u.email, u.verified, u.is_suspended
     FROM user_social_accounts usa
     JOIN users u ON u.id = usa.user_id
     WHERE usa.provider = ? AND usa.provider_user_id = ?
     LIMIT 1`,
    [provider, providerUserId]
  );
  return rows[0] || null;
};

const loadUserByEmail = async (connection, email) => {
  if (!email) return null;
  const [rows] = await connection.query(
    'SELECT id, email, verified, is_suspended FROM users WHERE email = ? LIMIT 1',
    [email]
  );
  return rows[0] || null;
};

const upsertSocialAccount = async (connection, { userId, provider, providerUserId, email, emailVerified }) => {
  await connection.query(
    `INSERT INTO user_social_accounts
     (id, user_id, provider, provider_user_id, email, email_verified, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())
     ON DUPLICATE KEY UPDATE
       email = VALUES(email),
       email_verified = VALUES(email_verified),
       updated_at = NOW()`,
    [
      uuidv4(),
      userId,
      provider,
      providerUserId,
      email || null,
      emailVerified ? 1 : 0,
    ]
  );
};

const handleSocialLogin = async ({
  provider,
  providerUserId,
  email,
  emailVerified,
  referralCode,
  req,
  deviceId,
}) => {
  const connection = await db.getConnection();
  let user = null;
  let created = false;

  try {
    await connection.beginTransaction();

    user = await loadSocialUser(connection, provider, providerUserId);
    if (!user) {
      user = await loadUserByEmail(connection, email);
    }

    if (user && user.is_suspended) {
      await connection.rollback();
      return { error: { status: 403, message: 'Account is suspended' } };
    }

    if (!user) {
      const userId = uuidv4();
      const referredBy = await validateReferralCode(connection, referralCode);
      const newReferralCode = await generateUniqueReferralCode(connection);

      await connection.query(
        `INSERT INTO users
         (id, email, phone, password_hash, referral_code, referred_by, verified, otp_code, otp_expires, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NOW(), NOW())`,
        [userId, email || null, null, null, newReferralCode, referredBy, true]
      );

      user = { id: userId, email: email || null, verified: true, is_suspended: false };
      created = true;
    } else {
      const updates = [];
      const values = [];
      if (!user.verified) {
        updates.push('verified = 1');
        updates.push('otp_code = NULL');
        updates.push('otp_expires = NULL');
        user.verified = true;
      }
      if (email && !user.email) {
        updates.push('email = ?');
        values.push(email);
        user.email = email;
      }
      if (updates.length) {
        updates.push('updated_at = NOW()');
        await connection.query(
          `UPDATE users SET ${updates.join(', ')} WHERE id = ?`,
          [...values, user.id]
        );
      }
    }

    await upsertSocialAccount(connection, {
      userId: user.id,
      provider,
      providerUserId,
      email,
      emailVerified,
    });

    await connection.commit();
  } catch (err) {
    await connection.rollback();
    if (isMissingTableError(err)) {
      return { error: { status: 503, message: 'Social sign-in unavailable. Apply latest migrations.' } };
    }
    throw err;
  } finally {
    connection.release();
  }

  const tokens = await issueTokens(user, req);
  const deviceState = await registerUserDeviceLogin({ user, req, deviceId });
  if (deviceState.isNewDeviceOrIp) {
    sendNewDeviceLoginAlert({ email: user.email, req }).catch((err) => {
      console.error('New device login email failed:', err.message);
    });
  }
  if (created && user.email) {
    sendWelcomeEmail({ email: user.email }).catch((err) => {
      console.error('Welcome email failed:', err.message);
    });
  }

  return { tokens };
};

// -------------------- POST /signup --------------------
exports.signup = async (req, res) => {
  const { email, phone, referralCode, password } = req.body;

  // Validation
  if (!email && !phone) {
    return res.status(400).json({ error: 'Email or phone number is required' });
  }
  if (email && !isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }
  if (phone && !isValidPhone(phone)) {
    return res.status(400).json({ error: 'Invalid phone number' });
  }
  if (!email && phone) {
    return res.status(400).json({ error: 'Phone signup is not supported yet' });
  }
  const passwordError = validatePassword(password);
  if (passwordError) {
    return res.status(400).json({ error: passwordError });
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    // 1. Check for duplicate email/phone
    const [existing] = await connection.query(
      'SELECT id FROM users WHERE email = ? OR phone = ?',
      [email || null, phone || null]
    );
    if (existing.length) {
      await connection.rollback();
      return res.status(409).json({ error: 'Email or phone already registered' });
    }

    // 2. Validate referral code (if provided)
    const referredBy = await validateReferralCode(connection, referralCode);

    // 3. Create new user (unverified)
    const userId = uuidv4();
    const otp = generateOtp();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    const newReferralCode = await generateUniqueReferralCode(connection);
    const passwordHash = await hashPassword(password);

    await connection.query(
      `INSERT INTO users (id, email, phone, password_hash, referral_code, referred_by, verified, otp_code, otp_expires, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
      [userId, email || null, phone || null, passwordHash, newReferralCode, referredBy, false, otp, otpExpires]
    );

    // 4. Send OTP via email (if email provided)
    if (email) {
      try {
        await sendOtpEmail(email, otp);
        console.log(`OTP sent to ${email}`);
      } catch (emailErr) {
        console.error('Failed to send OTP email:', emailErr.message);
        // Rollback user creation if email fails? Business decision: we proceed but warn.
        // For strict flow, rollback:
        await connection.rollback();
        return res.status(500).json({ error: 'Failed to send verification email. Try again.' });
      }
    }

    await connection.commit();

    const response = {
      message: 'User registered successfully. Please verify your account.',
      userId,
    };
    res.status(201).json(response);

  } catch (err) {
    await connection.rollback();
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
};

// -------------------- POST /verify --------------------
exports.verify = async (req, res) => {
  const { userId, otp } = req.body;
  const userIdValue = typeof userId === 'string' ? userId.trim() : '';
  const otpValue = typeof otp === 'string' ? otp.trim() : '';

  if (!userIdValue || !otpValue) {
    return res.status(400).json({ error: 'userId and otp are required' });
  }
  if (!isUuid(userIdValue)) {
    return res.status(400).json({ error: 'Invalid userId' });
  }
  if (!/^\d{6}$/.test(otpValue)) {
    return res.status(400).json({ error: 'Invalid or expired OTP' });
  }

  const lockState = isLocked('verify', userIdValue);
  if (lockState.locked) {
    res.setHeader('Retry-After', String(lockState.retryAfterSec));
    return res.status(429).json({ error: 'Too many invalid OTP attempts. Try again later.' });
  }

  try {
    // Find user with matching OTP and not expired
    const [users] = await db.query(
      `SELECT id, email FROM users 
       WHERE id = ? AND verified = 0 AND otp_code = ? AND otp_expires > NOW()`,
      [userIdValue, otpValue]
    );

    if (users.length === 0) {
      const afterFailure = recordFailure('verify', userIdValue);
      if (afterFailure.locked) {
        res.setHeader('Retry-After', String(afterFailure.retryAfterSec));
        return res.status(429).json({ error: 'Too many invalid OTP attempts. Try again later.' });
      }
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    // Mark user as verified and clear OTP fields
    await db.query(
      `UPDATE users SET verified = 1, otp_code = NULL, otp_expires = NULL, updated_at = NOW()
       WHERE id = ?`,
      [userIdValue]
    );

    clearFailures('verify', userIdValue);
    const tokens = await issueTokens({ id: userIdValue, email: users[0].email }, req);
    sendWelcomeEmail({ email: users[0].email }).catch((err) => {
      console.error('Welcome email failed:', err.message);
    });
    res.json({ message: 'Account verified successfully.', ...tokens });

  } catch (err) {
    console.error('Verification error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- POST /resend-otp (Bonus) --------------------
exports.resendOtp = async (req, res) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  try {
    // Only allow OTP resend for unverified accounts
    const [users] = await db.query(
      'SELECT id, verified FROM users WHERE email = ?',
      [email]
    );
    if (users.length === 0 || users[0].verified) {
      return res.json({ message: 'If an unverified account exists, OTP has been sent' });
    }

    const userId = users[0].id;
    const otp = generateOtp();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

    await db.query(
      'UPDATE users SET otp_code = ?, otp_expires = ?, updated_at = NOW() WHERE id = ?',
      [otp, otpExpires, userId]
    );

    await sendOtpEmail(email, otp);
    console.log(`OTP resent to ${email}`);

    res.json({ message: 'If an unverified account exists, OTP has been sent' });

  } catch (err) {
    console.error('Resend OTP error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- POST /auth/google --------------------
exports.googleSignIn = async (req, res) => {
  const idToken = typeof req.body.idToken === 'string' ? req.body.idToken.trim() : '';
  const { deviceId, referralCode } = req.body || {};

  if (!idToken) {
    return res.status(400).json({ error: 'idToken is required' });
  }

  try {
    const payload = await verifyGoogleIdToken(idToken);
    const providerUserId = payload && payload.sub ? String(payload.sub) : '';
    if (!providerUserId) {
      return res.status(401).json({ error: 'Invalid Google token' });
    }

    const email = normalizeSocialEmail(payload.email);
    const emailVerified = normalizeEmailVerified(payload.email_verified);

    const result = await handleSocialLogin({
      provider: 'google',
      providerUserId,
      email,
      emailVerified,
      referralCode,
      req,
      deviceId,
    });

    if (result.error) {
      return res.status(result.error.status).json({ error: result.error.message });
    }

    return res.json({ message: 'Login successful', ...result.tokens });
  } catch (err) {
    if (err && err.code === 'SOCIAL_CONFIG_MISSING') {
      return res.status(503).json({ error: err.message });
    }
    console.error('Google sign-in error:', err);
    return res.status(401).json({ error: 'Invalid Google token' });
  }
};

// -------------------- POST /auth/apple --------------------
exports.appleSignIn = async (req, res) => {
  const identityToken = typeof req.body.identityToken === 'string' ? req.body.identityToken.trim() : '';
  const { deviceId, referralCode } = req.body || {};

  if (!identityToken) {
    return res.status(400).json({ error: 'identityToken is required' });
  }

  try {
    const payload = await verifyAppleIdentityToken(identityToken);
    const providerUserId = payload && payload.sub ? String(payload.sub) : '';
    if (!providerUserId) {
      return res.status(401).json({ error: 'Invalid Apple token' });
    }

    const email = normalizeSocialEmail(payload.email);
    const emailVerified = normalizeEmailVerified(payload.email_verified);

    const result = await handleSocialLogin({
      provider: 'apple',
      providerUserId,
      email,
      emailVerified,
      referralCode,
      req,
      deviceId,
    });

    if (result.error) {
      return res.status(result.error.status).json({ error: result.error.message });
    }

    return res.json({ message: 'Login successful', ...result.tokens });
  } catch (err) {
    if (err && err.code === 'SOCIAL_CONFIG_MISSING') {
      return res.status(503).json({ error: err.message });
    }
    console.error('Apple sign-in error:', err);
    return res.status(401).json({ error: 'Invalid Apple token' });
  }
};

// -------------------- POST /login --------------------
exports.login = async (req, res) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const { password, deviceId } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  try {
    const [users] = await db.query(
      `SELECT id, email, verified, password_hash, is_suspended
       FROM users WHERE email = ?`,
      [email]
    );

    if (users.length === 0) {
      await comparePassword(password, DUMMY_PASSWORD_HASH);
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const user = users[0];
    const passwordMatches = await comparePassword(password, user.password_hash || DUMMY_PASSWORD_HASH);
    if (!passwordMatches) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    if (!user.verified || user.is_suspended) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const deviceState = await registerUserDeviceLogin({ user, req, deviceId });
    if (deviceState.isNewDeviceOrIp) {
      sendNewDeviceLoginAlert({ email: user.email, req }).catch((err) => {
        console.error('New device login email failed:', err.message);
      });
    }

    const tokens = await issueTokens(user, req);
    res.json({ message: 'Login successful', ...tokens });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- POST /request-login-otp --------------------
exports.requestLoginOtp = async (req, res) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const genericMessage = 'If an active account exists, OTP has been sent';

  if (!email) {
    return res.status(400).json({ error: 'email is required' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  try {
    const [users] = await db.query(
      `SELECT id, email, verified, is_suspended
       FROM users WHERE email = ?`,
      [email]
    );

    if (users.length === 0 || !users[0].verified || users[0].is_suspended) {
      return res.json({ message: genericMessage });
    }

    const user = users[0];
    const otp = generateOtp();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

    await db.query(
      'UPDATE users SET otp_code = ?, otp_expires = ?, updated_at = NOW() WHERE id = ?',
      [otp, otpExpires, user.id]
    );
    await sendLoginOtpEmail(user.email, otp);

    return res.json({ message: genericMessage });
  } catch (err) {
    console.error('Request login OTP error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- POST /forgot-password/request --------------------
exports.requestPasswordResetOtp = async (req, res) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const genericMessage = 'If an active account exists, password reset OTP has been sent';

  if (!email) {
    return res.status(400).json({ error: 'email is required' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  try {
    const [users] = await db.query(
      'SELECT id, email, verified, is_suspended FROM users WHERE email = ?',
      [email]
    );
    if (users.length === 0 || !users[0].verified || users[0].is_suspended) {
      return res.json({ message: genericMessage });
    }

    const user = users[0];
    const otp = generateOtp();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

    await db.query(
      `UPDATE user_password_reset_otps
       SET consumed_at = NOW()
       WHERE user_id = ? AND consumed_at IS NULL`,
      [user.id]
    );
    await db.query(
      `INSERT INTO user_password_reset_otps (id, user_id, otp_code, otp_expires, consumed_at, created_at)
       VALUES (?, ?, ?, ?, NULL, NOW())`,
      [uuidv4(), user.id, otp, otpExpires]
    );

    await sendPasswordResetOtpEmail(user.email, otp);
    return res.json({ message: genericMessage });
  } catch (err) {
    if (isMissingTableError(err)) {
      return res.status(503).json({ error: 'Password reset service unavailable. Apply latest migrations.' });
    }
    console.error('Request password reset OTP error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- POST /forgot-password/verify --------------------
exports.verifyPasswordResetOtp = async (req, res) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const otp = typeof req.body.otp === 'string' ? req.body.otp.trim() : '';
  const lockIdentity = `forgot-password:${email}`;

  if (!email || !otp) {
    return res.status(400).json({ error: 'email and otp are required' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }
  if (!/^\d{6}$/.test(otp)) {
    return res.status(400).json({ error: 'Invalid or expired OTP' });
  }

  const lockState = isLocked('forgot-password', lockIdentity);
  if (lockState.locked) {
    res.setHeader('Retry-After', String(lockState.retryAfterSec));
    return res.status(429).json({ error: 'Too many invalid OTP attempts. Try again later.' });
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    const [users] = await connection.query(
      `SELECT id, email, verified, is_suspended
       FROM users
       WHERE email = ?
       FOR UPDATE`,
      [email]
    );
    if (users.length === 0 || !users[0].verified || users[0].is_suspended) {
      await connection.rollback();
      const fail = recordFailure('forgot-password', lockIdentity);
      if (fail.locked) {
        res.setHeader('Retry-After', String(fail.retryAfterSec));
        return res.status(429).json({ error: 'Too many invalid OTP attempts. Try again later.' });
      }
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    const user = users[0];
    const [otpRows] = await connection.query(
      `SELECT id, otp_code, otp_expires
       FROM user_password_reset_otps
       WHERE user_id = ? AND consumed_at IS NULL
       ORDER BY created_at DESC
       LIMIT 1
       FOR UPDATE`,
      [user.id]
    );

    if (
      otpRows.length === 0 ||
      otpRows[0].otp_code !== otp ||
      !otpRows[0].otp_expires ||
      new Date(otpRows[0].otp_expires) <= new Date()
    ) {
      await connection.rollback();
      const fail = recordFailure('forgot-password', lockIdentity);
      if (fail.locked) {
        res.setHeader('Retry-After', String(fail.retryAfterSec));
        return res.status(429).json({ error: 'Too many invalid OTP attempts. Try again later.' });
      }
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    await connection.query(
      'UPDATE user_password_reset_otps SET consumed_at = NOW() WHERE id = ?',
      [otpRows[0].id]
    );

    await connection.query(
      'UPDATE user_password_reset_sessions SET consumed_at = NOW() WHERE user_id = ? AND consumed_at IS NULL',
      [user.id]
    );
    const session = await createPasswordResetSession(connection, user.id);

    await connection.commit();
    clearFailures('forgot-password', lockIdentity);

    return res.json({
      message: 'OTP verified successfully',
      resetToken: session.token,
      expiresInSeconds: PASSWORD_RESET_SESSION_MINUTES * 60,
    });
  } catch (err) {
    await connection.rollback();
    if (isMissingTableError(err)) {
      return res.status(503).json({ error: 'Password reset service unavailable. Apply latest migrations.' });
    }
    console.error('Verify password reset OTP error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
};

// -------------------- POST /forgot-password/reset --------------------
exports.resetPasswordWithToken = async (req, res) => {
  const resetToken = normalizeRefreshToken(req.body && req.body.resetToken);
  const newPassword = req.body && req.body.newPassword;

  if (!resetToken) {
    return res.status(400).json({ error: 'Valid resetToken is required' });
  }
  const passwordError = validatePassword(newPassword);
  if (passwordError) {
    return res.status(400).json({ error: passwordError });
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    const tokenHash = hashToken(resetToken);
    const [sessions] = await connection.query(
      `SELECT id, user_id, expires_at, consumed_at
       FROM user_password_reset_sessions
       WHERE token_hash = ?
       FOR UPDATE`,
      [tokenHash]
    );
    if (sessions.length === 0) {
      await connection.rollback();
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    const session = sessions[0];
    if (session.consumed_at || !session.expires_at || new Date(session.expires_at) <= new Date()) {
      await connection.rollback();
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    const [users] = await connection.query(
      'SELECT id, email, password_hash FROM users WHERE id = ? FOR UPDATE',
      [session.user_id]
    );
    if (users.length === 0) {
      await connection.rollback();
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    const user = users[0];
    const samePassword = await comparePassword(newPassword, user.password_hash || DUMMY_PASSWORD_HASH);
    if (samePassword) {
      await connection.rollback();
      return res.status(400).json({ error: 'New password must be different from current password' });
    }

    const newPasswordHash = await hashPassword(newPassword);
    await connection.query(
      'UPDATE users SET password_hash = ?, updated_at = NOW() WHERE id = ?',
      [newPasswordHash, user.id]
    );
    await connection.query(
      'UPDATE user_password_reset_sessions SET consumed_at = NOW() WHERE id = ?',
      [session.id]
    );
    await connection.query(
      'UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = ? AND revoked_at IS NULL',
      [user.id]
    );

    await connection.commit();
    sendPasswordChangedEmail({ email: user.email, req }).catch((err) => {
      console.error('Password reset success email failed:', err.message);
    });

    return res.json({ message: 'Password reset successful. Please login again.' });
  } catch (err) {
    await connection.rollback();
    if (isMissingTableError(err)) {
      return res.status(503).json({ error: 'Password reset service unavailable. Apply latest migrations.' });
    }
    console.error('Reset password with token error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
};

// -------------------- POST /login-otp --------------------
exports.loginOtp = async (req, res) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const otpValue = typeof req.body.otp === 'string' ? req.body.otp.trim() : '';
  const deviceId = req.body && req.body.deviceId;

  if (!email || !otpValue) {
    return res.status(400).json({ error: 'email and otp are required' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }
  if (!/^\d{6}$/.test(otpValue)) {
    return res.status(400).json({ error: 'Invalid or expired OTP' });
  }

  const identity = email.trim().toLowerCase();
  const lockState = isLocked('login-otp', identity);
  if (lockState.locked) {
    res.setHeader('Retry-After', String(lockState.retryAfterSec));
    return res.status(429).json({ error: 'Too many invalid OTP attempts. Try again later.' });
  }

  try {
    const [users] = await db.query(
      `SELECT id, email, verified, otp_code, otp_expires, is_suspended
       FROM users WHERE email = ?`,
      [email]
    );

    if (users.length === 0) {
      const afterFailure = recordFailure('login-otp', identity);
      if (afterFailure.locked) {
        res.setHeader('Retry-After', String(afterFailure.retryAfterSec));
        return res.status(429).json({ error: 'Too many invalid OTP attempts. Try again later.' });
      }
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    const user = users[0];
    if (!user.verified || user.is_suspended) {
      const afterFailure = recordFailure('login-otp', identity);
      if (afterFailure.locked) {
        res.setHeader('Retry-After', String(afterFailure.retryAfterSec));
        return res.status(429).json({ error: 'Too many invalid OTP attempts. Try again later.' });
      }
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    if (!user.otp_code || user.otp_code !== otpValue || !user.otp_expires || user.otp_expires <= new Date()) {
      const afterFailure = recordFailure('login-otp', identity);
      if (afterFailure.locked) {
        res.setHeader('Retry-After', String(afterFailure.retryAfterSec));
        return res.status(429).json({ error: 'Too many invalid OTP attempts. Try again later.' });
      }
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    await db.query(
      'UPDATE users SET otp_code = NULL, otp_expires = NULL, updated_at = NOW() WHERE id = ?',
      [user.id]
    );

    clearFailures('login-otp', identity);
    const deviceState = await registerUserDeviceLogin({ user, req, deviceId });
    if (deviceState.isNewDeviceOrIp) {
      sendNewDeviceLoginAlert({ email: user.email, req }).catch((err) => {
        console.error('New device login email failed:', err.message);
      });
    }

    const tokens = await issueTokens(user, req);
    res.json({ message: 'Login successful', ...tokens });
  } catch (err) {
    console.error('Login OTP error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- POST /refresh --------------------
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
      `SELECT id, user_id, expires_at, revoked_at
       FROM refresh_tokens
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

    // Revoke old token
    await connection.query(
      'UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = ?',
      [tokenRow.id]
    );

    const [users] = await connection.query(
      'SELECT id, email, verified, is_suspended FROM users WHERE id = ? FOR UPDATE',
      [tokenRow.user_id]
    );
    if (users.length === 0 || !users[0].verified) {
      await connection.rollback();
      return res.status(401).json({ error: 'Invalid user' });
    }
    if (users[0].is_suspended) {
      await connection.rollback();
      return res.status(403).json({ error: 'Account is suspended' });
    }

    const tokens = await issueTokens(users[0], req, connection);
    await connection.commit();
    res.json({ message: 'Token refreshed', ...tokens });
  } catch (err) {
    await connection.rollback();
    console.error('Refresh error:', err);
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
};

// -------------------- POST /logout --------------------
exports.logout = async (req, res) => {
  const refreshToken = normalizeRefreshToken(req.body && req.body.refreshToken);
  const userId = req.user && req.user.id;
  if (!userId || !isUuid(userId)) {
    return res.status(401).json({ error: 'Authorization token required' });
  }
  if (!refreshToken) {
    return res.status(400).json({ error: 'Valid refreshToken is required' });
  }

  try {
    const tokenHash = hashToken(refreshToken);
    await db.query(
      'UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = ? AND user_id = ?',
      [tokenHash, userId]
    );
    return res.json({ message: 'Logged out' });
  } catch (err) {
    console.error('Logout error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- POST /logout-all --------------------
exports.logoutAll = async (req, res) => {
  const userId = req.user && req.user.id;
  if (!userId || !isUuid(userId)) {
    return res.status(401).json({ error: 'Authorization token required' });
  }

  try {
    await db.query(
      'UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = ? AND revoked_at IS NULL',
      [userId]
    );
    return res.json({ message: 'All sessions logged out' });
  } catch (err) {
    console.error('Logout all error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- GET /auth/me --------------------
exports.me = async (req, res) => {
  const userId = req.user && req.user.id;
  if (!userId) {
    return res.status(401).json({ error: 'Authorization token required' });
  }

  try {
    const [users] = await db.query(
      `SELECT id, email, phone, verified, is_suspended, created_at, updated_at
       FROM users
       WHERE id = ?`,
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.json(users[0]);
  } catch (err) {
    console.error('Get profile error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- PATCH /auth/me --------------------
exports.updateMe = async (req, res) => {
  const userId = req.user && req.user.id;
  const { phone, currentPassword, newPassword } = req.body;

  if (!userId) {
    return res.status(401).json({ error: 'Authorization token required' });
  }

  const wantsPhoneUpdate = phone !== undefined;
  const wantsPasswordUpdate = currentPassword !== undefined || newPassword !== undefined;

  if (!wantsPhoneUpdate && !wantsPasswordUpdate) {
    return res.status(400).json({ error: 'No profile fields provided for update' });
  }

  if (wantsPasswordUpdate) {
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'currentPassword and newPassword are required for password change' });
    }
    const passwordError = validatePassword(newPassword);
    if (passwordError) {
      return res.status(400).json({ error: passwordError });
    }
    if (currentPassword === newPassword) {
      return res.status(400).json({ error: 'New password must be different from current password' });
    }
  }

  if (wantsPhoneUpdate && phone !== null && phone !== '' && !isValidPhone(phone)) {
    return res.status(400).json({ error: 'Invalid phone number' });
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    const [users] = await connection.query(
      'SELECT id, email, phone, password_hash FROM users WHERE id = ?',
      [userId]
    );
    if (users.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'User not found' });
    }

    const user = users[0];
    const userEmail = user.email;
    const fields = [];
    const values = [];
    let passwordChanged = false;

    if (wantsPhoneUpdate) {
      const normalizedPhone = phone === null || phone === '' ? null : String(phone).trim();
      if (normalizedPhone) {
        const [dup] = await connection.query(
          'SELECT id FROM users WHERE phone = ? AND id <> ?',
          [normalizedPhone, userId]
        );
        if (dup.length > 0) {
          await connection.rollback();
          return res.status(409).json({ error: 'Phone number already registered' });
        }
      }
      fields.push('phone = ?');
      values.push(normalizedPhone);
    }

    if (wantsPasswordUpdate) {
      const ok = await comparePassword(currentPassword, user.password_hash || DUMMY_PASSWORD_HASH);
      if (!ok) {
        await connection.rollback();
        return res.status(400).json({ error: 'Current password is incorrect' });
      }

      const newPasswordHash = await hashPassword(newPassword);
      fields.push('password_hash = ?');
      values.push(newPasswordHash);
      passwordChanged = true;
    }

    fields.push('updated_at = NOW()');
    await connection.query(
      `UPDATE users SET ${fields.join(', ')} WHERE id = ?`,
      [...values, userId]
    );

    const [updatedUsers] = await connection.query(
      `SELECT id, email, phone, verified, is_suspended, created_at, updated_at
       FROM users WHERE id = ?`,
      [userId]
    );

    await connection.commit();

    if (passwordChanged) {
      sendPasswordChangedEmail({ email: userEmail, req }).catch((err) => {
        console.error('Password changed email failed:', err.message);
      });
    }

    return res.json({
      message: 'Profile updated successfully',
      user: updatedUsers[0],
    });
  } catch (err) {
    await connection.rollback();
    console.error('Update profile error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
};

// -------------------- POST /auth/referral-code/generate --------------------
exports.generateReferralCode = async (req, res) => {
  const userId = req.user && req.user.id;
  if (!userId || !isUuid(userId)) {
    return res.status(401).json({ error: 'Authorization token required' });
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

    const referralCode = await generateUniqueReferralCode(connection);
    await connection.query(
      'UPDATE users SET referral_code = ?, updated_at = NOW() WHERE id = ?',
      [referralCode, userId]
    );

    await connection.commit();
    return res.status(201).json({
      message: 'Referral code generated successfully',
      referralCode,
    });
  } catch (err) {
    await connection.rollback();
    console.error('Generate referral code error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
};

// -------------------- POST /auth/delete-account/request-otp --------------------
exports.requestAccountDeletionOtp = async (req, res) => {
  const userId = req.user && req.user.id;
  if (!userId || !isUuid(userId)) {
    return res.status(401).json({ error: 'Authorization token required' });
  }

  try {
    const [users] = await db.query(
      'SELECT id, email, verified, is_suspended FROM users WHERE id = ?',
      [userId]
    );
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = users[0];
    if (!user.verified || user.is_suspended) {
      return res.status(400).json({ error: 'Account is not active' });
    }
    if (!user.email) {
      return res.status(400).json({ error: 'Email is required to verify account deletion' });
    }

    const otp = generateOtp();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

    await db.query(
      `UPDATE user_account_deletion_otps
       SET consumed_at = NOW()
       WHERE user_id = ? AND consumed_at IS NULL`,
      [userId]
    );
    await db.query(
      `INSERT INTO user_account_deletion_otps
       (id, user_id, otp_code, otp_expires, consumed_at, created_at)
       VALUES (?, ?, ?, ?, NULL, NOW())`,
      [uuidv4(), userId, otp, otpExpires]
    );

    await sendAccountDeletionOtpEmail({ email: user.email, otp });
    return res.json({ message: 'Account deletion OTP sent to your email' });
  } catch (err) {
    if (isMissingTableError(err)) {
      return res.status(503).json({ error: 'Account deletion service unavailable. Apply latest migrations.' });
    }
    console.error('Request account deletion OTP error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- DELETE /auth/delete-account --------------------
exports.deleteAccount = async (req, res) => {
  const userId = req.user && req.user.id;
  const otp = typeof req.body.otp === 'string' ? req.body.otp.trim() : '';
  const lockIdentity = `delete-account:${userId}`;

  if (!userId || !isUuid(userId)) {
    return res.status(401).json({ error: 'Authorization token required' });
  }
  if (!/^\d{6}$/.test(otp)) {
    return res.status(400).json({ error: 'Valid otp is required' });
  }

  const lockState = isLocked('delete-account', lockIdentity);
  if (lockState.locked) {
    res.setHeader('Retry-After', String(lockState.retryAfterSec));
    return res.status(429).json({ error: 'Too many invalid OTP attempts. Try again later.' });
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    const [users] = await connection.query(
      'SELECT id, email FROM users WHERE id = ? FOR UPDATE',
      [userId]
    );
    if (users.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'User not found' });
    }
    const user = users[0];

    const [otpRows] = await connection.query(
      `SELECT id, otp_code, otp_expires, consumed_at
       FROM user_account_deletion_otps
       WHERE user_id = ?
       ORDER BY created_at DESC
       LIMIT 1
       FOR UPDATE`,
      [userId]
    );

    if (
      otpRows.length === 0 ||
      otpRows[0].consumed_at ||
      otpRows[0].otp_code !== otp ||
      !otpRows[0].otp_expires ||
      new Date(otpRows[0].otp_expires) <= new Date()
    ) {
      await connection.rollback();
      const fail = recordFailure('delete-account', lockIdentity);
      if (fail.locked) {
        res.setHeader('Retry-After', String(fail.retryAfterSec));
        return res.status(429).json({ error: 'Too many invalid OTP attempts. Try again later.' });
      }
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    await connection.query(
      'UPDATE user_account_deletion_otps SET consumed_at = NOW() WHERE id = ?',
      [otpRows[0].id]
    );
    await runDeleteIfTableExists(connection, 'DELETE FROM refresh_tokens WHERE user_id = ?', [userId]);
    await runDeleteIfTableExists(connection, 'DELETE FROM user_trusted_devices WHERE user_id = ?', [userId]);
    await runDeleteIfTableExists(connection, 'DELETE FROM user_password_reset_otps WHERE user_id = ?', [userId]);
    await runDeleteIfTableExists(connection, 'DELETE FROM user_password_reset_sessions WHERE user_id = ?', [userId]);
    await runDeleteIfTableExists(connection, 'DELETE FROM user_account_deletion_otps WHERE user_id = ?', [userId]);
    await runDeleteIfTableExists(connection, 'DELETE FROM cart_items WHERE user_id = ?', [userId]);
    await runDeleteIfTableExists(connection, 'DELETE FROM coupon_redemptions WHERE user_id = ?', [userId]);
    await runDeleteIfTableExists(connection, 'DELETE FROM payments WHERE user_id = ?', [userId]);
    await runDeleteIfTableExists(connection, 'DELETE FROM orders WHERE user_id = ?', [userId]);

    const [deleteResult] = await connection.query(
      'DELETE FROM users WHERE id = ?',
      [userId]
    );
    if (!deleteResult || deleteResult.affectedRows !== 1) {
      await connection.rollback();
      return res.status(500).json({ error: 'Failed to delete account' });
    }

    await connection.commit();
    clearFailures('delete-account', lockIdentity);

    sendAccountDeletedGoodbyeEmail({ email: user.email }).catch((err) => {
      console.error('Goodbye email failed:', err.message);
    });
    return res.json({ message: 'Account deleted successfully' });
  } catch (err) {
    await connection.rollback();
    if (isMissingTableError(err)) {
      return res.status(503).json({ error: 'Account deletion service unavailable. Apply latest migrations.' });
    }
    console.error('Delete account error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
};

