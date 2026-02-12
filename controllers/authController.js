const db = require('../config/db');
const { v4: uuidv4 } = require('uuid');
const generateOtp = require('../utils/generateOtp');
const { generateReferralCode, validateReferralCode } = require('../utils/referralHelper');
const nodemailer = require('nodemailer');
const { isValidEmail, isValidPhone } = require('../utils/validation');
const jwt = require('jsonwebtoken');
const { validatePassword, hashPassword, comparePassword } = require('../utils/password');
const { createRefreshToken, hashToken, refreshExpiryDate } = require('../utils/tokens');

const issueAccessToken = (user) => {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('JWT secret not configured');
  }
  return jwt.sign(
    { sub: user.id, email: user.email || null },
    secret,
    { expiresIn: process.env.JWT_EXPIRES_IN, issuer: process.env.JWT_ISSUER }
  );
};

const issueRefreshToken = async (userId, req) => {
  const token = createRefreshToken();
  const tokenHash = hashToken(token);
  const expiresAt = refreshExpiryDate();

  await db.query(
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

const issueTokens = async (user, req) => {
  const accessToken = issueAccessToken(user);
  const refreshToken = await issueRefreshToken(user.id, req);
  return { accessToken, refreshToken };
};

// -------------------- Nodemailer Transporter --------------------
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// -------------------- Helper: Send OTP Email --------------------
const sendOtpEmail = async (email, otp) => {
  const mailOptions = {
    from: process.env.EMAIL_FROM,
    to: email,
    subject: 'Glossy_Gly-Kitchen - Verify Your Account',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #ff6b35;">Welcome to Glossy_Gly-Kitchen!</h2>
        <p>Your OTP for account verification is:</p>
        <div style="background: #f5f5f5; padding: 15px; font-size: 24px; font-weight: bold; text-align: center; letter-spacing: 5px;">
          ${otp}
        </div>
        <p>This code will expire in 10 minutes.</p>
        <p>If you didn't request this, please ignore this email.</p>
        <br>
        <p>Cheers,<br>Glossy_Gly-Kitchen Team</p>
      </div>
    `,
  };

  await transporter.sendMail(mailOptions);
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
    const newReferralCode = generateReferralCode();
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

  if (!userId || !otp) {
    return res.status(400).json({ error: 'userId and otp are required' });
  }

  try {
    // Find user with matching OTP and not expired
    const [users] = await db.query(
      `SELECT id, email FROM users 
       WHERE id = ? AND verified = 0 AND otp_code = ? AND otp_expires > NOW()`,
      [userId, otp]
    );

    if (users.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    // Mark user as verified and clear OTP fields
    await db.query(
      `UPDATE users SET verified = 1, otp_code = NULL, otp_expires = NULL, updated_at = NOW()
       WHERE id = ?`,
      [userId]
    );

    const tokens = await issueTokens({ id: userId, email: users[0].email }, req);
    res.json({ message: 'Account verified successfully.', ...tokens });

  } catch (err) {
    console.error('Verification error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- POST /resend-otp (Bonus) --------------------
exports.resendOtp = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  try {
    // Find unverified user with this email
    const [users] = await db.query(
      'SELECT id, verified FROM users WHERE email = ?',
      [email]
    );
    if (users.length === 0) {
      return res.status(404).json({ error: 'No account found with this email' });
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

    res.json({ message: 'OTP resent successfully' });

  } catch (err) {
    console.error('Resend OTP error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- POST /login --------------------
exports.login = async (req, res) => {
  const { email, password } = req.body;

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
      return res.status(404).json({ error: 'Account not found' });
    }

    const user = users[0];
    if (!user.verified) {
      return res.status(403).json({ error: 'Account not verified' });
    }
    if (user.is_suspended) {
      return res.status(403).json({ error: 'Account is suspended' });
    }

    const passwordMatches = await comparePassword(password, user.password_hash || '');
    if (!passwordMatches) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const tokens = await issueTokens(user, req);
    res.json({ message: 'Login successful', ...tokens });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- POST /login-otp --------------------
exports.loginOtp = async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ error: 'email and otp are required' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  try {
    const [users] = await db.query(
      `SELECT id, email, verified, otp_code, otp_expires, is_suspended
       FROM users WHERE email = ?`,
      [email]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: 'Account not found' });
    }

    const user = users[0];
    if (!user.verified) {
      return res.status(403).json({ error: 'Account not verified' });
    }
    if (user.is_suspended) {
      return res.status(403).json({ error: 'Account is suspended' });
    }

    if (!user.otp_code || user.otp_code !== otp || !user.otp_expires || user.otp_expires <= new Date()) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    await db.query(
      'UPDATE users SET otp_code = NULL, otp_expires = NULL, updated_at = NOW() WHERE id = ?',
      [user.id]
    );

    const tokens = await issueTokens(user, req);
    res.json({ message: 'Login successful', ...tokens });
  } catch (err) {
    console.error('Login OTP error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- POST /refresh --------------------
exports.refresh = async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ error: 'refreshToken is required' });
  }

  try {
    const tokenHash = hashToken(refreshToken);
    const [rows] = await db.query(
      `SELECT id, user_id, expires_at, revoked_at
       FROM refresh_tokens
       WHERE token_hash = ?`,
      [tokenHash]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    const tokenRow = rows[0];
    if (tokenRow.revoked_at) {
      return res.status(401).json({ error: 'Refresh token revoked' });
    }
    if (new Date(tokenRow.expires_at) <= new Date()) {
      return res.status(401).json({ error: 'Refresh token expired' });
    }

    // Revoke old token
    await db.query(
      'UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = ?',
      [tokenRow.id]
    );

    const [users] = await db.query('SELECT id, email, verified, is_suspended FROM users WHERE id = ?', [tokenRow.user_id]);
    if (users.length === 0 || !users[0].verified) {
      return res.status(401).json({ error: 'Invalid user' });
    }
    if (users[0].is_suspended) {
      return res.status(403).json({ error: 'Account is suspended' });
    }

    const tokens = await issueTokens(users[0], req);
    res.json({ message: 'Token refreshed', ...tokens });
  } catch (err) {
    console.error('Refresh error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- POST /logout --------------------
exports.logout = async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ error: 'refreshToken is required' });
  }

  try {
    const tokenHash = hashToken(refreshToken);
    await db.query('UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = ?', [tokenHash]);
    res.json({ message: 'Logged out' });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

