const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { rateLimit } = require('../utils/security');
const { requireAuth } = require('../utils/jwtAuth');

const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: Number(process.env.AUTH_RATE_LIMIT_MAX),
  keyGenerator: (req) => `auth:${req.ip}`,
});

const otpIdentityLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: Number(process.env.OTP_IDENTITY_RATE_LIMIT_MAX) > 0
    ? Number(process.env.OTP_IDENTITY_RATE_LIMIT_MAX)
    : 10,
  keyGenerator: (req) => {
    const authUserId = req.user && req.user.id ? String(req.user.id).trim().toLowerCase().slice(0, 128) : '';
    const userId = req.body && req.body.userId ? String(req.body.userId).trim().toLowerCase().slice(0, 128) : '';
    const email = req.body && req.body.email ? String(req.body.email).trim().toLowerCase().slice(0, 128) : '';
    const identity = authUserId || userId || email || 'unknown';
    return `otp:${req.path}:${req.ip}:${identity}`;
  },
});

router.post('/signup', authLimiter, authController.signup);
router.post('/verify', authLimiter, otpIdentityLimiter, authController.verify);
router.post('/resend-otp', authLimiter, otpIdentityLimiter, authController.resendOtp); 
router.post('/google', authLimiter, authController.googleSignIn);
router.post('/apple', authLimiter, authController.appleSignIn);
router.post('/login', authLimiter, authController.login);
router.post('/request-login-otp', authLimiter, otpIdentityLimiter, authController.requestLoginOtp);
router.post('/login-otp', authLimiter, otpIdentityLimiter, authController.loginOtp);
router.post('/forgot-password/request', authLimiter, otpIdentityLimiter, authController.requestPasswordResetOtp);
router.post('/forgot-password/verify', authLimiter, otpIdentityLimiter, authController.verifyPasswordResetOtp);
router.post('/forgot-password/reset', authLimiter, authController.resetPasswordWithToken);
router.post('/refresh', authLimiter, authController.refresh);
router.post('/logout', authLimiter, requireAuth, authController.logout);
router.post('/logout-all', authLimiter, requireAuth, authController.logoutAll);
router.post('/delete-account/request-otp', authLimiter, requireAuth, authController.requestAccountDeletionOtp);
router.delete('/delete-account', authLimiter, requireAuth, otpIdentityLimiter, authController.deleteAccount);
router.get('/me', requireAuth, authController.me);
router.patch('/me', requireAuth, authController.updateMe);
router.post('/referral-code/generate', requireAuth, authController.generateReferralCode);

module.exports = router;
