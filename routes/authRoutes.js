const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { rateLimit } = require('../utils/security');

const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: Number(process.env.AUTH_RATE_LIMIT_MAX) || 10,
  keyGenerator: (req) => `auth:${req.ip}`,
});

router.post('/signup', authLimiter, authController.signup);
router.post('/verify', authLimiter, authController.verify);
router.post('/resend-otp', authLimiter, authController.resendOtp); 
router.post('/login', authLimiter, authController.login);
router.post('/login-otp', authLimiter, authController.loginOtp);
router.post('/refresh', authLimiter, authController.refresh);
router.post('/logout', authLimiter, authController.logout);

module.exports = router;
