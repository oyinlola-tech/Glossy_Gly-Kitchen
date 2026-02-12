const express = require('express');
const router = express.Router();
const paymentController = require('../controllers/paymentController');
const { requireAuth } = require('../utils/jwtAuth');
const { requireVerifiedUser } = require('../utils/userGuard');
const { rateLimit } = require('../utils/security');

const paymentLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: Number(process.env.RATE_LIMIT_MAX),
  keyGenerator: (req) => `payments:${req.ip}`,
});

router.post('/initialize', paymentLimiter, requireAuth, requireVerifiedUser, paymentController.initialize);
router.get('/verify/:reference', paymentLimiter, requireAuth, requireVerifiedUser, paymentController.verify);
router.post('/cards', paymentLimiter, requireAuth, requireVerifiedUser, paymentController.attachCard);
router.get('/cards', paymentLimiter, requireAuth, requireVerifiedUser, paymentController.listCards);
router.patch('/cards/:cardId/default', paymentLimiter, requireAuth, requireVerifiedUser, paymentController.setDefaultCard);
router.delete('/cards/:cardId', paymentLimiter, requireAuth, requireVerifiedUser, paymentController.deleteCard);
router.post('/pay-with-saved-card', paymentLimiter, requireAuth, requireVerifiedUser, paymentController.payWithSavedCard);
router.post('/webhook/paystack', paymentController.paystackWebhook);

module.exports = router;
