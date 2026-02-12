const express = require('express');
const router = express.Router();
const orderController = require('../controllers/orderController');
const { requireVerifiedUser } = require('../utils/userGuard');
const { requireAuth } = require('../utils/jwtAuth');
const { requireAdminAuth } = require('../utils/adminJwtAuth');
const { auditAdminAction } = require('../utils/audit');

router.post('/', requireAuth, requireVerifiedUser, orderController.createOrder);
router.get('/', requireAuth, requireVerifiedUser, orderController.listMyOrders);
router.get('/:id', requireAuth, requireVerifiedUser, orderController.getOrderById);
router.post('/:id/coupon/validate', requireAuth, requireVerifiedUser, orderController.validateCouponForOrder);
router.post('/:id/coupon/apply', requireAuth, requireVerifiedUser, orderController.applyCouponToOrder);
router.delete('/:id/coupon', requireAuth, requireVerifiedUser, orderController.removeCouponFromOrder);
router.patch(
  '/:id/status',
  requireAdminAuth,
  auditAdminAction('order.status.update'),
  orderController.updateOrderStatus
);
router.post('/:id/cancel', requireAuth, requireVerifiedUser, orderController.cancelOrder);

module.exports = router;
