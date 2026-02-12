const express = require('express');
const router = express.Router();
const orderController = require('../controllers/orderController');
const { requireVerifiedUser } = require('../utils/userGuard');
const { requireAdminKey } = require('../utils/adminAuth');
const { requireAuth } = require('../utils/jwtAuth');
const { auditAdminAction } = require('../utils/audit');

router.post('/', requireAuth, requireVerifiedUser, orderController.createOrder);
router.get('/', requireAuth, requireVerifiedUser, orderController.listMyOrders);
router.get('/:id', requireAuth, requireVerifiedUser, orderController.getOrderById);
router.patch(
  '/:id/status',
  requireAdminKey,
  auditAdminAction('order.status.update'),
  orderController.updateOrderStatus
);
router.post('/:id/cancel', requireAuth, requireVerifiedUser, orderController.cancelOrder);

module.exports = router;
