const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');
const { rateLimit } = require('../utils/security');
const { requireAdminAuth, requireSuperAdmin } = require('../utils/adminJwtAuth');
const { auditAdminAction } = require('../utils/audit');

const adminAuthLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: Number(process.env.ADMIN_AUTH_RATE_LIMIT_MAX),
  keyGenerator: (req) => `admin-auth:${req.ip}`,
});

router.post('/auth/bootstrap', adminAuthLimiter, adminController.bootstrap);
router.post('/auth/login', adminAuthLimiter, adminController.login);
router.post('/auth/refresh', adminAuthLimiter, adminController.refresh);
router.post('/auth/logout', adminAuthLimiter, requireAdminAuth, adminController.logout);
router.post('/auth/logout-all', adminAuthLimiter, requireAdminAuth, adminController.logoutAll);
router.get('/me', requireAdminAuth, adminController.me);

router.get('/dashboard', requireAdminAuth, auditAdminAction('admin.dashboard.view'), adminController.dashboard);

router.post('/admins', requireAdminAuth, requireSuperAdmin, auditAdminAction('admin.user.create'), adminController.createAdmin);

router.get('/users', requireAdminAuth, auditAdminAction('admin.users.list'), adminController.listUsers);
router.get('/users/:id', requireAdminAuth, auditAdminAction('admin.users.get'), adminController.getUserById);
router.patch('/users/:id/status', requireAdminAuth, auditAdminAction('admin.users.update_status'), adminController.updateUserStatus);

router.get('/orders', requireAdminAuth, auditAdminAction('admin.orders.list'), adminController.listOrders);
router.get('/orders/:id', requireAdminAuth, auditAdminAction('admin.orders.get'), adminController.getOrderById);
router.patch('/orders/:id/status', requireAdminAuth, auditAdminAction('admin.orders.update_status'), adminController.updateOrderStatus);

router.post('/coupons', requireAdminAuth, auditAdminAction('admin.coupons.create'), adminController.createCoupon);
router.get('/coupons', requireAdminAuth, auditAdminAction('admin.coupons.list'), adminController.listCoupons);
router.post('/referral-codes', requireAdminAuth, auditAdminAction('admin.referrals.create'), adminController.createUserReferralCode);
router.get('/referral-codes', requireAdminAuth, auditAdminAction('admin.referrals.list'), adminController.listUserReferralCodes);

router.post('/disputes', requireAdminAuth, auditAdminAction('admin.disputes.create'), adminController.createDispute);
router.get('/disputes', requireAdminAuth, auditAdminAction('admin.disputes.list'), adminController.listDisputes);
router.get('/disputes/:id', requireAdminAuth, auditAdminAction('admin.disputes.get'), adminController.getDisputeById);
router.patch('/disputes/:id', requireAdminAuth, auditAdminAction('admin.disputes.update'), adminController.updateDispute);
router.post('/disputes/:id/resolve', requireAdminAuth, auditAdminAction('admin.disputes.resolve'), adminController.resolveDispute);
router.post('/disputes/:id/comments', requireAdminAuth, auditAdminAction('admin.disputes.add_comment'), adminController.addDisputeComment);
router.get('/audit-logs', requireAdminAuth, auditAdminAction('admin.audit_logs.list'), adminController.listAuditLogs);

module.exports = router;
