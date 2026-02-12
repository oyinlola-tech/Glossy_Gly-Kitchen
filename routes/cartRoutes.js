const express = require('express');
const router = express.Router({ mergeParams: true });
const cartController = require('../controllers/cartController');
const { requireVerifiedUser } = require('../utils/userGuard');
const { requireAuth } = require('../utils/jwtAuth');

router.post('/', requireAuth, requireVerifiedUser, cartController.addToCart);
router.get('/', requireAuth, requireVerifiedUser, cartController.viewCart);
router.put('/', requireAuth, requireVerifiedUser, cartController.updateCartItem);
router.delete('/', requireAuth, requireVerifiedUser, cartController.clearCart);

module.exports = router;
