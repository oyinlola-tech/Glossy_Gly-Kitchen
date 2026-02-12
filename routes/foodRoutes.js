const express = require('express');
const router = express.Router();
const foodController = require('../controllers/foodController');
const { requireAdminKey } = require('../utils/adminAuth');
const { auditAdminAction } = require('../utils/audit');

router.get('/', foodController.getAllFoods);
router.post('/', requireAdminKey, auditAdminAction('food.create'), foodController.addFood);
router.put('/:id', requireAdminKey, auditAdminAction('food.update'), foodController.updateFood);
router.delete('/:id', requireAdminKey, auditAdminAction('food.delete'), foodController.deleteFood);

module.exports = router;
