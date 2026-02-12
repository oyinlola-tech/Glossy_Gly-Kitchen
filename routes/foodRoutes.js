const express = require('express');
const router = express.Router();
const foodController = require('../controllers/foodController');
const { requireAdminAuth } = require('../utils/adminJwtAuth');
const { auditAdminAction } = require('../utils/audit');

router.get('/', foodController.getAllFoods);
router.get('/:id', foodController.getFoodById);
router.post('/', requireAdminAuth, auditAdminAction('food.create'), foodController.addFood);
router.put('/:id', requireAdminAuth, auditAdminAction('food.update'), foodController.updateFood);
router.delete('/:id', requireAdminAuth, auditAdminAction('food.delete'), foodController.deleteFood);

module.exports = router;
