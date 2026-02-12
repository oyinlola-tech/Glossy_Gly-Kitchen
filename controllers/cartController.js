const db = require('../config/db');
const { v4: uuidv4 } = require('uuid');
const { isUuid, toInt } = require('../utils/validation');

// -------------------- POST /cart/:userId (Add to cart) --------------------
exports.addToCart = async (req, res) => {
  const userId = req.user.id;
  const { foodId, quantity } = req.body;

  if (!isUuid(userId)) {
    return res.status(400).json({ error: 'Invalid userId' });
  }
  if (!foodId || !isUuid(foodId)) {
    return res.status(400).json({ error: 'Invalid foodId' });
  }

  const qty = toInt(quantity);
  if (!qty || qty < 1) {
    return res.status(400).json({ error: 'foodId and positive quantity are required' });
  }

  try {
    // Check if food exists and is available
    const [food] = await db.query(
      'SELECT id, available FROM food_items WHERE id = ?',
      [foodId]
    );
    if (food.length === 0) {
      return res.status(404).json({ error: 'Food item not found' });
    }
    if (!food[0].available) {
      return res.status(400).json({ error: 'Food item is not available' });
    }

    // Upsert cart item
    const cartItemId = uuidv4();
    await db.query(
      `INSERT INTO cart_items (id, user_id, food_id, quantity, added_at)
       VALUES (?, ?, ?, ?, NOW())
       ON DUPLICATE KEY UPDATE
         quantity = quantity + VALUES(quantity),
         added_at = NOW()`,
      [cartItemId, userId, foodId, qty]
    );

    res.json({ message: 'Item added to cart successfully' });

  } catch (err) {
    console.error('Add to cart error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- GET /cart/:userId (View cart) --------------------
exports.viewCart = async (req, res) => {
  const userId = req.user.id;

  if (!isUuid(userId)) {
    return res.status(400).json({ error: 'Invalid userId' });
  }

  try {
    const [items] = await db.query(
      `SELECT 
         ci.food_id,
         fi.name,
         fi.price,
         ci.quantity,
         (fi.price * ci.quantity) AS subtotal,
         fi.available
       FROM cart_items ci
       JOIN food_items fi ON ci.food_id = fi.id
       WHERE ci.user_id = ?`,
      [userId]
    );

    const total = items.reduce((sum, item) => sum + parseFloat(item.subtotal), 0);

    res.json({
      userId,
      items,
      total: total.toFixed(2),
    });

  } catch (err) {
    console.error('View cart error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- PUT /cart/:userId (Update cart item quantity) --------------------
exports.updateCartItem = async (req, res) => {
  const userId = req.user.id;
  const { foodId, quantity } = req.body;

  if (!isUuid(userId)) {
    return res.status(400).json({ error: 'Invalid userId' });
  }
  if (!foodId || !isUuid(foodId)) {
    return res.status(400).json({ error: 'Invalid foodId' });
  }
  if (quantity === undefined) {
    return res.status(400).json({ error: 'foodId and quantity are required' });
  }

  try {
    const qty = toInt(quantity);
    if (qty === null) {
      return res.status(400).json({ error: 'quantity must be an integer' });
    }

    if (qty <= 0) {
      // Remove item
      const [result] = await db.query(
        'DELETE FROM cart_items WHERE user_id = ? AND food_id = ?',
        [userId, foodId]
      );
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Item not found in cart' });
      }
      return res.json({ message: 'Item removed from cart' });
    }

    // Update quantity
    const [result] = await db.query(
      `UPDATE cart_items SET quantity = ?, added_at = NOW()
       WHERE user_id = ? AND food_id = ?`,
      [qty, userId, foodId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Item not found in cart' });
    }

    res.json({ message: 'Cart updated successfully' });

  } catch (err) {
    console.error('Update cart error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- DELETE /cart/:userId (Clear entire cart) --------------------
exports.clearCart = async (req, res) => {
  const userId = req.user.id;

  if (!isUuid(userId)) {
    return res.status(400).json({ error: 'Invalid userId' });
  }

  try {
    await db.query('DELETE FROM cart_items WHERE user_id = ?', [userId]);
    res.json({ message: 'Cart cleared successfully' });
  } catch (err) {
    console.error('Clear cart error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};
