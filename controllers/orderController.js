const db = require('../config/db');
const { v4: uuidv4 } = require('uuid');
const { isTransitionAllowed } = require('../utils/statusTransitions');
const { isUuid, toInt } = require('../utils/validation');

// -------------------- GET /orders (List current user's orders) --------------------
exports.listMyOrders = async (req, res) => {
  const userId = req.user.id;
  const page = Math.max(toInt(req.query.page) || 1, 1);
  const limit = Math.min(Math.max(toInt(req.query.limit) || 20, 1), 100);
  const offset = (page - 1) * limit;
  const status = req.query.status ? String(req.query.status) : null;

  if (!userId || !isUuid(userId)) {
    return res.status(400).json({ error: 'Valid userId is required' });
  }

  const where = ['user_id = ?'];
  const values = [userId];
  if (status) {
    where.push('status = ?');
    values.push(status);
  }

  const whereClause = `WHERE ${where.join(' AND ')}`;

  try {
    const [countRows] = await db.query(
      `SELECT COUNT(*) AS total
       FROM orders
       ${whereClause}`,
      values
    );

    const [orders] = await db.query(
      `SELECT id, user_id, total_amount, status, created_at, updated_at
       FROM orders
       ${whereClause}
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [...values, limit, offset]
    );

    res.json({
      page,
      limit,
      total: countRows[0].total,
      orders,
    });
  } catch (err) {
    console.error('List orders error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- POST /orders (Create order from cart) --------------------
exports.createOrder = async (req, res) => {
  const userId = req.user.id;

  if (!userId || !isUuid(userId)) {
    return res.status(400).json({ error: 'Valid userId is required' });
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    // 1. Fetch cart items with food details and lock the cart rows
    const [cartItems] = await connection.query(
      `SELECT 
         ci.food_id,
         ci.quantity,
         fi.price,
         fi.available,
         fi.name
       FROM cart_items ci
       JOIN food_items fi ON ci.food_id = fi.id
       WHERE ci.user_id = ?
       FOR UPDATE`, // prevent double ordering
      [userId]
    );

    if (cartItems.length === 0) {
      await connection.rollback();
      return res.status(400).json({ error: 'Cart is empty' });
    }

    // 2. Check availability of all items
    const unavailableItems = cartItems.filter(item => !item.available);
    if (unavailableItems.length > 0) {
      await connection.rollback();
      return res.status(409).json({
        error: 'Some items are no longer available',
        items: unavailableItems.map(i => i.name),
      });
    }

    // 3. Calculate total
    const total = cartItems.reduce(
      (sum, item) => sum + parseFloat(item.price) * item.quantity,
      0
    );

    // 4. Create order (status = 'pending')
    const orderId = uuidv4();
    await connection.query(
      `INSERT INTO orders (id, user_id, total_amount, status, created_at, updated_at)
       VALUES (?, ?, ?, 'pending', NOW(), NOW())`,
      [orderId, userId, total]
    );

    // 5. Create order items (snapshot)
    for (const item of cartItems) {
      await connection.query(
        `INSERT INTO order_items (id, order_id, food_id, quantity, price_at_order)
         VALUES (?, ?, ?, ?, ?)`,
        [uuidv4(), orderId, item.food_id, item.quantity, item.price]
      );
    }

    // 6. Clear user's cart
    await connection.query('DELETE FROM cart_items WHERE user_id = ?', [userId]);

    await connection.commit();

    res.status(201).json({
      orderId,
      status: 'pending',
      total: total.toFixed(2),
    });

  } catch (err) {
    await connection.rollback();
    console.error('Create order error:', err);
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
};

// -------------------- GET /orders/:id (Get order details) --------------------
exports.getOrderById = async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  if (!isUuid(id)) {
    return res.status(400).json({ error: 'Invalid order id' });
  }
  if (!userId || !isUuid(userId)) {
    return res.status(400).json({ error: 'Valid userId is required' });
  }

  try {
    // Get order header
    const [orders] = await db.query(
      `SELECT o.*, u.email, u.phone
       FROM orders o
       JOIN users u ON o.user_id = u.id
       WHERE o.id = ? AND o.user_id = ?`,
      [id, userId]
    );

    if (orders.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const order = orders[0];

    // Get order items
    const [items] = await db.query(
      `SELECT oi.*, fi.name, fi.description
       FROM order_items oi
       JOIN food_items fi ON oi.food_id = fi.id
       WHERE oi.order_id = ?`,
      [id]
    );

    res.json({
      ...order,
      items,
    });

  } catch (err) {
    console.error('Get order error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- PATCH /orders/:id/status (Update order status) --------------------
exports.updateOrderStatus = async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!isUuid(id)) {
    return res.status(400).json({ error: 'Invalid order id' });
  }
  if (!status) {
    return res.status(400).json({ error: 'status is required' });
  }

  try {
    // Get current order
    const [orders] = await db.query('SELECT status FROM orders WHERE id = ?', [id]);
    if (orders.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const currentStatus = orders[0].status;

    // Check if transition is allowed
    if (!isTransitionAllowed(currentStatus, status)) {
      return res.status(400).json({
        error: `Cannot transition order from '${currentStatus}' to '${status}'`,
      });
    }

    await db.query(
      'UPDATE orders SET status = ?, updated_at = NOW() WHERE id = ?',
      [status, id]
    );

    res.json({
      message: 'Order status updated successfully',
      orderId: id,
      newStatus: status,
    });

  } catch (err) {
    console.error('Update order status error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- POST /orders/:id/cancel (Customer cancel) --------------------
exports.cancelOrder = async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  if (!userId || !isUuid(userId)) {
    return res.status(400).json({ error: 'Valid userId is required' });
  }
  if (!isUuid(id)) {
    return res.status(400).json({ error: 'Invalid order id' });
  }

  try {
    // Verify order belongs to user and is in cancellable state
    const [orders] = await db.query(
      'SELECT status FROM orders WHERE id = ? AND user_id = ?',
      [id, userId]
    );

    if (orders.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const currentStatus = orders[0].status;
    // Customers can only cancel pending orders
    if (currentStatus !== 'pending') {
      return res.status(400).json({
        error: `Cannot cancel order in '${currentStatus}' status. Only pending orders can be cancelled.`,
      });
    }

    await db.query(
      'UPDATE orders SET status = ?, updated_at = NOW() WHERE id = ?',
      ['cancelled', id]
    );

    res.json({ message: 'Order cancelled successfully' });

  } catch (err) {
    console.error('Cancel order error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};
