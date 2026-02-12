const db = require('../config/db');
const { v4: uuidv4 } = require('uuid');
const { isTransitionAllowed } = require('../utils/statusTransitions');
const { isUuid, toInt } = require('../utils/validation');

const COUPON_CODE_REGEX = /^[A-Z0-9_-]{4,40}$/;

const normalizeCouponCode = (value) => String(value || '').trim().toUpperCase();

const validateCouponWindow = (coupon) => {
  if (!coupon || !coupon.is_active) return { valid: false, reason: 'Coupon is not active' };
  const now = new Date();
  if (coupon.starts_at && new Date(coupon.starts_at) > now) {
    return { valid: false, reason: 'Coupon is not active yet' };
  }
  if (coupon.expires_at && new Date(coupon.expires_at) <= now) {
    return { valid: false, reason: 'Coupon has expired' };
  }
  if (coupon.max_redemptions !== null && coupon.redemptions_count >= coupon.max_redemptions) {
    return { valid: false, reason: 'Coupon redemption limit reached' };
  }
  return { valid: true };
};

const computeCouponAmounts = (totalAmount, coupon) => {
  const total = Number(totalAmount);
  if (!Number.isFinite(total) || total <= 0) {
    return { error: 'Invalid order amount' };
  }

  let discountAmount = 0;
  const couponType = String(coupon.discount_type || '').toLowerCase();
  const discountValue = Number(coupon.discount_value);
  if (!Number.isFinite(discountValue) || discountValue <= 0) {
    return { error: 'Invalid coupon discount value' };
  }
  if (couponType === 'percentage') {
    if (discountValue > 100) {
      return { error: 'Invalid coupon discount value' };
    }
    discountAmount = (total * discountValue) / 100;
  } else if (couponType === 'fixed') {
    discountAmount = discountValue;
  } else {
    return { error: 'Unsupported coupon type' };
  }

  discountAmount = Number(discountAmount.toFixed(2));
  const payableAmount = Number((total - discountAmount).toFixed(2));
  if (payableAmount <= 0) {
    return { error: 'Coupon discount cannot reduce order to zero' };
  }

  return {
    discountAmount,
    payableAmount,
  };
};

const reserveCouponCount = async (connection, couponId) => {
  const [result] = await connection.query(
    `UPDATE coupons
     SET redemptions_count = redemptions_count + 1, updated_at = NOW()
     WHERE id = ?
       AND is_active = 1
       AND (starts_at IS NULL OR starts_at <= NOW())
       AND (expires_at IS NULL OR expires_at > NOW())
       AND (max_redemptions IS NULL OR redemptions_count < max_redemptions)`,
    [couponId]
  );
  return result.affectedRows > 0;
};

const releaseCouponCount = async (connection, couponId) => {
  await connection.query(
    `UPDATE coupons
     SET redemptions_count = CASE WHEN redemptions_count > 0 THEN redemptions_count - 1 ELSE 0 END,
         updated_at = NOW()
     WHERE id = ?`,
    [couponId]
  );
};

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
      `SELECT id, user_id, total_amount, discount_amount, payable_amount, coupon_code, status, created_at, updated_at
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
       FOR UPDATE`,
      [userId]
    );

    if (cartItems.length === 0) {
      await connection.rollback();
      return res.status(400).json({ error: 'Cart is empty' });
    }

    const unavailableItems = cartItems.filter((item) => !item.available);
    if (unavailableItems.length > 0) {
      await connection.rollback();
      return res.status(409).json({
        error: 'Some items are no longer available',
        items: unavailableItems.map((i) => i.name),
      });
    }

    const total = cartItems.reduce(
      (sum, item) => sum + Number(item.price) * item.quantity,
      0
    );

    const orderId = uuidv4();
    await connection.query(
      `INSERT INTO orders (id, user_id, total_amount, discount_amount, payable_amount, coupon_id, coupon_code, coupon_discount_type, coupon_discount_value, status, created_at, updated_at)
       VALUES (?, ?, ?, 0, ?, NULL, NULL, NULL, NULL, 'pending', NOW(), NOW())`,
      [orderId, userId, total, total]
    );

    for (const item of cartItems) {
      await connection.query(
        `INSERT INTO order_items (id, order_id, food_id, quantity, price_at_order)
         VALUES (?, ?, ?, ?, ?)`,
        [uuidv4(), orderId, item.food_id, item.quantity, item.price]
      );
    }

    await connection.query('DELETE FROM cart_items WHERE user_id = ?', [userId]);
    await connection.commit();

    res.status(201).json({
      orderId,
      status: 'pending',
      total: total.toFixed(2),
      payableAmount: total.toFixed(2),
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

// -------------------- POST /orders/:id/coupon/validate --------------------
exports.validateCouponForOrder = async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;
  const couponCode = normalizeCouponCode(req.body && req.body.couponCode);

  if (!isUuid(id)) {
    return res.status(400).json({ error: 'Invalid order id' });
  }
  if (!isUuid(userId)) {
    return res.status(400).json({ error: 'Valid userId is required' });
  }
  if (!COUPON_CODE_REGEX.test(couponCode)) {
    return res.status(400).json({ error: 'Invalid coupon code format' });
  }

  try {
    const [orders] = await db.query(
      `SELECT id, user_id, total_amount, status, coupon_code
       FROM orders
       WHERE id = ? AND user_id = ?`,
      [id, userId]
    );
    if (orders.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    const order = orders[0];
    if (order.status !== 'pending') {
      return res.status(400).json({ error: 'Coupon can only be applied to pending orders' });
    }

    const [coupons] = await db.query(
      `SELECT id, code, discount_type, discount_value, max_redemptions, redemptions_count, starts_at, expires_at, is_active
       FROM coupons
       WHERE code = ?`,
      [couponCode]
    );
    if (coupons.length === 0) {
      return res.status(404).json({ error: 'Coupon not found' });
    }
    const coupon = coupons[0];
    const availability = validateCouponWindow(coupon);
    if (!availability.valid) {
      return res.status(400).json({ error: availability.reason });
    }

    const computed = computeCouponAmounts(order.total_amount, coupon);
    if (computed.error) {
      return res.status(400).json({ error: computed.error });
    }

    return res.json({
      valid: true,
      coupon: {
        code: coupon.code,
        discountType: coupon.discount_type,
        discountValue: Number(coupon.discount_value),
      },
      order: {
        totalAmount: Number(order.total_amount),
        discountAmount: computed.discountAmount,
        payableAmount: computed.payableAmount,
        alreadyApplied: order.coupon_code === coupon.code,
      },
    });
  } catch (err) {
    console.error('Validate coupon error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

// -------------------- POST /orders/:id/coupon/apply --------------------
exports.applyCouponToOrder = async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;
  const couponCode = normalizeCouponCode(req.body && req.body.couponCode);

  if (!isUuid(id)) {
    return res.status(400).json({ error: 'Invalid order id' });
  }
  if (!isUuid(userId)) {
    return res.status(400).json({ error: 'Valid userId is required' });
  }
  if (!COUPON_CODE_REGEX.test(couponCode)) {
    return res.status(400).json({ error: 'Invalid coupon code format' });
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    const [orders] = await connection.query(
      `SELECT id, user_id, total_amount, status, coupon_id
       FROM orders
       WHERE id = ? AND user_id = ?
       FOR UPDATE`,
      [id, userId]
    );
    if (orders.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Order not found' });
    }
    const order = orders[0];
    if (order.status !== 'pending') {
      await connection.rollback();
      return res.status(400).json({ error: 'Coupon can only be applied to pending orders' });
    }

    const [couponRows] = await connection.query(
      `SELECT id, code, discount_type, discount_value, max_redemptions, redemptions_count, starts_at, expires_at, is_active
       FROM coupons
       WHERE code = ?
       FOR UPDATE`,
      [couponCode]
    );
    if (couponRows.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Coupon not found' });
    }
    const coupon = couponRows[0];

    const [redemptions] = await connection.query(
      `SELECT id, coupon_id, status
       FROM coupon_redemptions
       WHERE order_id = ?
       LIMIT 1
       FOR UPDATE`,
      [id]
    );
    const alreadyReservedSameCoupon = redemptions.length > 0
      && redemptions[0].coupon_id === coupon.id
      && redemptions[0].status === 'reserved';

    const availability = validateCouponWindow(coupon);
    if (!availability.valid && !alreadyReservedSameCoupon) {
      await connection.rollback();
      return res.status(400).json({ error: availability.reason });
    }

    const computed = computeCouponAmounts(order.total_amount, coupon);
    if (computed.error) {
      await connection.rollback();
      return res.status(400).json({ error: computed.error });
    }

    let shouldReserveNew = false;
    if (redemptions.length === 0) {
      shouldReserveNew = true;
      await connection.query(
        `INSERT INTO coupon_redemptions
         (id, coupon_id, order_id, user_id, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'reserved', NOW(), NOW())`,
        [uuidv4(), coupon.id, id, userId]
      );
    } else {
      const redemption = redemptions[0];
      if (redemption.status === 'consumed') {
        await connection.rollback();
        return res.status(409).json({ error: 'Coupon for this order is already consumed' });
      }

      if (redemption.coupon_id !== coupon.id) {
        if (redemption.status === 'reserved') {
          await releaseCouponCount(connection, redemption.coupon_id);
        }
        shouldReserveNew = true;
        await connection.query(
          `UPDATE coupon_redemptions
           SET coupon_id = ?, status = 'reserved', updated_at = NOW()
           WHERE id = ?`,
          [coupon.id, redemption.id]
        );
      } else if (redemption.status === 'released') {
        shouldReserveNew = true;
        await connection.query(
          `UPDATE coupon_redemptions
           SET status = 'reserved', updated_at = NOW()
           WHERE id = ?`,
          [redemption.id]
        );
      }
    }

    if (shouldReserveNew) {
      const reserved = await reserveCouponCount(connection, coupon.id);
      if (!reserved) {
        await connection.rollback();
        return res.status(400).json({ error: 'Coupon redemption limit reached' });
      }
    }

    await connection.query(
      `UPDATE orders
       SET coupon_id = ?,
           coupon_code = ?,
           coupon_discount_type = ?,
           coupon_discount_value = ?,
           discount_amount = ?,
           payable_amount = ?,
           updated_at = NOW()
       WHERE id = ?`,
      [
        coupon.id,
        coupon.code,
        coupon.discount_type,
        coupon.discount_value,
        computed.discountAmount,
        computed.payableAmount,
        id,
      ]
    );

    await connection.commit();
    return res.json({
      message: 'Coupon applied successfully',
      orderId: id,
      coupon: {
        code: coupon.code,
        discountType: coupon.discount_type,
        discountValue: Number(coupon.discount_value),
      },
      amounts: {
        totalAmount: Number(order.total_amount),
        discountAmount: computed.discountAmount,
        payableAmount: computed.payableAmount,
      },
    });
  } catch (err) {
    await connection.rollback();
    console.error('Apply coupon error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
};

// -------------------- DELETE /orders/:id/coupon --------------------
exports.removeCouponFromOrder = async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  if (!isUuid(id)) {
    return res.status(400).json({ error: 'Invalid order id' });
  }
  if (!isUuid(userId)) {
    return res.status(400).json({ error: 'Valid userId is required' });
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    const [orders] = await connection.query(
      `SELECT id, total_amount, status, coupon_id
       FROM orders
       WHERE id = ? AND user_id = ?
       FOR UPDATE`,
      [id, userId]
    );
    if (orders.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Order not found' });
    }

    const order = orders[0];
    if (order.status !== 'pending') {
      await connection.rollback();
      return res.status(400).json({ error: 'Coupon can only be removed from pending orders' });
    }
    if (!order.coupon_id) {
      await connection.rollback();
      return res.status(400).json({ error: 'No coupon applied on this order' });
    }

    const [redemptions] = await connection.query(
      `SELECT id, coupon_id, status
       FROM coupon_redemptions
       WHERE order_id = ?
       LIMIT 1
       FOR UPDATE`,
      [id]
    );

    if (redemptions.length > 0 && redemptions[0].status === 'reserved') {
      await releaseCouponCount(connection, redemptions[0].coupon_id);
      await connection.query(
        `UPDATE coupon_redemptions
         SET status = 'released', updated_at = NOW()
         WHERE id = ?`,
        [redemptions[0].id]
      );
    }

    await connection.query(
      `UPDATE orders
       SET coupon_id = NULL,
           coupon_code = NULL,
           coupon_discount_type = NULL,
           coupon_discount_value = NULL,
           discount_amount = 0,
           payable_amount = total_amount,
           updated_at = NOW()
       WHERE id = ?`,
      [id]
    );

    await connection.commit();
    return res.json({
      message: 'Coupon removed successfully',
      orderId: id,
      payableAmount: Number(order.total_amount),
    });
  } catch (err) {
    await connection.rollback();
    console.error('Remove coupon error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
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
    const [orders] = await db.query('SELECT status FROM orders WHERE id = ?', [id]);
    if (orders.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const currentStatus = orders[0].status;
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

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    const [orders] = await connection.query(
      `SELECT id, status, total_amount, coupon_id
       FROM orders
       WHERE id = ? AND user_id = ?
       FOR UPDATE`,
      [id, userId]
    );
    if (orders.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Order not found' });
    }

    const order = orders[0];
    if (order.status !== 'pending') {
      await connection.rollback();
      return res.status(400).json({
        error: `Cannot cancel order in '${order.status}' status. Only pending orders can be cancelled.`,
      });
    }

    if (order.coupon_id) {
      const [redemptions] = await connection.query(
        `SELECT id, coupon_id, status
         FROM coupon_redemptions
         WHERE order_id = ?
         LIMIT 1
         FOR UPDATE`,
        [id]
      );
      if (redemptions.length > 0 && redemptions[0].status === 'reserved') {
        await releaseCouponCount(connection, redemptions[0].coupon_id);
        await connection.query(
          `UPDATE coupon_redemptions
           SET status = 'released', updated_at = NOW()
           WHERE id = ?`,
          [redemptions[0].id]
        );
      }

      await connection.query(
        `UPDATE orders
         SET coupon_id = NULL,
             coupon_code = NULL,
             coupon_discount_type = NULL,
             coupon_discount_value = NULL,
             discount_amount = 0,
             payable_amount = total_amount,
             updated_at = NOW()
         WHERE id = ?`,
        [id]
      );
    }

    await connection.query(
      'UPDATE orders SET status = ?, updated_at = NOW() WHERE id = ?',
      ['cancelled', id]
    );

    await connection.commit();
    res.json({ message: 'Order cancelled successfully' });
  } catch (err) {
    await connection.rollback();
    console.error('Cancel order error:', err);
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
};
