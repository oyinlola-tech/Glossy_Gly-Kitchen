const { v4: uuidv4 } = require('uuid');
const db = require('../config/db');
const { isUuid } = require('../utils/validation');
const { initializeTransaction, verifyTransaction, verifyWebhookSignature } = require('../utils/paystack');
const { isTransitionAllowed } = require('../utils/statusTransitions');

const buildReference = (orderId) => `PSK-${orderId.slice(0, 8)}-${Date.now()}`;

exports.initialize = async (req, res) => {
  const { orderId, callbackUrl } = req.body;
  const userId = req.user.id;

  if (!isUuid(orderId)) {
    return res.status(400).json({ error: 'Valid orderId is required' });
  }

  try {
    const [orders] = await db.query(
      `SELECT o.id, o.user_id, o.total_amount, o.status, u.email
       FROM orders o
       JOIN users u ON u.id = o.user_id
       WHERE o.id = ? AND o.user_id = ?`,
      [orderId, userId]
    );

    if (orders.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const order = orders[0];
    if (order.status === 'cancelled' || order.status === 'completed') {
      return res.status(400).json({ error: `Cannot initialize payment for '${order.status}' order` });
    }
    if (!order.email) {
      return res.status(400).json({ error: 'User email is required for payment initialization' });
    }

    const [successful] = await db.query(
      `SELECT id, reference
       FROM payments
       WHERE order_id = ? AND status = 'success'
       LIMIT 1`,
      [orderId]
    );
    if (successful.length > 0) {
      return res.status(409).json({ error: 'Payment already completed for this order', reference: successful[0].reference });
    }

    const reference = buildReference(orderId);
    const data = await initializeTransaction({
      email: order.email,
      amount: order.total_amount,
      reference,
      callbackUrl,
      metadata: { orderId, userId },
    });

    await db.query(
      `INSERT INTO payments
       (id, order_id, user_id, provider, reference, amount, currency, status, gateway_response, created_at, updated_at)
       VALUES (?, ?, ?, 'paystack', ?, ?, 'NGN', 'initialized', ?, NOW(), NOW())`,
      [uuidv4(), orderId, userId, reference, order.total_amount, JSON.stringify({ access_code: data.access_code || null })]
    );

    return res.status(201).json({
      message: 'Payment initialized successfully',
      orderId,
      reference,
      authorizationUrl: data.authorization_url,
      accessCode: data.access_code,
    });
  } catch (err) {
    console.error('Initialize payment error:', err);
    return res.status(500).json({ error: err.message || 'Internal server error' });
  }
};

const markPaymentSuccessAndConfirmOrder = async (connection, paymentRow, verifyData) => {
  await connection.query(
    `UPDATE payments
     SET status = 'success',
         paid_at = COALESCE(?, NOW()),
         gateway_response = ?,
         updated_at = NOW()
     WHERE id = ?`,
    [verifyData.paid_at ? new Date(verifyData.paid_at) : null, JSON.stringify(verifyData), paymentRow.id]
  );

  const [orders] = await connection.query('SELECT status FROM orders WHERE id = ? FOR UPDATE', [paymentRow.order_id]);
  if (orders.length === 0) return;

  const currentStatus = orders[0].status;
  if (isTransitionAllowed(currentStatus, 'confirmed')) {
    await connection.query(
      `UPDATE orders
       SET status = 'confirmed', updated_at = NOW()
       WHERE id = ?`,
      [paymentRow.order_id]
    );
  }
};

exports.verify = async (req, res) => {
  const { reference } = req.params;
  const userId = req.user.id;

  if (!reference || typeof reference !== 'string') {
    return res.status(400).json({ error: 'reference is required' });
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    const [rows] = await connection.query(
      `SELECT id, order_id, user_id, status, reference
       FROM payments
       WHERE reference = ?
       FOR UPDATE`,
      [reference]
    );
    if (rows.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Payment not found' });
    }

    const payment = rows[0];
    if (payment.user_id !== userId) {
      await connection.rollback();
      return res.status(403).json({ error: 'Forbidden' });
    }

    const verifyData = await verifyTransaction(reference);
    const remoteStatus = String(verifyData.status || '').toLowerCase();

    if (remoteStatus === 'success') {
      await markPaymentSuccessAndConfirmOrder(connection, payment, verifyData);
    } else if (['failed', 'abandoned'].includes(remoteStatus)) {
      await connection.query(
        `UPDATE payments
         SET status = ?, gateway_response = ?, updated_at = NOW()
         WHERE id = ?`,
        [remoteStatus, JSON.stringify(verifyData), payment.id]
      );
    }

    await connection.commit();
    return res.json({
      message: 'Payment verification completed',
      reference,
      status: remoteStatus || payment.status,
      orderId: payment.order_id,
    });
  } catch (err) {
    await connection.rollback();
    console.error('Verify payment error:', err);
    return res.status(500).json({ error: err.message || 'Internal server error' });
  } finally {
    connection.release();
  }
};

exports.paystackWebhook = async (req, res) => {
  const signature = req.get('x-paystack-signature');
  const rawBody = req.rawBody;

  if (!verifyWebhookSignature(rawBody, signature)) {
    return res.status(401).json({ error: 'Invalid webhook signature' });
  }

  const event = req.body || {};
  const data = event.data || {};
  const reference = data.reference;
  const status = String(data.status || '').toLowerCase();

  if (!reference) {
    return res.status(200).json({ message: 'Webhook received' });
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();
    const [rows] = await connection.query(
      `SELECT id, order_id, status
       FROM payments
       WHERE reference = ?
       FOR UPDATE`,
      [reference]
    );

    if (rows.length === 0) {
      await connection.commit();
      return res.status(200).json({ message: 'Webhook received' });
    }

    const payment = rows[0];

    if (payment.status === 'success') {
      await connection.commit();
      return res.status(200).json({ message: 'Already processed' });
    }

    if (event.event === 'charge.success' || status === 'success') {
      await markPaymentSuccessAndConfirmOrder(connection, payment, data);
    } else if (status === 'failed' || status === 'abandoned') {
      await connection.query(
        `UPDATE payments
         SET status = ?, gateway_response = ?, updated_at = NOW()
         WHERE id = ?`,
        [status, JSON.stringify(data), payment.id]
      );
    }

    await connection.commit();
    return res.status(200).json({ message: 'Webhook processed' });
  } catch (err) {
    await connection.rollback();
    console.error('Paystack webhook error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
};
