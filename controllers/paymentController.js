const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const db = require('../config/db');
const { isUuid } = require('../utils/validation');
const { initializeTransaction, verifyTransaction, chargeAuthorization, verifyWebhookSignature } = require('../utils/paystack');
const { isTransitionAllowed } = require('../utils/statusTransitions');
const { sendMail } = require('../utils/mailer');
const { buildReceiptEmail } = require('../utils/receiptTemplate');

const buildReference = (orderId, prefix = 'PSK') => `${prefix}-${orderId.slice(0, 8)}-${Date.now()}`;
const sha256Hex = (value) => crypto.createHash('sha256').update(String(value || ''), 'utf8').digest('hex');
const isValidReference = (value) => typeof value === 'string' && /^[A-Za-z0-9._:-]{6,120}$/.test(value);

const resolveReceiptStatus = (remoteStatus, gatewayResponse) => {
  const status = String(remoteStatus || '').toLowerCase();
  if (status === 'success') return 'success';
  if (status === 'failed') return 'failed';
  if (status === 'abandoned') return 'failed';
  if (String(gatewayResponse || '').toLowerCase().includes('declined')) return 'declined';
  return status || 'failed';
};

const consumeCouponRedemption = async (connection, orderId) => {
  const [rows] = await connection.query(
    `SELECT id, status
     FROM coupon_redemptions
     WHERE order_id = ?
     LIMIT 1
     FOR UPDATE`,
    [orderId]
  );
  if (rows.length === 0) return;
  if (rows[0].status !== 'reserved') return;

  await connection.query(
    `UPDATE coupon_redemptions
     SET status = 'consumed', updated_at = NOW()
     WHERE id = ?`,
    [rows[0].id]
  );
};

const getOrderEmailAndItems = async (connection, orderId) => {
  const [orders] = await connection.query(
    `SELECT o.id, o.total_amount, COALESCE(o.payable_amount, o.total_amount) AS payable_amount, u.email
     FROM orders o
     JOIN users u ON u.id = o.user_id
     WHERE o.id = ?`,
    [orderId]
  );
  if (orders.length === 0) return null;

  const [items] = await connection.query(
    `SELECT oi.quantity, oi.price_at_order, fi.name
     FROM order_items oi
     JOIN food_items fi ON fi.id = oi.food_id
     WHERE oi.order_id = ?`,
    [orderId]
  );

  return {
    orderId: orders[0].id,
    totalAmount: orders[0].payable_amount,
    customerEmail: orders[0].email,
    items,
  };
};

const sendReceiptForOrder = async ({ orderId, paymentReference, status }) => {
  try {
    const data = await getOrderEmailAndItems(db, orderId);
    if (!data || !data.customerEmail) return;

    const email = buildReceiptEmail({
      customerEmail: data.customerEmail,
      orderId: data.orderId,
      paymentReference,
      status,
      items: data.items,
      totalAmount: data.totalAmount,
      currency: 'NGN',
    });

    await sendMail({
      to: data.customerEmail,
      subject: email.subject,
      html: email.html,
      text: email.text,
    });
  } catch (err) {
    console.error('Failed to send receipt email:', err.message);
  }
};

const upsertSavedCard = async (connection, userId, authorization) => {
  if (!authorization || !authorization.authorization_code) return null;
  if (!authorization.reusable) return null;

  const signature = authorization.signature || authorization.authorization_code;

  const [existing] = await connection.query(
    'SELECT id FROM user_payment_cards WHERE user_id = ? AND signature = ? LIMIT 1',
    [userId, signature]
  );

  if (existing.length > 0) {
    await connection.query(
      `UPDATE user_payment_cards
       SET authorization_code = ?, last4 = ?, exp_month = ?, exp_year = ?, card_type = ?, bank = ?, account_name = ?,
           reusable = ?, updated_at = NOW()
       WHERE id = ?`,
      [
        authorization.authorization_code,
        authorization.last4 || null,
        authorization.exp_month || null,
        authorization.exp_year || null,
        authorization.card_type || null,
        authorization.bank || null,
        authorization.account_name || null,
        authorization.reusable ? 1 : 0,
        existing[0].id,
      ]
    );
    return existing[0].id;
  }

  const [defaultCards] = await connection.query(
    'SELECT id FROM user_payment_cards WHERE user_id = ? AND is_default = 1 LIMIT 1',
    [userId]
  );
  const isDefault = defaultCards.length === 0 ? 1 : 0;
  const cardId = uuidv4();

  await connection.query(
    `INSERT INTO user_payment_cards
     (id, user_id, provider, authorization_code, signature, last4, exp_month, exp_year, card_type, bank, account_name, reusable, is_default, created_at, updated_at)
     VALUES (?, ?, 'paystack', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
    [
      cardId,
      userId,
      authorization.authorization_code,
      signature,
      authorization.last4 || null,
      authorization.exp_month || null,
      authorization.exp_year || null,
      authorization.card_type || null,
      authorization.bank || null,
      authorization.account_name || null,
      authorization.reusable ? 1 : 0,
      isDefault,
    ]
  );

  return cardId;
};

const markPaymentSuccessAndConfirmOrder = async (connection, paymentRow, verifyData, saveCard = false) => {
  await connection.query(
    `UPDATE payments
     SET status = 'success',
         paid_at = COALESCE(?, NOW()),
         gateway_response = ?,
         updated_at = NOW()
     WHERE id = ?`,
    [verifyData.paid_at ? new Date(verifyData.paid_at) : null, JSON.stringify(verifyData), paymentRow.id]
  );

  if (saveCard) {
    await upsertSavedCard(connection, paymentRow.user_id, verifyData.authorization);
  }

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
  await consumeCouponRedemption(connection, paymentRow.order_id);
};

const reserveWebhookEvent = async (connection, { provider, eventId, reference, signatureHash, payloadHash }) => {
  const eventRowId = uuidv4();
  await connection.query(
    `INSERT INTO webhook_event_receipts
     (id, provider, event_id, reference, signature_hash, payload_hash, first_seen_at, processed_at)
     VALUES (?, ?, ?, ?, ?, ?, NOW(), NULL)
     ON DUPLICATE KEY UPDATE
       id = id`,
    [eventRowId, provider, eventId || null, reference || null, signatureHash, payloadHash]
  );

  const [rows] = await connection.query(
    `SELECT id, processed_at
     FROM webhook_event_receipts
     WHERE provider = ? AND signature_hash = ?
     FOR UPDATE`,
    [provider, signatureHash]
  );
  if (rows.length === 0) {
    throw new Error('Webhook receipt lookup failed');
  }
  if (rows[0].processed_at) {
    return { accepted: false, eventRowId: rows[0].id };
  }
  await connection.query(
    `UPDATE webhook_event_receipts
     SET event_id = COALESCE(event_id, ?),
         reference = COALESCE(reference, ?),
         payload_hash = ?
     WHERE id = ?`,
    [eventId || null, reference || null, payloadHash, rows[0].id]
  );
  return { accepted: true, eventRowId: rows[0].id };
};

const markWebhookEventProcessed = async (connection, eventRowId) => {
  await connection.query(
    `UPDATE webhook_event_receipts
     SET processed_at = NOW()
     WHERE id = ?`,
    [eventRowId]
  );
};

exports.initialize = async (req, res) => {
  const { orderId, callbackUrl, saveCard } = req.body;
  const userId = req.user.id;

  if (!isUuid(orderId)) {
    return res.status(400).json({ error: 'Valid orderId is required' });
  }
  if (callbackUrl !== undefined && callbackUrl !== null) {
    if (typeof callbackUrl !== 'string' || callbackUrl.length > 500) {
      return res.status(400).json({ error: 'Invalid callbackUrl' });
    }
    try {
      const u = new URL(callbackUrl);
      if (u.protocol !== 'https:') {
        return res.status(400).json({ error: 'callbackUrl must use https' });
      }
    } catch {
      return res.status(400).json({ error: 'Invalid callbackUrl' });
    }
  }

  try {
    const [orders] = await db.query(
      `SELECT o.id, o.user_id, o.total_amount, COALESCE(o.payable_amount, o.total_amount) AS payable_amount, o.status, u.email
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
      amount: order.payable_amount,
      reference,
      callbackUrl,
      metadata: { orderId, userId, saveCard: Boolean(saveCard) },
    });

    await db.query(
      `INSERT INTO payments
       (id, order_id, user_id, provider, reference, amount, currency, status, gateway_response, created_at, updated_at)
       VALUES (?, ?, ?, 'paystack', ?, ?, 'NGN', 'initialized', ?, NOW(), NOW())`,
      [uuidv4(), orderId, userId, reference, order.payable_amount, JSON.stringify({ access_code: data.access_code || null, saveCard: Boolean(saveCard) })]
    );

    return res.status(201).json({
      message: 'Payment initialized successfully',
      orderId,
      reference,
      authorizationUrl: data.authorization_url,
      accessCode: data.access_code,
      saveCard: Boolean(saveCard),
    });
  } catch (err) {
    console.error('Initialize payment error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.verify = async (req, res) => {
  const { reference } = req.params;
  const userId = req.user.id;

  if (!isValidReference(reference)) {
    return res.status(400).json({ error: 'Invalid reference' });
  }

  const connection = await db.getConnection();
  let orderIdForReceipt = null;
  let receiptStatus = null;
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
    if (payment.status === 'success') {
      await connection.commit();
      return res.json({
        message: 'Payment already verified',
        reference,
        status: 'success',
        orderId: payment.order_id,
      });
    }

    const verifyData = await verifyTransaction(reference);
    const remoteStatus = String(verifyData.status || '').toLowerCase();
    const saveCardRequested = Boolean(verifyData.metadata && verifyData.metadata.saveCard);
    orderIdForReceipt = payment.order_id;

    if (remoteStatus === 'success') {
      await markPaymentSuccessAndConfirmOrder(connection, payment, verifyData, saveCardRequested);
      receiptStatus = 'success';
    } else if (['failed', 'abandoned'].includes(remoteStatus)) {
      await connection.query(
        `UPDATE payments
         SET status = ?, gateway_response = ?, updated_at = NOW()
         WHERE id = ?`,
        [remoteStatus, JSON.stringify(verifyData), payment.id]
      );
      receiptStatus = resolveReceiptStatus(remoteStatus, verifyData.gateway_response);
    }

    await connection.commit();

    if (receiptStatus) {
      await sendReceiptForOrder({
        orderId: orderIdForReceipt,
        paymentReference: reference,
        status: receiptStatus,
      });
    }

    return res.json({
      message: 'Payment verification completed',
      reference,
      status: remoteStatus || payment.status,
      orderId: payment.order_id,
    });
  } catch (err) {
    await connection.rollback();
    console.error('Verify payment error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
};

exports.attachCard = async (req, res) => {
  const { reference } = req.body;
  const userId = req.user.id;

  if (!isValidReference(reference)) {
    return res.status(400).json({ error: 'Invalid reference' });
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    const [payments] = await connection.query(
      `SELECT id, user_id, order_id
       FROM payments
       WHERE reference = ? AND user_id = ?
       FOR UPDATE`,
      [reference, userId]
    );
    if (payments.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Payment not found for this user' });
    }

    const verifyData = await verifyTransaction(reference);
    if (String(verifyData.status || '').toLowerCase() !== 'success') {
      await connection.rollback();
      return res.status(400).json({ error: 'Only successful payments can be used to save a card' });
    }
    if (!verifyData.authorization || !verifyData.authorization.reusable) {
      await connection.rollback();
      return res.status(400).json({ error: 'This card authorization is not reusable' });
    }

    const cardId = await upsertSavedCard(connection, userId, verifyData.authorization);
    await connection.commit();

    const [cards] = await db.query(
      `SELECT id, provider, last4, exp_month, exp_year, card_type, bank, account_name, is_default, created_at, updated_at
       FROM user_payment_cards
       WHERE id = ?`,
      [cardId]
    );

    return res.status(201).json({
      message: 'Card saved successfully',
      card: cards[0],
    });
  } catch (err) {
    await connection.rollback();
    console.error('Attach card error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
};

exports.listCards = async (req, res) => {
  const userId = req.user.id;
  try {
    const [cards] = await db.query(
      `SELECT id, provider, last4, exp_month, exp_year, card_type, bank, account_name, is_default, created_at, updated_at
       FROM user_payment_cards
       WHERE user_id = ?
       ORDER BY is_default DESC, updated_at DESC`,
      [userId]
    );
    return res.json({ cards });
  } catch (err) {
    console.error('List cards error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.setDefaultCard = async (req, res) => {
  const userId = req.user.id;
  const { cardId } = req.params;
  if (!isUuid(cardId)) {
    return res.status(400).json({ error: 'Invalid cardId' });
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();
    const [cards] = await connection.query(
      `SELECT id
       FROM user_payment_cards
       WHERE id = ? AND user_id = ?
       FOR UPDATE`,
      [cardId, userId]
    );
    if (cards.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Card not found' });
    }

    await connection.query(
      'UPDATE user_payment_cards SET is_default = 0, updated_at = NOW() WHERE user_id = ?',
      [userId]
    );
    await connection.query(
      'UPDATE user_payment_cards SET is_default = 1, updated_at = NOW() WHERE id = ? AND user_id = ?',
      [cardId, userId]
    );

    await connection.commit();
    return res.json({ message: 'Default card updated successfully' });
  } catch (err) {
    await connection.rollback();
    console.error('Set default card error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
};

exports.deleteCard = async (req, res) => {
  const userId = req.user.id;
  const { cardId } = req.params;
  if (!isUuid(cardId)) {
    return res.status(400).json({ error: 'Invalid cardId' });
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();
    const [cards] = await connection.query(
      `SELECT id, is_default
       FROM user_payment_cards
       WHERE id = ? AND user_id = ?
       FOR UPDATE`,
      [cardId, userId]
    );
    if (cards.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Card not found' });
    }

    await connection.query('DELETE FROM user_payment_cards WHERE id = ?', [cardId]);

    if (cards[0].is_default) {
      const [remaining] = await connection.query(
        `SELECT id
         FROM user_payment_cards
         WHERE user_id = ?
         ORDER BY updated_at DESC
         LIMIT 1`,
        [userId]
      );
      if (remaining.length > 0) {
        await connection.query('UPDATE user_payment_cards SET is_default = 1, updated_at = NOW() WHERE id = ?', [remaining[0].id]);
      }
    }

    await connection.commit();
    return res.json({ message: 'Card removed successfully' });
  } catch (err) {
    await connection.rollback();
    console.error('Delete card error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
};

exports.payWithSavedCard = async (req, res) => {
  const userId = req.user.id;
  const { orderId, cardId } = req.body;

  if (!isUuid(orderId)) {
    return res.status(400).json({ error: 'Valid orderId is required' });
  }
  if (!isUuid(cardId)) {
    return res.status(400).json({ error: 'Valid cardId is required' });
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    const [orders] = await connection.query(
      `SELECT o.id, o.user_id, o.total_amount, COALESCE(o.payable_amount, o.total_amount) AS payable_amount, o.status, u.email
       FROM orders o
       JOIN users u ON u.id = o.user_id
       WHERE o.id = ? AND o.user_id = ?
       FOR UPDATE`,
      [orderId, userId]
    );
    if (orders.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Order not found' });
    }

    const order = orders[0];
    if (order.status === 'cancelled' || order.status === 'completed') {
      await connection.rollback();
      return res.status(400).json({ error: `Cannot pay for '${order.status}' order` });
    }

    const [successful] = await connection.query(
      `SELECT id, reference
       FROM payments
       WHERE order_id = ? AND status = 'success'
       LIMIT 1`,
      [orderId]
    );
    if (successful.length > 0) {
      await connection.rollback();
      return res.status(409).json({ error: 'Payment already completed for this order', reference: successful[0].reference });
    }

    const [cards] = await connection.query(
      `SELECT id, authorization_code
       FROM user_payment_cards
       WHERE id = ? AND user_id = ? AND reusable = 1
       FOR UPDATE`,
      [cardId, userId]
    );
    if (cards.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Reusable saved card not found' });
    }

    const reference = buildReference(orderId, 'PSK-AUTO');
    const chargeData = await chargeAuthorization({
      email: order.email,
      amount: order.payable_amount,
      authorizationCode: cards[0].authorization_code,
      reference,
      metadata: { orderId, userId, autoDebit: true, cardId },
    });
    const chargeStatus = String(chargeData.status || '').toLowerCase();

    await connection.query(
      `INSERT INTO payments
       (id, order_id, user_id, provider, reference, amount, currency, status, gateway_response, paid_at, created_at, updated_at)
       VALUES (?, ?, ?, 'paystack', ?, ?, 'NGN', ?, ?, ?, NOW(), NOW())`,
      [
        uuidv4(),
        orderId,
        userId,
        reference,
        order.payable_amount,
        chargeStatus === 'success' ? 'success' : 'failed',
        JSON.stringify(chargeData),
        chargeStatus === 'success' ? (chargeData.paid_at ? new Date(chargeData.paid_at) : new Date()) : null,
      ]
    );

    if (chargeStatus === 'success') {
      if (isTransitionAllowed(order.status, 'confirmed')) {
        await connection.query('UPDATE orders SET status = ?, updated_at = NOW() WHERE id = ?', ['confirmed', orderId]);
      }
      await consumeCouponRedemption(connection, orderId);
      await connection.query('UPDATE user_payment_cards SET last_used_at = NOW(), updated_at = NOW() WHERE id = ?', [cardId]);
      await connection.commit();

      await sendReceiptForOrder({
        orderId,
        paymentReference: reference,
        status: 'success',
      });

      return res.status(201).json({
        message: 'Payment completed with saved card',
        orderId,
        reference,
        status: 'success',
      });
    }

    await connection.commit();

    const failStatus = resolveReceiptStatus(chargeStatus, chargeData.gateway_response);
    await sendReceiptForOrder({
      orderId,
      paymentReference: reference,
      status: failStatus,
    });

    return res.status(402).json({
      error: 'Automatic card debit failed',
      orderId,
      reference,
      status: chargeStatus || 'failed',
      gatewayResponse: chargeData.gateway_response || null,
    });
  } catch (err) {
    await connection.rollback();
    console.error('Pay with saved card error:', err);
    return res.status(500).json({ error: 'Internal server error' });
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
  const eventId = event.id ? String(event.id) : null;
  const reference = data.reference;
  const status = String(data.status || '').toLowerCase();
  const signatureHash = sha256Hex(String(signature || '').trim().toLowerCase());
  const payloadHash = sha256Hex(rawBody);

  const connection = await db.getConnection();
  let webhookEventRowId = null;
  let orderIdForReceipt = null;
  let receiptStatus = null;
  try {
    await connection.beginTransaction();

    const replay = await reserveWebhookEvent(connection, {
      provider: 'paystack',
      eventId,
      reference,
      signatureHash,
      payloadHash,
    });
    webhookEventRowId = replay.eventRowId;

    if (!replay.accepted) {
      await connection.commit();
      return res.status(200).json({ message: 'Replay ignored' });
    }

    if (!reference) {
      await markWebhookEventProcessed(connection, webhookEventRowId);
      await connection.commit();
      return res.status(200).json({ message: 'Webhook received' });
    }
    if (!isValidReference(reference)) {
      await markWebhookEventProcessed(connection, webhookEventRowId);
      await connection.commit();
      return res.status(200).json({ message: 'Webhook received' });
    }

    const [rows] = await connection.query(
      `SELECT id, order_id, user_id, status
       FROM payments
       WHERE reference = ?
       FOR UPDATE`,
      [reference]
    );

    if (rows.length === 0) {
      await markWebhookEventProcessed(connection, webhookEventRowId);
      await connection.commit();
      return res.status(200).json({ message: 'Webhook received' });
    }

    const payment = rows[0];
    orderIdForReceipt = payment.order_id;

    if (payment.status === 'success') {
      await markWebhookEventProcessed(connection, webhookEventRowId);
      await connection.commit();
      return res.status(200).json({ message: 'Already processed' });
    }

    if (event.event === 'charge.success' || status === 'success') {
      const saveCardRequested = Boolean(data.metadata && data.metadata.saveCard);
      await markPaymentSuccessAndConfirmOrder(connection, payment, data, saveCardRequested);
      receiptStatus = 'success';
    } else if (status === 'failed' || status === 'abandoned') {
      await connection.query(
        `UPDATE payments
         SET status = ?, gateway_response = ?, updated_at = NOW()
         WHERE id = ?`,
        [status, JSON.stringify(data), payment.id]
      );
      receiptStatus = resolveReceiptStatus(status, data.gateway_response);
    }

    await markWebhookEventProcessed(connection, webhookEventRowId);
    await connection.commit();

    if (receiptStatus) {
      await sendReceiptForOrder({
        orderId: orderIdForReceipt,
        paymentReference: reference,
        status: receiptStatus,
      });
    }

    return res.status(200).json({ message: 'Webhook processed' });
  } catch (err) {
    await connection.rollback();
    console.error('Paystack webhook error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
  }
};
