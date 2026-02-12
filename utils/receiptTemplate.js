const formatMoney = (value, currency = 'NGN') => {
  const amount = Number(value || 0);
  return new Intl.NumberFormat('en-NG', {
    style: 'currency',
    currency,
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(amount);
};

const escapeHtml = (value) =>
  String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

const buildRows = (items, currency) =>
  items
    .map((item) => {
      const quantity = Number(item.quantity || 0);
      const unitPrice = Number(item.price_at_order || 0);
      const lineTotal = quantity * unitPrice;
      return `
        <tr>
          <td style="padding:12px 10px;border-bottom:1px solid #f0f0f0;">${escapeHtml(item.name)}</td>
          <td style="padding:12px 10px;border-bottom:1px solid #f0f0f0;text-align:center;">${quantity}</td>
          <td style="padding:12px 10px;border-bottom:1px solid #f0f0f0;text-align:right;">${formatMoney(unitPrice, currency)}</td>
          <td style="padding:12px 10px;border-bottom:1px solid #f0f0f0;text-align:right;font-weight:600;">${formatMoney(lineTotal, currency)}</td>
        </tr>
      `;
    })
    .join('');

const statusStyle = (status) => {
  if (status === 'success') {
    return { label: 'Payment Successful', bg: '#e8fff3', color: '#0a7a4b', border: '#8be3ba' };
  }
  if (status === 'failed' || status === 'declined') {
    return { label: 'Payment Failed', bg: '#fff0f0', color: '#a31515', border: '#f2a5a5' };
  }
  return { label: 'Payment Status Update', bg: '#f3f4ff', color: '#2d3cae', border: '#bec6ff' };
};

const buildReceiptEmail = ({ customerEmail, orderId, paymentReference, status, items, totalAmount, currency = 'NGN' }) => {
  const safeItems = Array.isArray(items) ? items : [];
  const badge = statusStyle(String(status || '').toLowerCase());
  const safeOrderId = escapeHtml(orderId);
  const safeReference = escapeHtml(paymentReference || 'N/A');
  const safeEmail = escapeHtml(customerEmail);
  const createdOn = new Date().toLocaleString('en-NG', { timeZone: 'Africa/Lagos' });
  const title = badge.label;

  const html = `
  <div style="margin:0;padding:32px 12px;background:linear-gradient(135deg,#fff7ed 0%,#fff 45%,#f8fafc 100%);font-family:Segoe UI,Arial,sans-serif;color:#0f172a;">
    <div style="max-width:760px;margin:0 auto;background:#fff;border:1px solid #ececec;border-radius:18px;overflow:hidden;box-shadow:0 8px 30px rgba(2,6,23,0.08);">
      <div style="padding:28px 30px;background:linear-gradient(120deg,#fb923c 0%,#ea580c 100%);color:#fff;">
        <div style="font-size:13px;letter-spacing:1.4px;text-transform:uppercase;opacity:0.88;">Glossy_Gly-Kitchen</div>
        <h1 style="margin:8px 0 0;font-size:26px;line-height:1.2;">Order Receipt</h1>
      </div>

      <div style="padding:24px 30px 10px;">
        <div style="display:inline-block;padding:8px 14px;border-radius:999px;border:1px solid ${badge.border};background:${badge.bg};color:${badge.color};font-size:13px;font-weight:700;">
          ${badge.label}
        </div>
      </div>

      <div style="padding:14px 30px 6px;font-size:14px;color:#334155;">
        <div style="margin-bottom:4px;"><strong>Order ID:</strong> ${safeOrderId}</div>
        <div style="margin-bottom:4px;"><strong>Payment Ref:</strong> ${safeReference}</div>
        <div style="margin-bottom:4px;"><strong>Customer:</strong> ${safeEmail}</div>
        <div><strong>Generated:</strong> ${escapeHtml(createdOn)}</div>
      </div>

      <div style="padding:22px 30px 10px;">
        <table style="width:100%;border-collapse:collapse;border:1px solid #f0f0f0;border-radius:10px;overflow:hidden;">
          <thead>
            <tr style="background:#f8fafc;color:#334155;font-size:13px;text-transform:uppercase;letter-spacing:0.4px;">
              <th style="padding:12px 10px;text-align:left;">Item</th>
              <th style="padding:12px 10px;text-align:center;">Qty</th>
              <th style="padding:12px 10px;text-align:right;">Amount</th>
              <th style="padding:12px 10px;text-align:right;">Line Total</th>
            </tr>
          </thead>
          <tbody>
            ${buildRows(safeItems, currency)}
          </tbody>
        </table>
      </div>

      <div style="padding:10px 30px 26px;display:flex;justify-content:flex-end;">
        <div style="min-width:260px;border:1px solid #f1f5f9;border-radius:12px;padding:14px 16px;background:#fafafa;">
          <div style="display:flex;justify-content:space-between;font-size:16px;font-weight:700;">
            <span>Total</span>
            <span>${formatMoney(totalAmount, currency)}</span>
          </div>
        </div>
      </div>

      <div style="padding:16px 30px 24px;background:#f8fafc;border-top:1px solid #eef2f7;font-size:12px;color:#64748b;">
        This receipt reflects your latest payment attempt for this order. If this status is incorrect, contact support with your payment reference.
      </div>
    </div>
  </div>`;

  const text = [
    'Glossy_Gly-Kitchen - Order Receipt',
    `Status: ${title}`,
    `Order ID: ${orderId}`,
    `Payment Reference: ${paymentReference || 'N/A'}`,
    `Customer: ${customerEmail}`,
    '',
    'Items:',
    ...safeItems.map((item) => {
      const quantity = Number(item.quantity || 0);
      const unit = Number(item.price_at_order || 0);
      const lineTotal = quantity * unit;
      return `- ${item.name} | Qty: ${quantity} | Amount: ${formatMoney(unit, currency)} | Line Total: ${formatMoney(lineTotal, currency)}`;
    }),
    '',
    `Total: ${formatMoney(totalAmount, currency)}`,
  ].join('\n');

  return {
    subject: `Receipt - ${title} (${orderId})`,
    html,
    text,
  };
};

module.exports = {
  buildReceiptEmail,
};
