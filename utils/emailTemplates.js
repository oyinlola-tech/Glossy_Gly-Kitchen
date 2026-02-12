const escapeHtml = (value) => {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
};

const appName = 'Glossy_Gly-Kitchen';
const brandColor = '#e87423';
const accentColor = '#0b6d69';
const supportEmail = 'support@glossygly-kitchen.com';

const baseTemplate = ({ title, preheader, intro, contentHtml, outro }) => {
  const safeTitle = escapeHtml(title);
  const safePreheader = escapeHtml(preheader || title);
  const safeIntro = escapeHtml(intro || '');
  const safeOutro = escapeHtml(outro || `Thanks,\n${appName} Team`).replace(/\n/g, '<br>');

  const html = `
    <div style="display:none;opacity:0;overflow:hidden;max-height:0;max-width:0;">
      ${safePreheader}
    </div>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f8f6f3;padding:24px 8px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:640px;background:#ffffff;border-radius:16px;overflow:hidden;border:1px solid #efe9e2;box-shadow:0 8px 28px rgba(11,109,105,.08);">
            <tr>
              <td style="background:linear-gradient(120deg, ${brandColor}, ${accentColor});padding:22px 24px;color:#fff;font-family:Segoe UI,Arial,sans-serif;">
                <p style="margin:0 0 8px;font-size:12px;opacity:.92;letter-spacing:.3px;text-transform:uppercase;">Account Security Center</p>
                <h1 style="margin:0;font-size:22px;line-height:1.3;">${safeTitle}</h1>
              </td>
            </tr>
            <tr>
              <td style="padding:28px 24px;font-family:Segoe UI,Arial,sans-serif;color:#1f2937;font-size:15px;line-height:1.65;">
                ${safeIntro ? `<p style="margin:0 0 16px;">${safeIntro}</p>` : ''}
                ${contentHtml}
                <p style="margin:22px 0 0;color:#4b5563;">${safeOutro}</p>
                <p style="margin:16px 0 0;font-size:12px;color:#6b7280;">
                  Need help? Contact <a href="mailto:${supportEmail}" style="color:${accentColor};text-decoration:none;">${supportEmail}</a>
                </p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  `;

  const textParts = [title, intro, contentHtml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim(), outro]
    .filter(Boolean)
    .join('\n\n');

  return { html, text: textParts };
};

const otpBlock = (otp, caption) => {
  return `
    <div style="margin:18px 0;padding:16px;background:#fff5ec;border:1px solid #ffd9bc;border-radius:12px;">
      <p style="margin:0 0 8px;color:#7c2d12;font-weight:600;">${escapeHtml(caption)}</p>
      <div style="font-size:28px;letter-spacing:10px;font-weight:700;color:#111827;text-align:center;padding:8px 0;">
        ${escapeHtml(otp)}
      </div>
    </div>
  `;
};

const infoList = (rows) => {
  const items = rows
    .filter((row) => row && row.value)
    .map((row) => `<li style="margin:0 0 6px;"><strong>${escapeHtml(row.label)}:</strong> ${escapeHtml(row.value)}</li>`)
    .join('');
  if (!items) return '';
  return `<ul style="margin:14px 0 0;padding-left:18px;color:#374151;">${items}</ul>`;
};

const securityTipsBlock = (tips) => {
  if (!Array.isArray(tips) || tips.length === 0) return '';
  const items = tips
    .filter(Boolean)
    .map((tip) => `<li style="margin:0 0 6px;">${escapeHtml(tip)}</li>`)
    .join('');

  return `
    <div style="margin:18px 0 0;padding:14px 16px;background:#f2faf9;border:1px solid #cbe8e5;border-radius:12px;">
      <p style="margin:0 0 8px;color:#0f766e;font-weight:700;">Security tips</p>
      <ul style="margin:0;padding-left:18px;color:#0f172a;">
        ${items}
      </ul>
    </div>
  `;
};

const buildSignupVerificationEmail = ({ otp }) => {
  const subject = `${appName} - Verify Your Account`;
  const body = baseTemplate({
    title: 'Welcome to Glossy_Gly-Kitchen',
    preheader: 'Your account verification OTP',
    intro: 'Thanks for creating your account. Confirm your email with this OTP.',
    contentHtml: `
      ${otpBlock(otp, 'Verification OTP')}
      <p style="margin:10px 0 0;">This code expires in 10 minutes.</p>
      ${securityTipsBlock([
        'Never share this OTP with anyone, including support staff.',
        'If you did not initiate this request, ignore this email.',
        'Use a strong password and enable login OTP for better protection.',
      ])}
    `,
    outro: `If you did not create this account, please ignore this message.\n${appName} Security`,
  });
  return { subject, ...body };
};

const buildLoginOtpEmail = ({ otp }) => {
  const subject = `${appName} - Login OTP`;
  const body = baseTemplate({
    title: 'Login Verification',
    preheader: 'Use this OTP to sign in',
    intro: 'Use the OTP below to complete your login.',
    contentHtml: `
      ${otpBlock(otp, 'Login OTP')}
      <p style="margin:10px 0 0;">This code expires in 10 minutes.</p>
      ${securityTipsBlock([
        'Only enter this code on official Glossy_Gly-Kitchen pages.',
        'Do not forward this email to anyone.',
        'If login was not initiated by you, change your password immediately.',
      ])}
    `,
    outro: `If this was not you, reset your password immediately.\n${appName} Security`,
  });
  return { subject, ...body };
};

const buildPasswordResetOtpEmail = ({ otp }) => {
  const subject = `${appName} - Password Reset OTP`;
  const body = baseTemplate({
    title: 'Reset Your Password',
    preheader: 'Password reset OTP',
    intro: 'A password reset request was received for your account.',
    contentHtml: `
      ${otpBlock(otp, 'Password Reset OTP')}
      <p style="margin:10px 0 0;">This OTP expires in 10 minutes.</p>
      ${securityTipsBlock([
        'Use a new password not used on other websites.',
        'Do not share this OTP with anyone.',
        'If this request was not made by you, no changes will happen unless the OTP is used.',
      ])}
    `,
    outro: `If you did not request this, no action is required.\n${appName} Security`,
  });
  return { subject, ...body };
};

const buildPasswordChangedEmail = ({ ip, userAgent, changedAt }) => {
  const subject = `${appName} - Password Changed`;
  const details = infoList([
    { label: 'Time', value: changedAt || new Date().toISOString() },
    { label: 'IP', value: ip || 'Unknown' },
    { label: 'Device', value: userAgent || 'Unknown' },
  ]);
  const body = baseTemplate({
    title: 'Your Password Was Changed',
    preheader: 'Security notification',
    intro: 'Your account password was changed successfully.',
    contentHtml: `
      <p style="margin:0;">If this was not you, secure your account immediately and contact support.</p>
      ${details}
      ${securityTipsBlock([
        'Review recent account activity and remove unknown devices.',
        'Avoid reusing passwords across services.',
        'Update your password manager entry after every password reset.',
      ])}
    `,
  });
  return { subject, ...body };
};

const buildNewDeviceLoginAlertEmail = ({ ip, userAgent, loginAt }) => {
  const subject = `${appName} - New Device or IP Login Alert`;
  const details = infoList([
    { label: 'Time', value: loginAt || new Date().toISOString() },
    { label: 'IP', value: ip || 'Unknown' },
    { label: 'Device', value: userAgent || 'Unknown' },
  ]);
  const body = baseTemplate({
    title: 'New Login Detected',
    preheader: 'Security alert for your account',
    intro: 'We detected a login from a new device or IP address.',
    contentHtml: `
      <p style="margin:0;">If this was you, no action is needed.</p>
      ${details}
      ${securityTipsBlock([
        'If you do not recognize this login, change your password now.',
        'Log out of all sessions from your account settings.',
        'Contact support if suspicious activity continues.',
      ])}
    `,
    outro: `If this was not you, change your password immediately.\n${appName} Security`,
  });
  return { subject, ...body };
};

const buildWelcomeEmail = ({ email }) => {
  const subject = `${appName} - Welcome`;
  const details = infoList([
    { label: 'Account', value: email || null },
    { label: 'Status', value: 'Verified and Active' },
    { label: 'Joined', value: new Date().toISOString() },
  ]);
  const body = baseTemplate({
    title: 'Welcome to Glossy_Gly-Kitchen',
    preheader: 'Your account is ready',
    intro: 'Your email has been verified and your account is now active.',
    contentHtml: `
      <p style="margin:0;">You can now place orders, manage your profile, and track activity securely.</p>
      ${details}
      ${securityTipsBlock([
        'Complete your profile so account recovery is easier.',
        'Use a strong unique password for this account.',
        'Turn on login OTP whenever available.',
      ])}
    `,
    outro: `We are happy to have you with us.\n${appName} Team`,
  });
  return { subject, ...body };
};

const buildAccountDeletionOtpEmail = ({ otp }) => {
  const subject = `${appName} - Confirm Account Deletion`;
  const body = baseTemplate({
    title: 'Confirm Account Deletion',
    preheader: 'Use this OTP to confirm account deletion',
    intro: 'We received a request to permanently delete your account.',
    contentHtml: `
      ${otpBlock(otp, 'Deletion Confirmation OTP')}
      <p style="margin:10px 0 0;"><strong>Warning:</strong> This action is permanent and cannot be undone. This code expires in 10 minutes.</p>
      ${securityTipsBlock([
        'If you did not request deletion, ignore this email and change your password.',
        'Do not share this OTP with anyone for any reason.',
        'Review active sessions and logout unknown devices immediately.',
      ])}
    `,
    outro: `If this was not you, your account is still safe unless this OTP is used.\n${appName} Security`,
  });
  return { subject, ...body };
};

const buildAccountDeletedGoodbyeEmail = ({ email }) => {
  const subject = `${appName} - Account Deleted`;
  const details = infoList([
    { label: 'Account', value: email || null },
    { label: 'Deleted At', value: new Date().toISOString() },
  ]);
  const body = baseTemplate({
    title: 'Your Account Has Been Deleted',
    preheader: 'Account deletion confirmed',
    intro: 'Your Glossy_Gly-Kitchen account has been permanently deleted.',
    contentHtml: `
      <p style="margin:0;">We are sorry to see you go. If this action was unauthorized, contact support immediately.</p>
      ${details}
      ${securityTipsBlock([
        'If you did not request this, contact support as soon as possible.',
        'Update any saved credentials linked to this account.',
        'You can create a new account anytime with the same email if available.',
      ])}
    `,
    outro: `Goodbye and thank you for using ${appName}.`,
  });
  return { subject, ...body };
};

module.exports = {
  buildSignupVerificationEmail,
  buildLoginOtpEmail,
  buildPasswordResetOtpEmail,
  buildPasswordChangedEmail,
  buildNewDeviceLoginAlertEmail,
  buildWelcomeEmail,
  buildAccountDeletionOtpEmail,
  buildAccountDeletedGoodbyeEmail,
};
