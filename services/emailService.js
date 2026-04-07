// services/emailService.js
// Uses Brevo HTTP API directly (axios) — no broken npm package needed
const axios = require('axios');

const BREVO_API_KEY = process.env.BREVO_API_KEY;
const FROM_EMAIL   = process.env.BREVO_SENDER_EMAIL || process.env.EMAIL_FROM || 'hsbgmi200@gmail.com';
const FROM_NAME    = process.env.EMAIL_FROM_NAME    || 'Battle Destroyer';
const FRONTEND_URL = process.env.FRONTEND_URL       || 'https://battle-destroyer.shop';

if (BREVO_API_KEY) {
  console.log('[Email] Brevo HTTP API initialized successfully');
} else {
  console.warn('[Email] BREVO_API_KEY not found in environment variables');
}

// Generate 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Core send function using Brevo REST API
async function sendBrevoEmail(to, toName, subject, html) {
  if (!BREVO_API_KEY) {
    console.error('[Email] BREVO_API_KEY not set, cannot send email');
    return false;
  }

  try {
    const response = await axios.post(
      'https://api.brevo.com/v3/smtp/email',
      {
        sender:      { email: FROM_EMAIL, name: FROM_NAME },
        to:          [{ email: to, name: toName || to.split('@')[0] }],
        subject,
        htmlContent: html,
      },
      {
        headers: {
          'api-key':      BREVO_API_KEY,
          'Content-Type': 'application/json',
          'Accept':       'application/json',
        },
        timeout: 15000,
      }
    );

    console.log(`[Email] Sent to ${to} | MessageId: ${response.data?.messageId || 'ok'}`);
    return true;
  } catch (error) {
    const msg = error.response?.data?.message || error.message;
    console.error(`[Email] Send failed to ${to}: ${msg}`);
    return false;
  }
}

// Send OTP email
async function sendOTPEmail(email, otp, username = '') {
  const subject = 'Verify Your Battle Destroyer Account';
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Verify Your Account</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #ef4444, #dc2626); padding: 30px; text-align: center; }
        .header h1 { color: white; margin: 0; font-size: 28px; letter-spacing: 2px; }
        .content { padding: 40px 30px; text-align: center; }
        .otp-code { background: #f8f9fa; padding: 20px; font-size: 42px; font-weight: bold; letter-spacing: 12px; color: #dc2626; border-radius: 8px; margin: 24px 0; font-family: monospace; border: 2px dashed #dc2626; }
        .expire-note { color: #888; font-size: 14px; margin: 10px 0 20px; }
        .warning { color: #666; font-size: 12px; margin-top: 20px; padding-top: 20px; border-top: 1px solid #eee; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #999; font-size: 12px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>BATTLE DESTROYER</h1>
        </div>
        <div class="content">
          <h2>Verify Your Email Address</h2>
          ${username ? `<p>Hello <strong>${username}</strong>,</p>` : '<p>Hello,</p>'}
          <p>Thanks for signing up! Use the code below to complete your registration:</p>
          <div class="otp-code">${otp}</div>
          <p class="expire-note">This code expires in <strong>10 minutes</strong>.</p>
          <p>If you did not create an account, you can safely ignore this email.</p>
          <div class="warning">
            <strong>Security Notice</strong><br>
            Never share this code with anyone. Battle Destroyer will never ask for this code outside the registration process.
          </div>
        </div>
        <div class="footer">
          <p>Battle Destroyer - Attack with Honor</p>
          <p>&copy; ${new Date().getFullYear()} Battle Destroyer. All rights reserved.</p>
        </div>
      </div>
    </body>
    </html>
  `;

  return await sendBrevoEmail(email, username, subject, html);
}

module.exports = { generateOTP, sendOTPEmail };