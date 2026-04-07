// services/emailService.js
const nodemailer = require('nodemailer');

// Create transporter (free tier)
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.EMAIL_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_APP_PASSWORD,
  },
  tls: {
    rejectUnauthorized: false
  }
});

// Generate 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Send OTP email
async function sendOTPEmail(email, otp, username = '') {
  const mailOptions = {
    from: `"Battle Destroyer" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Verify Your Battle Destroyer Account',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verify Your Account</title>
        <style>
          body { font-family: 'Arial', sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }
          .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
          .header { background: linear-gradient(135deg, #ef4444, #dc2626); padding: 30px; text-align: center; }
          .header h1 { color: white; margin: 0; font-size: 28px; letter-spacing: 2px; }
          .content { padding: 40px 30px; text-align: center; }
          .otp-code { background: #f8f9fa; padding: 20px; font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #dc2626; border-radius: 8px; margin: 20px 0; font-family: monospace; }
          .warning { color: #666; font-size: 12px; margin-top: 20px; padding-top: 20px; border-top: 1px solid #eee; }
          .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; }
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
            <p>Thanks for signing up! Please use the following verification code to complete your registration:</p>
            <div class="otp-code">${otp}</div>
            <p>This code will expire in <strong>10 minutes</strong>.</p>
            <p>If you didn't request this, please ignore this email.</p>
            <div class="warning">
              <strong>⚠️ Security Notice</strong><br>
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
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`[Email] OTP sent to ${email}`);
    return true;
  } catch (error) {
    console.error('[Email] Send failed:', error);
    return false;
  }
}

// Send welcome email after verification
async function sendWelcomeEmail(email, username) {
  const mailOptions = {
    from: `"Battle Destroyer" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Welcome to Battle Destroyer! 🎮',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to Battle Destroyer</title>
        <style>
          body { font-family: 'Arial', sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }
          .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
          .header { background: linear-gradient(135deg, #ef4444, #dc2626); padding: 30px; text-align: center; }
          .header h1 { color: white; margin: 0; font-size: 28px; letter-spacing: 2px; }
          .content { padding: 40px 30px; text-align: center; }
          .button { background: linear-gradient(135deg, #ef4444, #dc2626); color: white; padding: 12px 30px; text-decoration: none; border-radius: 8px; display: inline-block; margin: 20px 0; font-weight: bold; }
          .features { text-align: left; margin: 30px 0; padding: 0 20px; }
          .feature { margin: 15px 0; padding: 10px; background: #f8f9fa; border-radius: 8px; }
          .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>BATTLE DESTROYER</h1>
          </div>
          <div class="content">
            <h2>Welcome, ${username}! 🎉</h2>
            <p>Your account has been successfully verified and created!</p>
            <div class="features">
              <div class="feature">
                <strong>✨ 3 Free Credits</strong> - Start attacking immediately
              </div>
              <div class="feature">
                <strong>🔗 Referral System</strong> - Earn +2 credits per referral
              </div>
              <div class="feature">
                <strong>🛡️ Device Protection</strong> - Your account is secured
              </div>
            </div>
            <a href="${process.env.FRONTEND_URL || 'http://localhost:3000'}/dashboard" class="button">Start Attacking →</a>
            <p>Ready to dominate the battlefield?</p>
          </div>
          <div class="footer">
            <p>Battle Destroyer - Attack with Honor</p>
          </div>
        </div>
      </body>
      </html>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`[Email] Welcome email sent to ${email}`);
    return true;
  } catch (error) {
    console.error('[Email] Welcome email failed:', error);
    return false;
  }
}

module.exports = { generateOTP, sendOTPEmail, sendWelcomeEmail };