const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const CryptoJS = require('crypto-js');
const User = require('../models/User');
const Stats = require('../models/Stats');
const { verifyCaptcha } = require('./captcha'); // Your hCaptcha module

// Encryption configuration
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'your-secret-key-2024-battle-destroyer';

/* ─── Encryption Helpers ──────────────────────────────────────── */

function decryptData(encryptedData) {
  try {
    const bytes = CryptoJS.AES.decrypt(encryptedData, ENCRYPTION_KEY);
    const decrypted = bytes.toString(CryptoJS.enc.Utf8);
    if (!decrypted) throw new Error('Decryption failed');
    return JSON.parse(decrypted);
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Invalid encrypted data');
  }
}

function encryptResponse(data) {
  const jsonString = JSON.stringify(data);
  return CryptoJS.AES.encrypt(jsonString, ENCRYPTION_KEY).toString();
}

function verifyHash(data, receivedHash) {
  const jsonString = JSON.stringify(data);
  const calculatedHash = CryptoJS.SHA256(jsonString + ENCRYPTION_KEY).toString();
  return calculatedHash === receivedHash;
}

function createHash(data) {
  const jsonString = JSON.stringify(data);
  return CryptoJS.SHA256(jsonString + ENCRYPTION_KEY).toString();
}

function sendEncryptedError(res, statusCode, message) {
  const errorResponse = { success: false, message };
  const encryptedError = encryptResponse(errorResponse);
  const errorHash = createHash(errorResponse);
  return res.status(statusCode).json({ encrypted: encryptedError, hash: errorHash });
}

/* ─── Shared IP extractor ─────────────────────────────────────── */

function getIp(req) {
  const raw = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '';
  let ip = raw.startsWith('::ffff:') ? raw.slice(7) : raw;
  if (ip === '::1') ip = '127.0.0.1';
  return ip;
}

/* ─── Password validation ─────────────────────────────────────── */

function validatePassword(password) {
  const errors = [];
  if (!password || password.length < 8) errors.push('Min 8 characters');
  if (!/[A-Z]/.test(password)) errors.push('At least 1 uppercase letter');
  if (!/[0-9]/.test(password)) errors.push('At least 1 number');
  if (!/[^A-Za-z0-9]/.test(password)) errors.push('At least 1 special character');
  return errors;
}

/* ─── SIGNUP with hCaptcha ───────────────────────────────── */

router.post('/signup', async (req, res) => {
  try {
    const { encrypted, hash, clientVersion } = req.body;

    if (!encrypted || !hash) {
      return sendEncryptedError(res, 400, 'Encrypted data required');
    }

    let decryptedData;
    try {
      decryptedData = decryptData(encrypted);
    } catch (err) {
      return sendEncryptedError(res, 400, 'Invalid encrypted payload');
    }

    if (!verifyHash(decryptedData, hash)) {
      return sendEncryptedError(res, 400, 'Data integrity check failed');
    }

    const currentTime = Date.now();
    const timeDiff = Math.abs(currentTime - decryptedData.timestamp);
    if (timeDiff > 5 * 60 * 1000) {
      return sendEncryptedError(res, 400, 'Request expired. Please try again.');
    }

    const { username, email, password, fingerprint, referralCode, captchaData, hp } = decryptedData;

    if (hp) {
      // For honeypot, still return encrypted response
      const responseData = { success: true, message: 'Account created successfully!' };
      const encryptedResponse = encryptResponse(responseData);
      const responseHash = createHash(responseData);
      return res.status(201).json({ encrypted: encryptedResponse, hash: responseHash });
    }

    if (!username || !email || !password || !captchaData) {
      return sendEncryptedError(res, 400, 'All fields are required');
    }

    const ip = getIp(req);
    const captchaToken = captchaData.token || captchaData;
    const captcha = await verifyCaptcha(captchaToken, null, ip);

    if (!captcha.ok) {
      console.log(`[Signup] Captcha failed for ${email}: ${captcha.reason}`);
      return sendEncryptedError(res, 400, captcha.reason || 'Captcha verification failed');
    }

    const pwErrors = validatePassword(password);
    if (pwErrors.length) {
      return sendEncryptedError(res, 400, pwErrors[0]);
    }

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return sendEncryptedError(res, 400, 'Username must be 3–20 alphanumeric characters');
    }

    const isInternalIp = /^(10\.|172\.16\.|192\.168\.|127\.)/.test(ip);
    
    // Check for existing user
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      if (existingUser.email === email) {
        return sendEncryptedError(res, 400, 'Email already registered. Please use a different email or login.');
      }
      if (existingUser.username === username) {
        return sendEncryptedError(res, 400, 'Username already taken. Please choose a different username.');
      }
    }

    let referrer = null;
    let isReferralValid = false;
    
    if (referralCode && referralCode.trim()) {
      referrer = await User.findOne({ referralCode: referralCode.trim() });
      if (referrer) {
        // Check if user is trying to use their own referral code
        if (referrer.email === email || referrer.username === username) {
          return sendEncryptedError(res, 400, 'Cannot use your own referral code');
        }
        isReferralValid = true;
        console.log(`[Signup] Valid referral code from ${referrer.username}`);
      } else {
        // Invalid referral code - continue signup but no referral bonus
        console.log(`[Signup] Invalid referral code: ${referralCode}`);
      }
    }

    const abuseOrClauses = [];
    if (!isInternalIp && ip) abuseOrClauses.push({ ipAddress: ip });
    if (fingerprint) abuseOrClauses.push({ fingerprint });

    const abuseCheck = abuseOrClauses.length
      ? await User.findOne({ $or: abuseOrClauses })
      : null;

    if (referrer && abuseCheck && abuseCheck._id.toString() === referrer._id.toString()) {
      return sendEncryptedError(res, 400, 'Cannot use your own referral code');
    }

    const isNewUniqueUser = !abuseCheck;
    const startingCredits = 0; // Start with 0 credits, will add referral bonus if applicable

    console.log(`[Signup] ${username} | IP: ${ip} | Referral: ${isReferralValid ? referrer.username : 'none'}`);

    const hashed = await bcrypt.hash(password, 12);
    
    // Calculate initial credits
    let initialCredits = startingCredits;
    
    // Give 2 credits to new user if valid referral
    if (isReferralValid) {
      initialCredits += 2;
      console.log(`[Signup] New user ${username} gets +2 referral credits`);
    }
    
    const user = new User({
      username,
      email,
      password: hashed,
      emailVerified: false,
      credits: initialCredits,
      ipAddress: isInternalIp ? null : ip,
      fingerprint: fingerprint || null,
      creditGiven: isNewUniqueUser,
      referredBy: referrer ? referrer.referralCode : null,
      subscription: {
        type: 'free',
        plan: 'none',
        dailyCredits: 1,
        lastCreditReset: new Date(),
      },
    });

    await user.save();
    console.log(`[Signup] User created: ${username} with ${initialCredits} credits`);

    // Handle referral credits - Give 2 credits to referrer if valid
    if (isReferralValid && referrer) {
      // Add 2 credits to referrer
      await User.findByIdAndUpdate(referrer._id, { 
        $inc: { credits: 2, referralCount: 1 } 
      });
      
      // Update referrer's credit in memory for logging
      const updatedReferrer = await User.findById(referrer._id);
      console.log(`[Referral] ✅ ${referrer.username} +2 credits (now has ${updatedReferrer.credits}) | ${username} +2 credits (now has ${user.credits})`);
    }

    // Generate and send OTP
    const { generateOTP, sendOTPEmail } = require('../services/emailService');
    const otp = generateOTP();
    user.otpCode = otp;
    user.otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000);
    user.otpAttempts = 0;
    await user.save();

    // Send OTP email
    const emailSent = await sendOTPEmail(email, otp, username);
    
    if (!emailSent) {
      console.error(`[Signup] Failed to send OTP to ${email}`);
    }

    await Stats.findByIdAndUpdate('global', { $inc: { totalUsers: 1 } }, { upsert: true });

    // Return response WITHOUT token - require OTP verification first
    const responseData = {
      success: true,
      requiresOTP: true,
      message: isReferralValid 
        ? `Verification code sent! You received +2 referral credits! Please verify your email.`
        : 'Verification code sent to your email. Please verify to complete registration.',
      userId: user.userId,
      email: email,
      referralBonus: isReferralValid ? 2 : 0,
    };

    const encryptedResponse = encryptResponse(responseData);
    const responseHash = createHash(responseData);

    return res.status(201).json({
      encrypted: encryptedResponse,
      hash: responseHash,
    });

  } catch (err) {
    console.error('Signup error:', err);
    if (err.code === 11000) {
      const field = Object.keys(err.keyPattern || {})[0] || 'field';
      const message = field === 'email' 
        ? 'Email already registered. Please use a different email.'
        : 'Username already taken. Please choose a different username.';
      return sendEncryptedError(res, 400, message);
    }
    return sendEncryptedError(res, 500, 'Server error. Please try again later.');
  }
});


// Complete signup after OTP verification
router.post('/complete-signup', async (req, res) => {
  try {
    const { encrypted, hash } = req.body;

    if (!encrypted || !hash) {
      return sendEncryptedError(res, 400, 'Encrypted data required');
    }

    let decryptedData;
    try {
      decryptedData = decryptData(encrypted);
    } catch (err) {
      return sendEncryptedError(res, 400, 'Invalid encrypted payload');
    }

    if (!verifyHash(decryptedData, hash)) {
      return sendEncryptedError(res, 400, 'Data integrity check failed');
    }

    const { userId, otp } = decryptedData;

    if (!userId || !otp) {
      return sendEncryptedError(res, 400, 'User ID and OTP required');
    }

    // Find the user
    const user = await User.findOne({ userId });
    
    if (!user) {
      return sendEncryptedError(res, 404, 'User not found');
    }

    // Check if already verified
    if (user.emailVerified) {
      return sendEncryptedError(res, 400, 'Email already verified');
    }

    // Check OTP attempts
    if (user.otpAttempts >= 5) {
      return sendEncryptedError(res, 400, 'Too many failed attempts. Please request a new OTP.');
    }

    // Check if OTP expired
    if (!user.otpCode || !user.otpExpiresAt || user.otpExpiresAt < new Date()) {
      return sendEncryptedError(res, 400, 'OTP expired. Please request a new verification code.');
    }

    // Verify OTP
    if (user.otpCode !== otp) {
      user.otpAttempts += 1;
      await user.save();
      const remaining = 5 - user.otpAttempts;
      return sendEncryptedError(res, 400, `Invalid OTP. ${remaining} attempts remaining.`);
    }

    // Mark as verified and clear OTP data
    user.emailVerified = true;
    user.otpCode = null;
    user.otpExpiresAt = null;
    user.otpAttempts = 0;
    
    // Give free credits on successful verification
    user.credits += 0; 
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { id: user._id, userId: user.userId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    const responseData = {
      success: true,
      message: 'Email verified successfully! Account is ready.',
      token,
      user: {
        userId: user.userId,
        username: user.username,
        email: user.email,
        credits: user.credits,
        referralCode: user.referralCode,
        referralCount: user.referralCount,
        isPro: user.isProUser(),
        subscription: user.subscription,
        remainingAttacks: await user.getRemainingAttacks(),
        maxDuration: user.getMaxDuration(),
      },
      timestamp: Date.now(),
    };

    const encryptedResponse = encryptResponse(responseData);
    const responseHash = createHash(responseData);

    return res.json({
      encrypted: encryptedResponse,
      hash: responseHash,
    });

  } catch (err) {
    console.error('Complete signup error:', err);
    return sendEncryptedError(res, 500, 'Server error. Please try again later.');
  }
});

// Resend OTP for existing unverified user
router.post('/resend-verification-email', async (req, res) => {
  try {
    const { encrypted, hash } = req.body;

    if (!encrypted || !hash) {
      return sendEncryptedError(res, 400, 'Encrypted data required');
    }

    let decryptedData;
    try {
      decryptedData = decryptData(encrypted);
    } catch (err) {
      return sendEncryptedError(res, 400, 'Invalid encrypted payload');
    }

    const { email } = decryptedData;

    if (!email) {
      return sendEncryptedError(res, 400, 'Email required');
    }

    const user = await User.findOne({ email });
    
    if (!user) {
      return sendEncryptedError(res, 404, 'User not found');
    }

    if (user.emailVerified) {
      return sendEncryptedError(res, 400, 'Email already verified');
    }

    // Generate new OTP
    const { generateOTP, sendOTPEmail } = require('../services/emailService');
    const otp = generateOTP();
    user.otpCode = otp;
    user.otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000);
    user.otpAttempts = 0;
    await user.save();

    const emailSent = await sendOTPEmail(user.email, otp, user.username);

    if (!emailSent) {
      return sendEncryptedError(res, 500, 'Failed to send OTP. Please try again.');
    }

    const responseData = {
      success: true,
      message: 'New verification code sent to your email',
      userId: user.userId,
    };

    const encryptedResponse = encryptResponse(responseData);
    const responseHash = createHash(responseData);

    return res.json({
      encrypted: encryptedResponse,
      hash: responseHash,
    });

  } catch (err) {
    console.error('Resend verification email error:', err);
    return sendEncryptedError(res, 500, 'Server error. Please try again later.');
  }
});

/* ─── LOGIN with hCaptcha ────────────────────────────────── */

router.post('/login', async (req, res) => {
  try {
    const { encrypted, hash, clientVersion } = req.body;

    if (!encrypted || !hash) {
      return sendEncryptedError(res, 400, 'Encrypted data required');
    }

    let decryptedData;
    try {
      decryptedData = decryptData(encrypted);
    } catch (err) {
      return sendEncryptedError(res, 400, 'Invalid encrypted payload');
    }

    if (!verifyHash(decryptedData, hash)) {
      return sendEncryptedError(res, 400, 'Data integrity check failed');
    }

    const currentTime = Date.now();
    const timeDiff = Math.abs(currentTime - decryptedData.timestamp);
    if (timeDiff > 5 * 60 * 1000) {
      return sendEncryptedError(res, 400, 'Request expired. Please try again.');
    }

    const { email, password, captchaData, hp } = decryptedData;

    if (hp) {
      return sendEncryptedError(res, 400, 'Invalid request');
    }

    if (!email || !password || !captchaData) {
      return sendEncryptedError(res, 400, 'All fields are required');
    }

    const ip = getIp(req);
    const captchaToken = captchaData.token || captchaData;
    const captcha = await verifyCaptcha(captchaToken, null, ip);

    if (!captcha.ok) {
      console.log(`[Login] Captcha failed for ${email}: ${captcha.reason}`);
      return sendEncryptedError(res, 400, captcha.reason || 'Captcha verification failed');
    }

    console.log(`[Login] Captcha passed for ${email}`);

    const user = await User.findOne({ email });
    if (!user) {
      return sendEncryptedError(res, 400, 'Invalid email or password');
    }

    // ✅ ADD THIS CHECK - Prevent unverified users from logging in
    if (!user.emailVerified) {
      console.log(`[Login] Unverified email attempt: ${email}`);
      return sendEncryptedError(res, 401, 'Please verify your email before logging in. Check your inbox for the verification code.');
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return sendEncryptedError(res, 400, 'Invalid email or password');
    }

    await user.checkAndResetDailyCredits();

    const token = jwt.sign(
      { id: user._id, userId: user.userId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    const responseData = {
      success: true,
      token,
      user: {
        userId: user.userId,
        username: user.username,
        email: user.email,
        credits: user.credits,
        referralCode: user.referralCode,
        referralCount: user.referralCount,
        isPro: user.isProUser(),
        subscription: user.subscription,
        remainingAttacks: await user.getRemainingAttacks(),
        maxDuration: user.getMaxDuration(),
        totalAttacks: user.totalAttacks,
      },
      timestamp: Date.now(),
    };

    const encryptedResponse = encryptResponse(responseData);
    const responseHash = createHash(responseData);

    return res.json({
      encrypted: encryptedResponse,
      hash: responseHash,
    });

  } catch (err) {
    console.error('Login error:', err);
    return sendEncryptedError(res, 500, 'Server error. Please try again later.');
  }
});

module.exports = router;