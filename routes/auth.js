const express = require('express');
const router  = express.Router();
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const CryptoJS = require('crypto-js');
const User    = require('../models/User');
const Stats   = require('../models/Stats');
const { verifyCaptcha } = require('./captcha');

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
  if (!password || password.length < 8)  errors.push('Min 8 characters');
  if (!/[A-Z]/.test(password))           errors.push('At least 1 uppercase letter');
  if (!/[0-9]/.test(password))           errors.push('At least 1 number');
  if (!/[^A-Za-z0-9]/.test(password))   errors.push('At least 1 special character');
  return errors;
}

/* ─── SIGNUP with full encryption ───────────────────────────────── */

router.post('/signup', async (req, res) => {
  try {
    const { encrypted, hash, clientVersion } = req.body;

    // Check if encrypted data exists
    if (!encrypted || !hash) {
      return res.status(400).json({ message: 'Encrypted data required' });
    }

    // Decrypt the data
    let decryptedData;
    try {
      decryptedData = decryptData(encrypted);
    } catch (err) {
      return res.status(400).json({ message: 'Invalid encrypted payload' });
    }

    // Verify hash integrity
    if (!verifyHash(decryptedData, hash)) {
      return res.status(400).json({ message: 'Data integrity check failed' });
    }

    // Check timestamp to prevent replay attacks (allow 5 minutes window)
    const currentTime = Date.now();
    const timeDiff = Math.abs(currentTime - decryptedData.timestamp);
    if (timeDiff > 5 * 60 * 1000) {
      return res.status(400).json({ message: 'Request expired. Please try again.' });
    }

    const {
      username, email, password,
      fingerprint, referralCode,
      captchaData,
      hp,
    } = decryptedData;

    /* Honeypot check */
    if (hp) {
      return res.status(201).json({ message: 'Account created successfully!' });
    }

    /* Required fields */
    if (!username || !email || !password || !captchaData) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    /* Captcha verification */
    const ip = getIp(req);
    const captcha = verifyCaptcha(
      captchaData.encrypted,
      captchaData.hash,
      ip
    );
    
    if (!captcha.ok) {
      return res.status(400).json({ message: captcha.reason || 'Captcha verification failed' });
    }

    /* Password strength */
    const pwErrors = validatePassword(password);
    if (pwErrors.length) return res.status(400).json({ message: pwErrors[0] });

    /* Username format */
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({ message: 'Username must be 3–20 alphanumeric characters' });
    }

    /* Internal IP flag */
    const isInternalIp = /^(10\.|172\.16\.|192\.168\.|127\.)/.test(ip);

    /* Duplicate check */
    const exists = await User.findOne({ $or: [{ email }, { username }] });
    if (exists) return res.status(400).json({ message: 'Email or username already taken' });

    /* Referral code */
    let referrer = null;
    if (referralCode) {
      referrer = await User.findOne({ referralCode: referralCode.trim() });
      if (!referrer) return res.status(400).json({ message: 'Invalid referral code' });
    }

    /* Abuse / duplicate device check */
    const abuseOrClauses = [];
    if (!isInternalIp && ip) abuseOrClauses.push({ ipAddress: ip });
    if (fingerprint) abuseOrClauses.push({ fingerprint });

    const abuseCheck = abuseOrClauses.length
      ? await User.findOne({ $or: abuseOrClauses })
      : null;

    /* Self-referral guard */
    if (referrer && abuseCheck && abuseCheck._id.toString() === referrer._id.toString()) {
      return res.status(400).json({ message: 'Cannot use your own referral code' });
    }

    const isNewUniqueUser = !abuseCheck;
    const startingCredits = isNewUniqueUser ? 10 : 0;

    console.log(`[Signup] ${username} | IP: ${ip} | credits: ${startingCredits}`);

    /* Create user */
    const hashed = await bcrypt.hash(password, 12);
    const user = new User({
      username,
      email,
      password: hashed,
      credits: startingCredits,
      ipAddress: isInternalIp ? null : ip,
      fingerprint: fingerprint || null,
      creditGiven: isNewUniqueUser,
      referredBy: referrer ? referrer.referralCode : null,
      subscription: {
        type: 'free',
        plan: 'none',
        dailyCredits: 10,
        lastCreditReset: new Date(),
      },
    });

    await user.save();

    /* Referral rewards */
    if (referrer && isNewUniqueUser) {
      await User.findByIdAndUpdate(referrer._id, { $inc: { credits: 2, referralCount: 1 } });
      await User.findByIdAndUpdate(user._id, { $inc: { credits: 2 } });
      user.credits += 2;
      console.log(`[Referral] ${referrer.username} +2 | ${username} +2`);
    }

    /* JWT */
    const token = jwt.sign(
      { id: user._id, userId: user.userId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    /* Global stats */
    await Stats.findByIdAndUpdate('global', { $inc: { totalUsers: 1 } }, { upsert: true });

    /* Prepare response data */
    const responseData = {
      success: true,
      message: 'Account created successfully! You received 10 free credits!',
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

    /* Encrypt response */
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
      const errorResponse = { success: false, message: `${field} already taken. Please try again.` };
      const encryptedError = encryptResponse(errorResponse);
      const errorHash = createHash(errorResponse);
      return res.status(400).json({ encrypted: encryptedError, hash: errorHash });
    }
    const errorResponse = { success: false, message: 'Server error. Please try again.' };
    const encryptedError = encryptResponse(errorResponse);
    const errorHash = createHash(errorResponse);
    return res.status(500).json({ encrypted: encryptedError, hash: errorHash });
  }
});

/* ─── LOGIN with full encryption ────────────────────────────────── */

router.post('/login', async (req, res) => {
  try {
    const { encrypted, hash, clientVersion } = req.body;

    // Check if encrypted data exists
    if (!encrypted || !hash) {
      return res.status(400).json({ message: 'Encrypted data required' });
    }

    // Decrypt the data
    let decryptedData;
    try {
      decryptedData = decryptData(encrypted);
    } catch (err) {
      return res.status(400).json({ message: 'Invalid encrypted payload' });
    }

    // Verify hash integrity
    if (!verifyHash(decryptedData, hash)) {
      return res.status(400).json({ message: 'Data integrity check failed' });
    }

    // Check timestamp
    const currentTime = Date.now();
    const timeDiff = Math.abs(currentTime - decryptedData.timestamp);
    if (timeDiff > 5 * 60 * 1000) {
      return res.status(400).json({ message: 'Request expired. Please try again.' });
    }

    const { email, password, captchaData, hp } = decryptedData;

    /* Honeypot */
    if (hp) return res.status(400).json({ message: 'Invalid request' });

    if (!email || !password || !captchaData) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    /* Captcha verification */
    const ip = getIp(req);
    const captcha = verifyCaptcha(
      captchaData.encrypted,
      captchaData.hash,
      ip
    );
    
    if (!captcha.ok) {
      return res.status(400).json({ message: captcha.reason || 'Captcha verification failed' });
    }

    /* Credentials */
    const user = await User.findOne({ email });
    const credError = { success: false, message: 'Invalid email or password' };
    if (!user) {
      const encryptedError = encryptResponse(credError);
      const errorHash = createHash(credError);
      return res.status(400).json({ encrypted: encryptedError, hash: errorHash });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      const encryptedError = encryptResponse(credError);
      const errorHash = createHash(credError);
      return res.status(400).json({ encrypted: encryptedError, hash: errorHash });
    }

    await user.checkAndResetDailyCredits();

    const token = jwt.sign(
      { id: user._id, userId: user.userId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    /* Prepare response data */
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

    /* Encrypt response */
    const encryptedResponse = encryptResponse(responseData);
    const responseHash = createHash(responseData);

    return res.json({
      encrypted: encryptedResponse,
      hash: responseHash,
    });

  } catch (err) {
    console.error('Login error:', err);
    const errorResponse = { success: false, message: 'Server error. Please try again.' };
    const encryptedError = encryptResponse(errorResponse);
    const errorHash = createHash(errorResponse);
    return res.status(500).json({ encrypted: encryptedError, hash: errorHash });
  }
});

module.exports = router;