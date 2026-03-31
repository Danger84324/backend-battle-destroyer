const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const User = require('../models/User');
const Stats = require('../models/Stats');

// ─── TOKEN BLACKLIST ──────────────────────────────────────────────────────────
// In production replace with Redis for persistence across restarts/instances.
const usedCaptchaTokens = new Map();

function blacklistToken(token) {
  usedCaptchaTokens.set(token, Date.now() + 310_000);
  for (const [t, exp] of usedCaptchaTokens) {
    if (Date.now() > exp) usedCaptchaTokens.delete(t);
  }
}

function isTokenBlacklisted(token) {
  const exp = usedCaptchaTokens.get(token);
  if (!exp) return false;
  if (Date.now() > exp) { usedCaptchaTokens.delete(token); return false; }
  return true;
}

// ─── TURNSTILE VERIFICATION ───────────────────────────────────────────────────
async function verifyTurnstile(token, ip) {
  if (!token || token.length < 10) {
    return { success: false, 'error-codes': ['missing-input-response'] };
  }
  if (isTokenBlacklisted(token)) {
    console.warn('⚠️  Replay attempt — token already used:', token.slice(0, 20) + '…');
    return { success: false, 'error-codes': ['duplicate-use'] };
  }
  try {
    const params = new URLSearchParams({
      secret: process.env.TURNSTILE_SECRET,
      response: token,
    });
    if (ip && ip !== '::1' && ip !== '127.0.0.1' && !ip.startsWith('::ffff:127')) {
      params.append('remoteip', ip);
    }
    const { data } = await axios.post(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      params,
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    if (data.success) blacklistToken(token);
    else console.warn('❌ Turnstile rejected:', data['error-codes']);
    return data;
  } catch (err) {
    console.error('❌ Turnstile request failed:', err.message);
    return { success: false, 'error-codes': ['internal-error'] };
  }
}

// ─── PASSWORD VALIDATION ──────────────────────────────────────────────────────
function validatePassword(password) {
  const errors = [];
  if (!password || password.length < 8) errors.push('Min 8 characters');
  if (!/[A-Z]/.test(password)) errors.push('At least 1 uppercase letter');
  if (!/[0-9]/.test(password)) errors.push('At least 1 number');
  if (!/[^A-Za-z0-9]/.test(password)) errors.push('At least 1 special character');
  return errors;
}

// ─── SIGNUP  POST /api/auth/signup ────────────────────────────────────────────
// ─── SIGNUP  POST /api/auth/signup ────────────────────────────────────────────
router.post('/signup', async (req, res) => {
  try {
    const { username, email, password, captchaToken, fingerprint, referralCode } = req.body;

    // ── Normalize IP (fixes localhost IPv6 variants) ──
    let ip = req.ip || '';
    if (ip.startsWith('::ffff:')) ip = ip.slice(7);
    if (ip === '::1') ip = '127.0.0.1';

    // ── Required fields ──
    if (!username || !email || !password || !captchaToken) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // ── CAPTCHA ──
    const captcha = await verifyTurnstile(captchaToken, ip);
    if (!captcha.success) {
      return res.status(400).json({
        message: captcha['error-codes']?.includes('duplicate-use')
          ? 'CAPTCHA already used. Please solve it again.'
          : 'CAPTCHA verification failed. Please try again.',
        codes: captcha['error-codes'],
      });
    }

    // ── Password strength ──
    const pwErrors = validatePassword(password);
    if (pwErrors.length) return res.status(400).json({ message: pwErrors[0] });

    // ── Username format ──
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({ message: 'Username must be 3–20 alphanumeric characters' });
    }

    // ── Duplicate check ──
    const exists = await User.findOne({ $or: [{ email }, { username }] });
    if (exists) return res.status(400).json({ message: 'Email or username already taken' });

    // ── Referral code check ──
    let referrer = null;
    if (referralCode) {
      referrer = await User.findOne({ referralCode: referralCode.trim() });
      if (!referrer) return res.status(400).json({ message: 'Invalid referral code' });
    }

    // ── Abuse check ──
    // Build query only for fields we actually have
    // Localhost IPs are excluded so dev/testing always gets 3 credits
    const isLocalhost = ip === '127.0.0.1';
    const abuseOrClauses = [];

    if (!isLocalhost && ip) abuseOrClauses.push({ ipAddress: ip });
    if (fingerprint) abuseOrClauses.push({ fingerprint });

    const abuseCheck = abuseOrClauses.length > 0
      ? await User.findOne({ $or: abuseOrClauses })
      : null;

    // Self-referral guard
    if (referrer && abuseCheck && abuseCheck._id.toString() === referrer._id.toString()) {
      return res.status(400).json({ message: 'Cannot use your own referral code' });
    }

    // ── Decide credits ──
    // New unique user → 3 free credits
    // Duplicate IP/fingerprint → 0 credits (abuse prevention)
    const isNewUniqueUser = !abuseCheck;
    const startingCredits = isNewUniqueUser ? 3 : 0;

    console.log(`[Signup] ${username} | IP: ${ip} | abuse: ${!!abuseCheck} | credits: ${startingCredits}`);

    // ── Create user ──
    const hashed = await bcrypt.hash(password, 12);

    const user = new User({
      username,
      email,
      password: hashed,
      credits: startingCredits,
      ipAddress: isLocalhost ? null : ip,  // don't store localhost IP
      fingerprint: fingerprint || null,
      creditGiven: isNewUniqueUser,
      referredBy: referrer ? referrer.referralCode : null,
      // referralCode & userId set by pre('save') hook
    });

    await user.save();

    // ── Reward referrer ──
    if (referrer && isNewUniqueUser) {
      await User.findByIdAndUpdate(referrer._id, {
        $inc: { credits: 2, referralCount: 1 }
      });
      console.log(`[Referral] ${referrer.username} +2 credits for referring ${username}`);
    }

    // ── JWT ──
    const token = jwt.sign(
      { id: user._id, userId: user.userId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // ── Global stats ──
    await Stats.findByIdAndUpdate(
      'global',
      { $inc: { totalUsers: 1 } },
      { upsert: true }
    );

    return res.status(201).json({
      message: 'Account created successfully!',
      token,
      user: {
        userId: user.userId,
        username: user.username,
        email: user.email,
        credits: user.credits,
        referralCode: user.referralCode,
        referralCount: user.referralCount,
        isPro: user.isPro,
      },
    });

  } catch (err) {
    console.error('Signup error:', err);

    if (err.code === 11000) {
      const field = Object.keys(err.keyPattern || {})[0] || 'field';
      return res.status(400).json({ message: `${field} already taken. Please try again.` });
    }

    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

// ─── LOGIN  POST /api/auth/login ──────────────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { email, password, captchaToken } = req.body;
    const ip = req.ip;

    if (!email || !password || !captchaToken) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const captcha = await verifyTurnstile(captchaToken, ip);
    if (!captcha.success) {
      return res.status(400).json({
        message: captcha['error-codes']?.includes('duplicate-use')
          ? 'CAPTCHA already used. Please solve it again.'
          : 'CAPTCHA verification failed. Please try again.',
        codes: captcha['error-codes'],
      });
    }

    const user = await User.findOne({ email });
    const credError = { message: 'Invalid email or password' };
    if (!user) return res.status(400).json(credError);

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json(credError);

    const token = jwt.sign(
      { id: user._id, userId: user.userId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      token,
      user: {
        userId: user.userId,
        username: user.username,
        email: user.email,
        credits: user.credits,
        referralCode: user.referralCode,
        referralCount: user.referralCount,
        isPro: user.isPro,
      },
    });

  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

module.exports = router;