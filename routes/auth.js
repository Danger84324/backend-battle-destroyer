/**
 * routes/auth.js
 * Key change: verifyCaptcha() now receives the real IP so all
 * IP-based protections in captcha.js actually fire.
 */

const express = require('express');
const router  = express.Router();
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const User    = require('../models/User');
const Stats   = require('../models/Stats');
const { verifyCaptcha } = require('./captcha');

/* ─── Shared IP extractor (same logic as captcha.js) ─────────── */

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

/* ─── SIGNUP ──────────────────────────────────────────────────── */

router.post('/signup', async (req, res) => {
  try {
    const {
      username, email, password,
      fingerprint, referralCode,
      challengeId, solution, answer,
      hp,                           // honeypot
    } = req.body;

    /* 1. Honeypot — bots that auto-fill hidden fields are silently dropped */
    if (hp) {
      return res.status(201).json({ message: 'Account created successfully!' });
    }

    /* 2. Required fields */
    if (!username || !email || !password || !challengeId || solution === undefined || answer === undefined) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    /* 3. Captcha — pass real IP so IP-binding + attempt limits work */
    const ip      = getIp(req);
    const captcha = verifyCaptcha(challengeId, solution, answer, ip);
    if (!captcha.ok) {
      return res.status(400).json({ message: captcha.reason || 'Captcha verification failed' });
    }

    /* 4. Password strength */
    const pwErrors = validatePassword(password);
    if (pwErrors.length) return res.status(400).json({ message: pwErrors[0] });

    /* 5. Username format */
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({ message: 'Username must be 3–20 alphanumeric characters' });
    }

    /* 6. Internal IP flag */
    const isInternalIp = /^(10\.|172\.16\.|192\.168\.|127\.)/.test(ip);

    /* 7. Duplicate check */
    const exists = await User.findOne({ $or: [{ email }, { username }] });
    if (exists) return res.status(400).json({ message: 'Email or username already taken' });

    /* 8. Referral code */
    let referrer = null;
    if (referralCode) {
      referrer = await User.findOne({ referralCode: referralCode.trim() });
      if (!referrer) return res.status(400).json({ message: 'Invalid referral code' });
    }

    /* 9. Abuse / duplicate device check */
    const abuseOrClauses = [];
    if (!isInternalIp && ip)  abuseOrClauses.push({ ipAddress: ip });
    if (fingerprint)          abuseOrClauses.push({ fingerprint });

    const abuseCheck = abuseOrClauses.length
      ? await User.findOne({ $or: abuseOrClauses })
      : null;

    /* 10. Self-referral guard */
    if (referrer && abuseCheck && abuseCheck._id.toString() === referrer._id.toString()) {
      return res.status(400).json({ message: 'Cannot use your own referral code' });
    }

    const isNewUniqueUser = !abuseCheck;
    const startingCredits = isNewUniqueUser ? 10 : 0;

    console.log(`[Signup] ${username} | IP: ${ip} | internal: ${isInternalIp} | abuse: ${!!abuseCheck} | credits: ${startingCredits}`);

    /* 11. Create user */
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

    /* 12. Referral rewards */
    if (referrer && isNewUniqueUser) {
      await User.findByIdAndUpdate(referrer._id, { $inc: { credits: 2, referralCount: 1 } });
      await User.findByIdAndUpdate(user._id,     { $inc: { credits: 2 } });
      user.credits += 2;
      console.log(`[Referral] ${referrer.username} +2  |  ${username} +2`);
    }

    /* 13. JWT */
    const token = jwt.sign(
      { id: user._id, userId: user.userId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    /* 14. Global stats */
    await Stats.findByIdAndUpdate('global', { $inc: { totalUsers: 1 } }, { upsert: true });

    return res.status(201).json({
      message: 'Account created successfully! You received 10 free credits!',
      token,
      user: {
        userId:           user.userId,
        username:         user.username,
        email:            user.email,
        credits:          user.credits,
        referralCode:     user.referralCode,
        referralCount:    user.referralCount,
        isPro:            user.isProUser(),
        subscription:     user.subscription,
        remainingAttacks: await user.getRemainingAttacks(),
        maxDuration:      user.getMaxDuration(),
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

/* ─── LOGIN ───────────────────────────────────────────────────── */

router.post('/login', async (req, res) => {
  try {
    const { email, password, challengeId, solution, answer, hp } = req.body;

    /* Honeypot */
    if (hp) return res.status(400).json({ message: 'Invalid request' });

    if (!email || !password || !challengeId || solution === undefined || answer === undefined) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    /* Captcha — pass real IP */
    const ip      = getIp(req);
    const captcha = verifyCaptcha(challengeId, solution, answer, ip);
    if (!captcha.ok) {
      return res.status(400).json({ message: captcha.reason || 'Captcha verification failed' });
    }

    /* Credentials */
    const user = await User.findOne({ email });
    const credError = { message: 'Invalid email or password' };
    if (!user) return res.status(400).json(credError);

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json(credError);

    await user.checkAndResetDailyCredits();

    const token = jwt.sign(
      { id: user._id, userId: user.userId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      token,
      user: {
        userId:           user.userId,
        username:         user.username,
        email:            user.email,
        credits:          user.credits,
        referralCode:     user.referralCode,
        referralCount:    user.referralCount,
        isPro:            user.isProUser(),
        subscription:     user.subscription,
        remainingAttacks: await user.getRemainingAttacks(),
        maxDuration:      user.getMaxDuration(),
        totalAttacks:     user.totalAttacks,
      },
    });

  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

module.exports = router;