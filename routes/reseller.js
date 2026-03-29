const express  = require('express');
const router   = express.Router();
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const Reseller = require('../models/Reseller');
const User     = require('../models/User');

// ===== RATE LIMITERS =====
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  skipSuccessfulRequests: true,
  message: { message: 'Too many login attempts. Try again in 15 minutes.' },
});

const actionLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 30,
  message: { message: 'Too many requests. Slow down.' },
});

// ===== BRUTE FORCE MAP FOR LOGIN =====
const loginAttempts = new Map();
const MAX_LOGIN     = 5;
const LOCKOUT_MS    = 15 * 60 * 1000;

setInterval(() => {
  const now = Date.now();
  for (const [ip, r] of loginAttempts.entries()) {
    if (r.lockedUntil < now && r.count === 0) loginAttempts.delete(ip);
  }
}, 30 * 60 * 1000);

// ===== JWT AUTH MIDDLEWARE =====
function resellerAuth(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  try {
    const decoded = jwt.verify(auth.slice(7), process.env.RESELLER_JWT_SECRET || process.env.JWT_SECRET);
    if (decoded.role !== 'reseller') return res.status(403).json({ message: 'Forbidden' });
    req.resellerId = decoded.id;
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

// ===== POST /api/reseller/login =====
router.post('/login', loginLimiter, async (req, res) => {
  const ip     = req.ip;
  const now    = Date.now();
  const record = loginAttempts.get(ip) || { count: 0, lockedUntil: 0 };

  if (record.lockedUntil > now) {
    const s = Math.ceil((record.lockedUntil - now) / 1000);
    return res.status(429).json({ message: `Account locked. Try again in ${s}s.` });
  }

  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  try {
    const reseller = await Reseller.findOne({
      $or: [{ username: username.trim() }, { email: username.trim().toLowerCase() }]
    });

    if (!reseller || !(await bcrypt.compare(password, reseller.password))) {
      record.count += 1;
      if (record.count >= MAX_LOGIN) {
        record.lockedUntil = now + LOCKOUT_MS;
        record.count = 0;
        loginAttempts.set(ip, record);
        return res.status(429).json({ message: 'Too many failed attempts. IP locked for 15 minutes.' });
      }
      loginAttempts.set(ip, record);
      return res.status(401).json({
        message: `Invalid credentials. ${MAX_LOGIN - record.count} attempts remaining.`
      });
    }

    if (reseller.isBlocked) {
      return res.status(403).json({ message: 'Your reseller account has been blocked. Contact admin.' });
    }

    loginAttempts.delete(ip);
    reseller.lastLogin = new Date();
    await reseller.save();

    const token = jwt.sign(
      { id: reseller._id, role: 'reseller' },
      process.env.RESELLER_JWT_SECRET || process.env.JWT_SECRET,
      { expiresIn: '12h' }
    );

    res.json({
      token,
      reseller: {
        id: reseller._id,
        username: reseller.username,
        email: reseller.email,
        credits: reseller.credits,
        totalGiven: reseller.totalGiven,
      }
    });
  } catch {
    res.status(500).json({ message: 'Server error' });
  }
});

// ===== GET /api/reseller/me =====
router.get('/me', resellerAuth, async (req, res) => {
  try {
    const reseller = await Reseller.findById(req.resellerId).select('-password');
    if (!reseller) return res.status(404).json({ message: 'Not found' });
    if (reseller.isBlocked) return res.status(403).json({ message: 'Account blocked' });
    res.json(reseller);
  } catch {
    res.status(500).json({ message: 'Server error' });
  }
});

// ===== GET /api/reseller/search-user =====
// Reseller searches a user by userId OR email — returns safe fields only
router.get('/search-user', resellerAuth, actionLimiter, async (req, res) => {
  try {
    const reseller = await Reseller.findById(req.resellerId);
    if (!reseller || reseller.isBlocked) {
      return res.status(403).json({ message: 'Account blocked or not found' });
    }

    const { query } = req.query;
    if (!query || query.trim().length < 3) {
      return res.status(400).json({ message: 'Query must be at least 3 characters' });
    }

    const user = await User.findOne({
      $or: [
        { userId: query.trim() },
        { email:  query.trim().toLowerCase() },
      ]
    }).select('_id userId username email credits isPro createdAt');

    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch {
    res.status(500).json({ message: 'Server error' });
  }
});

// ===== POST /api/reseller/give-credits =====
router.post('/give-credits', resellerAuth, actionLimiter, async (req, res) => {
  try {
    const reseller = await Reseller.findById(req.resellerId);
    if (!reseller || reseller.isBlocked) {
      return res.status(403).json({ message: 'Account blocked or not found' });
    }

    const { userId, amount } = req.body;

    if (!userId || !amount) {
      return res.status(400).json({ message: 'userId and amount are required' });
    }

    const credits = parseInt(amount, 10);
    if (isNaN(credits) || credits < 1 || credits > 100000) {
      return res.status(400).json({ message: 'Amount must be between 1 and 100,000' });
    }

    if (reseller.credits < credits) {
      return res.status(400).json({ message: `Insufficient credits. You have ${reseller.credits}.` });
    }

    const user = await User.findOne({
      $or: [{ userId: userId.trim() }, { email: userId.trim().toLowerCase() }]
    });

    if (!user) return res.status(404).json({ message: 'User not found' });

    // Atomic update — deduct from reseller, add to user, upgrade to pro
    const newUserCredits = user.credits + credits;
    await Promise.all([
      User.findByIdAndUpdate(user._id, {
        $inc: { credits: credits },
        isPro: true,          // auto-upgrade to pro
        creditGiven: true,
      }),
      Reseller.findByIdAndUpdate(reseller._id, {
        $inc: { credits: -credits, totalGiven: credits },
      }),
    ]);

    res.json({
      message: `✅ ${credits} credits given to ${user.username}. They are now Pro.`,
      resellerCreditsLeft: reseller.credits - credits,
      userNewCredits: newUserCredits,
    });
  } catch {
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
module.exports.resellerAuth = resellerAuth; // export for admin route use