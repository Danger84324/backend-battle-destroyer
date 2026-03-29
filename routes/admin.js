const express  = require('express');
const router   = express.Router();
const bcrypt   = require('bcryptjs');
const crypto   = require('crypto');
const User     = require('../models/User');
const Reseller = require('../models/Reseller');

// ===== BRUTE FORCE PROTECTION =====
const failedAttempts = new Map();
const MAX_ATTEMPTS   = 5;
const LOCKOUT_MS     = 15 * 60 * 1000;

setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of failedAttempts.entries()) {
    if (record.lockedUntil < now && record.count === 0) failedAttempts.delete(ip);
  }
}, 30 * 60 * 1000);

// ===== SINGLE-SESSION MANAGEMENT =====
// Only one active admin session token at a time.
// Logging in from a new device/tab invalidates the previous session.
let activeSession = null; // { token, createdAt, ip, userAgent }
const SESSION_TTL = 8 * 60 * 60 * 1000; // 8 hours

// POST /api/admin/session — exchange secret for a session token
router.post('/session', (req, res) => {
  const ip     = req.ip;
  const now    = Date.now();
  const record = failedAttempts.get(ip) || { count: 0, lockedUntil: 0 };

  if (record.lockedUntil > now) {
    const s = Math.ceil((record.lockedUntil - now) / 1000);
    return res.status(429).json({ message: `Too many failed attempts. Try again in ${s}s.` });
  }

  const { secret } = req.body;
  if (!secret || secret !== process.env.ADMIN_SECRET) {
    record.count += 1;
    if (record.count >= MAX_ATTEMPTS) {
      record.lockedUntil = now + LOCKOUT_MS;
      record.count = 0;
      failedAttempts.set(ip, record);
      return res.status(429).json({ message: 'Too many failed attempts. IP locked for 15 minutes.' });
    }
    failedAttempts.set(ip, record);
    return res.status(401).json({
      message: `Invalid secret. ${MAX_ATTEMPTS - record.count} attempts remaining.`
    });
  }

  failedAttempts.delete(ip);

  // Issue new token — this immediately kills any existing session
  const token = crypto.randomBytes(48).toString('hex');
  activeSession = {
    token,
    createdAt: now,
    ip,
    userAgent: req.headers['user-agent'] || 'unknown',
  };

  res.json({ token, expiresIn: SESSION_TTL });
});

// DELETE /api/admin/session — explicit logout
router.delete('/session', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (activeSession && activeSession.token === token) {
    activeSession = null;
  }
  res.json({ message: 'Logged out' });
});

// GET /api/admin/session/check — frontend heartbeat
router.get('/session/check', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (!activeSession || activeSession.token !== token) {
    return res.status(401).json({ message: 'SESSION_INVALIDATED' });
  }
  if (Date.now() - activeSession.createdAt > SESSION_TTL) {
    activeSession = null;
    return res.status(401).json({ message: 'SESSION_EXPIRED' });
  }
  res.json({ ok: true });
});

// ===== AUTH MIDDLEWARE (secret + session token) =====
function adminAuth(req, res, next) {
  const ip    = req.ip;
  const now   = Date.now();
  const token = req.headers['x-admin-token'];

  // Must have a valid active session token
  if (!token || !activeSession || activeSession.token !== token) {
    return res.status(401).json({ message: 'SESSION_INVALIDATED' });
  }

  // Check session expiry
  if (now - activeSession.createdAt > SESSION_TTL) {
    activeSession = null;
    return res.status(401).json({ message: 'SESSION_EXPIRED' });
  }

  next();
}

// ═══════════════════════════════════════════════
//  USER ROUTES (unchanged)
// ═══════════════════════════════════════════════

router.get('/stats', adminAuth, async (req, res) => {
  try {
    const [total, pro, withCredits, today, totalResellers, activeResellers] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ isPro: true }),
      User.countDocuments({ credits: { $gt: 0 } }),
      User.countDocuments({ createdAt: { $gte: new Date(Date.now() - 86400000) } }),
      Reseller.countDocuments(),
      Reseller.countDocuments({ isBlocked: false }),
    ]);
    res.json({ total, pro, withCredits, today, totalResellers, activeResellers });
  } catch { res.status(500).json({ message: 'Server error' }); }
});

router.get('/users', adminAuth, async (req, res) => {
  try {
    const { search, page = 1, limit = 20 } = req.query;
    const query = search
      ? { $or: [
          { username: { $regex: search, $options: 'i' } },
          { email:    { $regex: search, $options: 'i' } },
          { userId:   { $regex: search, $options: 'i' } },
        ]}
      : {};
    const total = await User.countDocuments(query);
    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(Number(limit));
    res.json({ users, total, page: Number(page), pages: Math.ceil(total / limit) });
  } catch { res.status(500).json({ message: 'Server error' }); }
});

router.get('/users/:id', adminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch { res.status(500).json({ message: 'Server error' }); }
});

router.patch('/users/:id', adminAuth, async (req, res) => {
  try {
    const allowed = ['credits', 'isPro', 'username', 'email', 'referralCount', 'creditGiven'];
    const updates = {};
    for (const key of allowed) {
      if (req.body[key] !== undefined) updates[key] = req.body[key];
    }
    if (req.body.password && req.body.password.length >= 8) {
      updates.password = await bcrypt.hash(req.body.password, 12);
    }
    const user = await User.findByIdAndUpdate(req.params.id, updates, { new: true }).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch (err) {
    if (err.code === 11000) {
      const field = Object.keys(err.keyPattern || {})[0] || 'field';
      return res.status(400).json({ message: `${field} already taken` });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

router.delete('/users/:id', adminAuth, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'User deleted' });
  } catch { res.status(500).json({ message: 'Server error' }); }
});

// ═══════════════════════════════════════════════
//  RESELLER ROUTES
// ═══════════════════════════════════════════════

// GET /api/admin/resellers
router.get('/resellers', adminAuth, async (req, res) => {
  try {
    const { search, page = 1, limit = 20 } = req.query;
    const query = search
      ? { $or: [
          { username: { $regex: search, $options: 'i' } },
          { email:    { $regex: search, $options: 'i' } },
        ]}
      : {};
    const total     = await Reseller.countDocuments(query);
    const resellers = await Reseller.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(Number(limit));
    res.json({ resellers, total, page: Number(page), pages: Math.ceil(total / limit) });
  } catch { res.status(500).json({ message: 'Server error' }); }
});

// POST /api/admin/resellers — create reseller
router.post('/resellers', adminAuth, async (req, res) => {
  try {
    const { username, email, password, credits = 0 } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'username, email and password are required' });
    }
    if (password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters' });
    }
    const hashed   = await bcrypt.hash(password, 12);
    const reseller = await Reseller.create({ username, email, password: hashed, credits });
    res.status(201).json({
      id: reseller._id,
      username: reseller.username,
      email: reseller.email,
      credits: reseller.credits,
      isBlocked: reseller.isBlocked,
    });
  } catch (err) {
    if (err.code === 11000) {
      const field = Object.keys(err.keyPattern || {})[0] || 'field';
      return res.status(400).json({ message: `${field} already taken` });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// PATCH /api/admin/resellers/:id — update reseller (credits, block, password, username, email)
router.patch('/resellers/:id', adminAuth, async (req, res) => {
  try {
    const allowed = ['credits', 'isBlocked', 'username', 'email'];
    const updates = {};
    for (const key of allowed) {
      if (req.body[key] !== undefined) updates[key] = req.body[key];
    }
    if (req.body.password && req.body.password.length >= 8) {
      updates.password = await bcrypt.hash(req.body.password, 12);
    }
    const reseller = await Reseller.findByIdAndUpdate(
      req.params.id, updates, { new: true }
    ).select('-password');
    if (!reseller) return res.status(404).json({ message: 'Reseller not found' });
    res.json(reseller);
  } catch (err) {
    if (err.code === 11000) {
      const field = Object.keys(err.keyPattern || {})[0] || 'field';
      return res.status(400).json({ message: `${field} already taken` });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// DELETE /api/admin/resellers/:id
router.delete('/resellers/:id', adminAuth, async (req, res) => {
  try {
    const reseller = await Reseller.findByIdAndDelete(req.params.id);
    if (!reseller) return res.status(404).json({ message: 'Reseller not found' });
    res.json({ message: 'Reseller deleted' });
  } catch { res.status(500).json({ message: 'Server error' }); }
});

module.exports = router;