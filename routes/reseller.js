// routes/reseller.js (Updated for subscription system)
const express  = require('express');
const router   = express.Router();
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = require('express-rate-limit');
const Reseller = require('../models/Reseller');
const User     = require('../models/User');
const AuditLog = require('../models/AuditLog');
const validation = require('../utils/validation');
const { createAuditLog } = require('../utils/audit');

// Updated plans for subscription system
const PLANS = [
  { label: 'Week',  days: 7,  price: 850,  displayName: 'Weekly Pro (7 days)' },
  { label: 'Month', days: 30, price: 1800, displayName: 'Monthly Pro (30 days)' },
  { label: 'Season', days: 90, price: 2500, displayName: 'Season Pro (90 days)' },
];

// ===== RATE LIMITERS =====
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  skipSuccessfulRequests: true,
  message: { message: 'Too many login attempts. Try again in 15 minutes.' },
  keyGenerator: (req) => ipKeyGenerator(req),
  validate: { trustProxy: false, xForwardedForHeader: false }
});

const actionLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 30,
  message: { message: 'Too many requests. Slow down.' },
  keyGenerator: (req) => `${ipKeyGenerator(req)}:${req.resellerId || 'anonymous'}`,
  validate: { trustProxy: false, xForwardedForHeader: false }
});

// ===== BRUTE FORCE MAP FOR LOGIN =====
const loginAttempts = new Map();
const MAX_LOGIN = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

setInterval(() => {
  const now = Date.now();
  for (const [ip, r] of loginAttempts.entries()) {
    if (r.lockedUntil < now && r.count === 0) loginAttempts.delete(ip);
  }
}, 30 * 60 * 1000);

// ===== JWT AUTH MIDDLEWARE =====
function resellerAuth(req, res, next) {
  const auth = req.headers['authorization'];

  if (!auth || typeof auth !== 'string' || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const token = auth.slice(7);

    if (!token || token.length < 20) {
      return res.status(401).json({ message: 'Invalid token format' });
    }

    const decoded = jwt.verify(
      token,
      process.env.RESELLER_JWT_SECRET || process.env.JWT_SECRET
    );

    if (decoded.role !== 'reseller' || !validation.validateObjectId(decoded.id)) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    req.resellerId = decoded.id;
    req.resellerToken = token;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    }
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

// ===== POST /api/reseller/login =====
router.post('/login', loginLimiter, async (req, res) => {
  const ip = req.ip;
  const now = Date.now();
  const record = loginAttempts.get(ip) || { count: 0, lockedUntil: 0 };

  if (record.lockedUntil > now) {
    const seconds = Math.ceil((record.lockedUntil - now) / 1000);

    await createAuditLog({
      actorType: 'reseller',
      action: 'BRUTE_FORCE_LOCKOUT',
      ip,
      userAgent: req.headers['user-agent'],
      success: false,
      error: `IP locked for ${seconds}s`
    });

    return res.status(429).json({
      message: `Account locked. Try again in ${seconds}s.`
    });
  }

  const { username, password } = req.body;

  if (!username || typeof username !== 'string') {
    return res.status(400).json({ message: 'Username is required' });
  }

  if (!password || typeof password !== 'string') {
    return res.status(400).json({ message: 'Password is required' });
  }

  const sanitizedUsername = validation.sanitizeString(username.trim(), 100);

  if (sanitizedUsername.length < 3) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  try {
    const reseller = await Reseller.findOne({
      $or: [
        { username: sanitizedUsername },
        { email: sanitizedUsername.toLowerCase() }
      ]
    });

    if (!reseller) {
      record.count += 1;
      if (record.count >= MAX_LOGIN) {
        record.lockedUntil = now + LOCKOUT_MS;
        record.count = 0;
        loginAttempts.set(ip, record);

        await createAuditLog({
          actorType: 'reseller',
          action: 'BRUTE_FORCE_LOCKOUT',
          ip,
          userAgent: req.headers['user-agent'],
          success: false,
          error: 'Max login attempts exceeded'
        });

        return res.status(429).json({
          message: 'Too many failed attempts. IP locked for 15 minutes.'
        });
      }

      loginAttempts.set(ip, record);
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, reseller.password);

    if (!isPasswordValid) {
      record.count += 1;
      if (record.count >= MAX_LOGIN) {
        record.lockedUntil = now + LOCKOUT_MS;
        record.count = 0;
        loginAttempts.set(ip, record);

        await createAuditLog({
          actorType: 'reseller',
          action: 'BRUTE_FORCE_LOCKOUT',
          ip,
          userAgent: req.headers['user-agent'],
          success: false,
          error: `Max attempts exceeded for reseller ${reseller._id}`
        });

        return res.status(429).json({
          message: 'Too many failed attempts. IP locked for 15 minutes.'
        });
      }

      loginAttempts.set(ip, record);
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    if (reseller.isBlocked) {
      await createAuditLog({
        actorType: 'reseller',
        action: 'UNAUTHORIZED_ACCESS',
        targetId: reseller._id,
        targetType: 'reseller',
        ip,
        userAgent: req.headers['user-agent'],
        success: false,
        error: 'Account is blocked'
      });

      return res.status(403).json({
        message: 'Your reseller account has been blocked. Contact admin.'
      });
    }

    loginAttempts.delete(ip);

    reseller.lastLogin = new Date();
    await reseller.save();

    const token = jwt.sign(
      { id: reseller._id, role: 'reseller' },
      process.env.RESELLER_JWT_SECRET || process.env.JWT_SECRET,
      { expiresIn: '12h' }
    );

    await createAuditLog({
      actorType: 'reseller',
      actorId: reseller._id,
      action: 'LOGIN',
      ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({
      token,
      expiresIn: 12 * 60 * 60 * 1000,
      reseller: {
        id: reseller._id,
        username: reseller.username,
        email: reseller.email,
        credits: reseller.credits,
        totalGiven: reseller.totalGiven,
      }
    });
  } catch (err) {
    console.error('❌ Login error:', err);

    await createAuditLog({
      actorType: 'reseller',
      action: 'LOGIN',
      ip,
      userAgent: req.headers['user-agent'],
      success: false,
      error: err.message
    });

    res.status(500).json({ message: 'Server error' });
  }
});

// ===== GET /api/reseller/me =====
router.get('/me', resellerAuth, async (req, res) => {
  try {
    const reseller = await Reseller.findById(req.resellerId)
      .select('-password')
      .lean();

    if (!reseller) {
      return res.status(404).json({ message: 'Reseller not found' });
    }

    if (reseller.isBlocked) {
      return res.status(403).json({ message: 'Account has been blocked' });
    }

    res.json(reseller);
  } catch (err) {
    console.error('❌ Get me error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ===== GET /api/reseller/search-user =====
router.get('/search-user', resellerAuth, actionLimiter, async (req, res) => {
  try {
    const reseller = await Reseller.findById(req.resellerId);

    if (!reseller || reseller.isBlocked) {
      return res.status(403).json({ message: 'Account is not active' });
    }

    const { query } = req.query;
    const searchQuery = validation.sanitizeSearch(query, 100);

    if (!searchQuery) {
      return res.status(400).json({
        message: 'Search query must be at least 3 characters'
      });
    }

    let searchFilter;
    if (validation.validateEmail(query)) {
      searchFilter = { email: query.trim().toLowerCase() };
    } else {
      searchFilter = { userId: query.trim() };
    }

    const user = await User.findOne(searchFilter).select(
      '_id userId username email credits isPro subscription createdAt'
    ).lean();

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Add computed subscription status
    user.isProActive = user.subscription?.type === 'pro' && user.subscription?.expiresAt > new Date();
    user.subscriptionStatus = user.isProActive ? {
      plan: user.subscription.plan,
      daysLeft: Math.ceil((new Date(user.subscription.expiresAt) - new Date()) / (1000 * 60 * 60 * 24)),
      expiresAt: user.subscription.expiresAt
    } : null;

    await createAuditLog({
      actorType: 'reseller',
      actorId: reseller._id,
      action: 'SEARCH_USER',
      targetId: user._id,
      targetType: 'user',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json(user);
  } catch (err) {
    console.error('❌ Search user error:', err);

    await createAuditLog({
      actorType: 'reseller',
      actorId: req.resellerId,
      action: 'SEARCH_USER',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: false,
      error: err.message
    });

    res.status(500).json({ message: 'Server error' });
  }
});

// ===== POST /api/reseller/give-pro ===== (Updated: Give Pro subscription instead of credits)
router.post('/give-pro', resellerAuth, actionLimiter, async (req, res) => {
  try {
    const reseller = await Reseller.findById(req.resellerId);
    if (!reseller || reseller.isBlocked) {
      return res.status(403).json({ message: 'Account is not active' });
    }

    const { userId, planLabel } = req.body;

    if (!userId || typeof userId !== 'string') {
      return res.status(400).json({ message: 'userId is required' });
    }

    if (!planLabel || typeof planLabel !== 'string') {
      return res.status(400).json({ message: 'Plan label is required' });
    }

    // Validate plan
    const plan = PLANS.find(p => p.label.toLowerCase() === planLabel.toLowerCase());
    if (!plan) {
      return res.status(400).json({
        message: `Invalid plan. Choose from: ${PLANS.map(p => p.label).join(', ')}`,
        plans: PLANS.map(p => ({ label: p.label, days: p.days, price: p.price }))
      });
    }

    // Check if reseller has enough credits (using credits as currency)
    if (reseller.credits < plan.price) {
      return res.status(400).json({
        message: `Insufficient credits. You have ${reseller.credits}, plan requires ${plan.price} credits.`,
        needed: plan.price,
        available: reseller.credits
      });
    }

    const sanitizedUserId = validation.sanitizeString(userId.trim(), 100);
    const user = await User.findOne({
      $or: [{ userId: sanitizedUserId }, { email: sanitizedUserId.toLowerCase() }]
    });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Get old subscription info for audit
    const oldSubscription = {
      type: user.subscription?.type,
      plan: user.subscription?.plan,
      expiresAt: user.subscription?.expiresAt
    };

    // Give Pro subscription to user
    const daysAdded = user.addProSubscription(plan.label.toLowerCase(), plan.days);
    await user.save();

    // Deduct credits from reseller
    const resellerNewCredits = reseller.credits - plan.price;
    await Reseller.findByIdAndUpdate(reseller._id, {
      $inc: { credits: -plan.price, totalGiven: plan.price }
    });

    // Get updated subscription status
    const newSubscriptionStatus = {
      active: user.isProUser(),
      plan: user.subscription.plan,
      daysLeft: Math.ceil((new Date(user.subscription.expiresAt) - new Date()) / (1000 * 60 * 60 * 24)),
      expiresAt: user.subscription.expiresAt
    };

    // Audit log
    await createAuditLog({
      actorType: 'reseller',
      actorId: reseller._id,
      action: 'GIVE_PRO_SUBSCRIPTION',
      targetId: user._id,
      targetType: 'user',
      changes: {
        plan: plan.label,
        days: plan.days,
        price: plan.price,
        oldSubscription,
        newSubscription: user.subscription,
        resellerCredits: resellerNewCredits
      },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({
      message: `✅ ${plan.displayName} (${plan.days} days) successfully given to ${user.username}! They now have Pro access.`,
      plan: plan.label,
      daysGiven: plan.days,
      price: plan.price,
      resellerCreditsLeft: resellerNewCredits,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isPro: user.isProUser(),
        subscription: newSubscriptionStatus
      }
    });
  } catch (err) {
    console.error('❌ Give pro error:', err);
    
    await createAuditLog({
      actorType: 'reseller',
      actorId: req.resellerId,
      action: 'GIVE_PRO_SUBSCRIPTION',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: false,
      error: err.message
    });
    
    res.status(500).json({ message: 'Server error: ' + err.message });
  }
});

// ===== GET /api/reseller/plans ===== (New endpoint to get available plans)
router.get('/plans', resellerAuth, async (req, res) => {
  try {
    const reseller = await Reseller.findById(req.resellerId);
    if (!reseller || reseller.isBlocked) {
      return res.status(403).json({ message: 'Account is not active' });
    }

    res.json({
      plans: PLANS.map(plan => ({
        label: plan.label,
        displayName: plan.displayName,
        days: plan.days,
        price: plan.price,
        description: `${plan.days} days of Pro access with 30 attacks per day`
      })),
      myCredits: reseller.credits
    });
  } catch (err) {
    console.error('❌ Get plans error:', err);
    res.status(500).json({ message: 'Failed to fetch plans' });
  }
});

// ===== GET /api/reseller/stats ===== (New endpoint for reseller stats)
router.get('/stats', resellerAuth, async (req, res) => {
  try {
    const reseller = await Reseller.findById(req.resellerId);
    if (!reseller || reseller.isBlocked) {
      return res.status(403).json({ message: 'Account is not active' });
    }

    // Get users this reseller has given pro subscriptions to
    const usersGiven = await User.find({
      referredBy: { $exists: true },
      // You might want to track which reseller gave the subscription
      // This requires adding resellerId field to User model
    }).countDocuments();

    res.json({
      credits: reseller.credits,
      totalGiven: reseller.totalGiven,
      usersServed: usersGiven,
      lastLogin: reseller.lastLogin,
      createdAt: reseller.createdAt
    });
  } catch (err) {
    console.error('❌ Get stats error:', err);
    res.status(500).json({ message: 'Failed to fetch stats' });
  }
});

// ===== POST /api/reseller/add-credits ===== (Admin can add credits to reseller)
// Note: This should ideally be in admin routes, but keeping for completeness
router.post('/add-credits', resellerAuth, async (req, res) => {
  try {
    // Only allow if reseller has special permission
    // You might want to add a field to Reseller model like 'canAddCredits'
    const reseller = await Reseller.findById(req.resellerId);
    if (!reseller || reseller.isBlocked) {
      return res.status(403).json({ message: 'Account is not active' });
    }

    const { amount, secret } = req.body;
    
    // Verify special secret for adding credits
    if (secret !== process.env.RESELLER_ADD_CREDITS_SECRET) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    if (!amount || amount < 1 || amount > 100000) {
      return res.status(400).json({ message: 'Invalid amount' });
    }

    reseller.credits += amount;
    await reseller.save();

    await createAuditLog({
      actorType: 'reseller',
      actorId: reseller._id,
      action: 'ADD_CREDITS',
      targetId: reseller._id,
      targetType: 'reseller',
      changes: { added: amount, newTotal: reseller.credits },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({
      message: `Added ${amount} credits`,
      credits: reseller.credits
    });
  } catch (err) {
    console.error('❌ Add credits error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ===== GET /api/reseller/audit-logs =====
router.get('/audit-logs', resellerAuth, async (req, res) => {
  try {
    const { page, limit } = validation.validatePaginationQuery(req.query);

    const logs = await AuditLog.find({
      actorId: req.resellerId,
      actorType: 'reseller'
    })
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();

    const total = await AuditLog.countDocuments({
      actorId: req.resellerId,
      actorType: 'reseller'
    });

    res.json({
      logs,
      total,
      page,
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error('❌ Audit logs error:', err);
    res.status(500).json({ message: 'Failed to fetch audit logs' });
  }
});

module.exports = router;
module.exports.resellerAuth = resellerAuth;