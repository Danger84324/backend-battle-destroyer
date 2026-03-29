// routes/admin.js
const express = require('express');
const router  = express.Router();
const bcrypt  = require('bcryptjs');
const User    = require('../models/User');

function adminAuth(req, res, next) {
  const secret = req.headers['x-admin-secret'];
  if (!secret || secret !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  next();
}

router.get('/stats', adminAuth, async (req, res) => {
  try {
    const [total, pro, withCredits, today] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ isPro: true }),
      User.countDocuments({ credits: { $gt: 0 } }),
      User.countDocuments({ createdAt: { $gte: new Date(Date.now() - 86400000) } }),
    ]);
    res.json({ total, pro, withCredits, today });
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

module.exports = router;