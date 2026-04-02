// routes/simpleAdmin.js
const express = require('express');
const router = express.Router();
const ApiUser = require('../models/ApiUser');

// Simple admin auth (use your existing admin middleware)
function adminAuth(req, res, next) {
    const token = req.headers['x-admin-token'];
    if (process.env.NODE_ENV === 'development' && token === process.env.DEV_ADMIN_TOKEN) {
        return next();
    }
    if (token === process.env.ADMIN_TOKEN) {
        return next();
    }
    res.status(401).json({ error: 'Admin access required' });
}

router.use(adminAuth);

// CREATE API User
router.post('/users', async (req, res) => {
    try {
        const { username, email, maxConcurrent = 2, maxDuration = 300 } = req.body;
        
        if (!username || !email) {
            return res.status(400).json({ error: 'Username and email required' });
        }
        
        const existing = await ApiUser.findOne({ $or: [{ username }, { email }] });
        if (existing) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        
        const apiKey = ApiUser.generateApiKey();
        const apiSecret = ApiUser.generateApiSecret();
        
        const apiUser = new ApiUser({
            username,
            email,
            apiKey,
            apiSecret,
            limits: { maxConcurrent, maxDuration }
        });
        
        await apiUser.save();
        
        res.status(201).json({
            success: true,
            user: {
                id: apiUser._id,
                username: apiUser.username,
                email: apiUser.email,
                apiKey: apiUser.apiKey,
                apiSecret: apiUser.apiSecret,
                limits: apiUser.limits,
                status: apiUser.status
            }
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// GET all API Users
router.get('/users', async (req, res) => {
    try {
        const users = await ApiUser.find({}).select('-apiSecret');
        
        // Add real-time active counts
        const usersWithActive = users.map(user => ({
            ...user.toObject(),
            currentActive: user.getActiveCount()
        }));
        
        res.json({ users: usersWithActive });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// GET single user
router.get('/users/:id', async (req, res) => {
    try {
        const user = await ApiUser.findById(req.params.id).select('-apiSecret');
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        res.json({
            ...user.toObject(),
            currentActive: user.getActiveCount()
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// UPDATE user limits
router.put('/users/:id/limits', async (req, res) => {
    try {
        const { maxConcurrent, maxDuration } = req.body;
        const user = await ApiUser.findById(req.params.id);
        
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        if (maxConcurrent !== undefined) user.limits.maxConcurrent = maxConcurrent;
        if (maxDuration !== undefined) user.limits.maxDuration = maxDuration;
        
        await user.save();
        
        res.json({
            success: true,
            limits: user.limits
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// UPDATE status
router.patch('/users/:id/status', async (req, res) => {
    try {
        const { status } = req.body;
        if (!['active', 'suspended'].includes(status)) {
            return res.status(400).json({ error: 'Status must be active or suspended' });
        }
        
        const user = await ApiUser.findByIdAndUpdate(
            req.params.id,
            { status },
            { new: true }
        ).select('-apiSecret');
        
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        res.json({ success: true, user });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// DELETE user
router.delete('/users/:id', async (req, res) => {
    try {
        const user = await ApiUser.findByIdAndDelete(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        res.json({ success: true, message: 'User deleted' });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Regenerate API secret
router.post('/users/:id/regenerate', async (req, res) => {
    try {
        const user = await ApiUser.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        user.apiSecret = ApiUser.generateApiSecret();
        await user.save();
        
        res.json({ success: true, apiSecret: user.apiSecret });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;