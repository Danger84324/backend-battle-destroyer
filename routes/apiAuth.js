// routes/apiAuth.js - with timing-safe secret comparison and hashed storage
const express = require('express');
const router  = express.Router();
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const ApiUser = require('../models/ApiUser');

const JWT_SECRET = process.env.API_USER_JWT_SECRET;
if (!JWT_SECRET) throw new Error('API_USER_JWT_SECRET is not set in environment');

// ── Login ─────────────────────────────────────────────────────────────────────

router.post('/login', async (req, res) => {
    try {
        const { username, apiSecret } = req.body;

        if (!username || !apiSecret) {
            return res.status(400).json({ error: 'Username and API Secret required' });
        }

        const apiUser = await ApiUser.findOne({ username });

        // Return the same error for "user not found" and "wrong secret"
        // to prevent username enumeration.
        if (!apiUser) {
            // Still run a dummy comparison to prevent timing side-channels
            crypto.timingSafeEqual(Buffer.alloc(32), Buffer.alloc(32));
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check expiration before anything else
        if (apiUser.isExpired()) {
            return res.status(403).json({
                error: 'Account has expired',
                expired: true,
                expiresAt: apiUser.expiresAt
            });
        }

        if (apiUser.status !== 'active') {
            return res.status(403).json({
                error: apiUser.status === 'suspended'
                    ? 'Account is suspended'
                    : 'Account is not active',
                status: apiUser.status
            });
        }

        // Timing-safe secret comparison
        // Hash the provided secret and compare against stored hash
        const providedHash = crypto.createHash('sha256').update(apiSecret).digest('hex');
        let secretMatch = false;
        try {
            secretMatch = crypto.timingSafeEqual(
                Buffer.from(providedHash,          'hex'),
                Buffer.from(apiUser.apiSecretHash, 'hex')
            );
        } catch {
            // Buffer length mismatch → wrong
        }

        if (!secretMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Update last login
        apiUser.lastLoginAt = new Date();
        await apiUser.save();

        // Issue JWT (short-lived — dashboard access only, NOT for API request signing)
        const token = jwt.sign(
            { id: apiUser._id, username: apiUser.username },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            token,
            user: {
                id:            apiUser._id,
                username:      apiUser.username,
                email:         apiUser.email,
                status:        apiUser.status,
                limits:        apiUser.limits,
                totalAttacks:  apiUser.totalAttacks,
                expiresAt:     apiUser.expiresAt,
                daysRemaining: apiUser.getDaysRemaining(),
                createdAt:     apiUser.createdAt
            }
        });

    } catch (error) {
        console.error('[apiAuth] Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ── Dashboard stats ───────────────────────────────────────────────────────────

router.get('/dashboard/stats', verifyApiUserToken, async (req, res) => {
    try {
        const apiUser = await ApiUser.findById(req.apiUserId);

        if (!apiUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        const isExpired      = apiUser.isExpired();
        const daysRemaining  = apiUser.getDaysRemaining();
        const now            = new Date();

        // Clean expired attacks
        const beforeCount = apiUser.activeAttacks.length;
        apiUser.activeAttacks = apiUser.activeAttacks.filter(a => a.expiresAt > now);
        if (beforeCount !== apiUser.activeAttacks.length) await apiUser.save();

        const activeCount = apiUser.activeAttacks.length;

        res.json({
            success: true,
            user: {
                id:            apiUser._id,
                username:      apiUser.username,
                email:         apiUser.email,
                status:        isExpired ? 'expired' : apiUser.status,
                limits: {
                    maxConcurrent: apiUser.limits.maxConcurrent,
                    maxDuration:   apiUser.limits.maxDuration
                },
                createdAt:     apiUser.createdAt,
                expiresAt:     apiUser.expiresAt,
                daysRemaining,
                isExpired
            },
            stats: {
                totalAttacks:        apiUser.totalAttacks  || 0,
                totalRequests:       apiUser.totalRequests || 0,
                currentActiveAttacks: activeCount,
                remainingSlots:      Math.max(0, apiUser.limits.maxConcurrent - activeCount)
            },
            activeAttacks: apiUser.activeAttacks.map(a => ({
                attackId:  a.attackId,
                target:    a.target,
                port:      a.port,
                expiresIn: Math.max(0, Math.floor((a.expiresAt - now) / 1000))
            })),
            apiKey: apiUser.apiKey  // public key — safe to return
            // apiSecretHash is NEVER returned
        });

    } catch (error) {
        console.error('[apiAuth] Dashboard error:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard data' });
    }
});

// ── JWT middleware ────────────────────────────────────────────────────────────

function verifyApiUserToken(req, res, next) {
    const authHeader = req.headers.authorization;
    const token      = authHeader && authHeader.startsWith('Bearer ')
        ? authHeader.slice(7)
        : null;

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    try {
        const decoded   = jwt.verify(token, JWT_SECRET);
        req.apiUserId   = decoded.id;
        req.apiUsername = decoded.username;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired' });
        }
        return res.status(401).json({ error: 'Invalid token' });
    }
}

module.exports = router;
module.exports.verifyApiUserToken = verifyApiUserToken;