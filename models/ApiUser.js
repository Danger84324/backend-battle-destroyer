// models/ApiUser.js - with hashed apiSecret storage
const mongoose = require('mongoose');
const crypto   = require('crypto');

const apiUserSchema = new mongoose.Schema({
    username:     { type: String, required: true, unique: true },
    email:        { type: String, required: true },
    apiKey:       { type: String, required: true, unique: true },

    // apiSecret is NEVER stored in plain text.
    // We store SHA-256(rawSecret) and use it as the HMAC key for request signing.
    // The rawSecret is shown to the admin ONCE at creation time and is unrecoverable.
    apiSecretHash: { type: String, required: true },

    status: { type: String, enum: ['active', 'suspended', 'expired'], default: 'active' },

    expiresAt: { type: Date, default: null },
    createdAt:  { type: Date, default: Date.now },

    limits: {
        maxConcurrent: { type: Number, default: 2 },
        maxDuration:   { type: Number, default: 300 }
    },

    activeAttacks: [{
        attackId:  { type: String, required: true },
        target:    String,
        port:      Number,
        startedAt: { type: Date, default: Date.now },
        expiresAt: Date
    }],

    totalAttacks:  { type: Number, default: 0 },
    totalRequests: { type: Number, default: 0 },
    createdBy:     { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    lastLoginAt:   { type: Date }
});

// ── Static generators ─────────────────────────────────────────────────────────

apiUserSchema.statics.generateApiKey = function () {
    return 'ak_' + crypto.randomBytes(24).toString('hex');
};

/**
 * Generates a raw apiSecret and returns BOTH the raw value and its SHA-256 hash.
 *
 * Usage:
 *   const { raw, hashed } = ApiUser.generateApiSecret();
 *   // Store `hashed` in DB as apiSecretHash
 *   // Return `raw` to the admin/user — it will NEVER be recoverable after this
 */
apiUserSchema.statics.generateApiSecret = function () {
    const raw    = 'as_' + crypto.randomBytes(32).toString('hex');
    const hashed = crypto.createHash('sha256').update(raw).digest('hex');
    return { raw, hashed };
};

// ── Expiration helpers ────────────────────────────────────────────────────────

apiUserSchema.methods.isExpired = function () {
    if (!this.expiresAt) return false;
    return new Date() > new Date(this.expiresAt);
};

apiUserSchema.methods.getDaysRemaining = function () {
    if (!this.expiresAt) return null;
    const days = Math.ceil((new Date(this.expiresAt) - new Date()) / (1000 * 60 * 60 * 24));
    return days > 0 ? days : 0;
};

apiUserSchema.methods.extendExpiration = async function (days) {
    if (!this.expiresAt) {
        this.expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
    } else {
        this.expiresAt = new Date(new Date(this.expiresAt).getTime() + days * 24 * 60 * 60 * 1000);
    }
    if (this.status === 'expired') this.status = 'active';
    await this.save();
    return this.expiresAt;
};

apiUserSchema.methods.setDefaultExpiration = async function () {
    this.expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await this.save();
    return this.expiresAt;
};

// ── Attack tracking ───────────────────────────────────────────────────────────

apiUserSchema.statics.cleanExpiredAttacks = async function () {
    const now = new Date();
    const attackResult = await this.updateMany(
        { 'activeAttacks.expiresAt': { $lt: now } },
        { $pull: { activeAttacks: { expiresAt: { $lt: now } } } }
    );
    const expireResult = await this.updateMany(
        { expiresAt: { $lt: now }, status: 'active' },
        { status: 'expired' }
    );
    if (attackResult.modifiedCount > 0 || expireResult.modifiedCount > 0) {
        console.log(`Cleaned ${attackResult.modifiedCount} attacks, ${expireResult.modifiedCount} accounts expired`);
    }
    return { attackResult, expireResult };
};

apiUserSchema.methods.getActiveCount = async function () {
    const now         = new Date();
    const beforeCount = this.activeAttacks.length;
    this.activeAttacks = this.activeAttacks.filter(a => a.expiresAt > now);
    if (beforeCount !== this.activeAttacks.length) await this.save();
    return this.activeAttacks.length;
};

apiUserSchema.methods.addActiveAttack = async function (attackId, target, port, duration) {
    if (this.isExpired()) throw new Error('Account has expired');
    this.activeAttacks.push({
        attackId,
        target,
        port,
        startedAt: new Date(),
        expiresAt: new Date(Date.now() + duration * 1000)
    });
    this.totalAttacks++;
    await this.save();
};

apiUserSchema.methods.removeActiveAttack = async function (attackId) {
    this.activeAttacks = this.activeAttacks.filter(a => a.attackId !== attackId);
    await this.save();
};

apiUserSchema.methods.cleanExpired = async function () {
    const now         = new Date();
    const beforeCount = this.activeAttacks.length;
    this.activeAttacks = this.activeAttacks.filter(a => a.expiresAt > now);
    if (beforeCount !== this.activeAttacks.length) await this.save();
    return this.activeAttacks.length;
};

module.exports = mongoose.model('ApiUser', apiUserSchema);