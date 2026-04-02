// models/ApiUser.js - FINAL WORKING VERSION
const mongoose = require('mongoose');
const crypto = require('crypto');

const apiUserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true },
    apiKey: { type: String, required: true, unique: true },
    apiSecret: { type: String, required: true, unique: true },
    status: { type: String, enum: ['active', 'suspended'], default: 'active' },
    
    // ONLY TWO LIMITS
    limits: {
        maxConcurrent: { type: Number, default: 2 },
        maxDuration: { type: Number, default: 300 }
    },
    
    // Track active attacks only
    activeAttacks: [{
        attackId: { type: String, required: true },
        target: String,
        port: Number,
        startedAt: { type: Date, default: Date.now },
        expiresAt: Date
    }],
    
    // Simple stats
    totalAttacks: { type: Number, default: 0 },
    totalRequests: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    lastLoginAt: { type: Date }
});

// Generate API credentials
apiUserSchema.statics.generateApiKey = function() {
    return 'ak_' + crypto.randomBytes(24).toString('hex');
};

apiUserSchema.statics.generateApiSecret = function() {
    return 'as_' + crypto.randomBytes(32).toString('hex');
};

// Clean expired attacks (static method for cleanup job)
apiUserSchema.statics.cleanExpiredAttacks = async function() {
    const now = new Date();
    const result = await this.updateMany(
        { 'activeAttacks.expiresAt': { $lt: now } },
        { $pull: { activeAttacks: { expiresAt: { $lt: now } } } }
    );
    if (result.modifiedCount > 0) {
        console.log(`Cleaned ${result.modifiedCount} expired attacks`);
    }
    return result;
};

// Get current active attack count (real-time) - FIXED to save after filtering
apiUserSchema.methods.getActiveCount = async function() {
    const now = new Date();
    const beforeCount = this.activeAttacks.length;
    this.activeAttacks = this.activeAttacks.filter(a => a.expiresAt > now);
    
    // Save if changes were made
    if (beforeCount !== this.activeAttacks.length) {
        await this.save();
    }
    return this.activeAttacks.length;
};

// Add active attack
apiUserSchema.methods.addActiveAttack = async function(attackId, target, port, duration) {
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

// Remove active attack
apiUserSchema.methods.removeActiveAttack = async function(attackId) {
    this.activeAttacks = this.activeAttacks.filter(a => a.attackId !== attackId);
    await this.save();
};

// Clean expired attacks for this user
apiUserSchema.methods.cleanExpired = async function() {
    const now = new Date();
    const beforeCount = this.activeAttacks.length;
    this.activeAttacks = this.activeAttacks.filter(a => a.expiresAt > now);
    if (beforeCount !== this.activeAttacks.length) {
        await this.save();
    }
    return this.activeAttacks.length;
};

// FIXED: Export the model
module.exports = mongoose.model('ApiUser', apiUserSchema);