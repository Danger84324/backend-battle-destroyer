// models/AuditLog.js
const mongoose = require('mongoose');

const AuditLogSchema = new mongoose.Schema({
  actorType: {
    type: String,
    enum: ['user', 'admin', 'reseller', 'system'],
    required: true
  },
  actorId: {
    type: mongoose.Schema.Types.Mixed, // ObjectId OR admin token string
    default: null
  },
  action: {
    type: String,
    enum: [
      // ── User actions ──────────────────────────────────────────────────────
      'LOGIN',
      'LOGOUT',
      'REGISTER',
      'UPDATE_PROFILE',
      'CHANGE_PASSWORD',
      'ATTACK_START',
      'ATTACK_STOP',
      'ATTACK_LIMIT_REACHED',
      'USE_CREDITS',

      // ── Admin actions ─────────────────────────────────────────────────────
      'SESSION_CREATED',
      'SESSION_INVALIDATED',
      'BRUTE_FORCE_LOCKOUT',
      'UNAUTHORIZED_ACCESS',
      'INVALID_TOKEN',
      'DAILY_RESET',
      'DAILY_RESET_FAILED',
      'CREATE_USER',
      'UPDATE_USER',
      'DELETE_USER',
      'CREATE_RESELLER',
      'UPDATE_RESELLER',
      'DELETE_RESELLER',
      'GIVE_PRO_SUBSCRIPTION',
      'REMOVE_PRO_SUBSCRIPTION',
      'EXTEND_PRO_SUBSCRIPTION',
      'REPLACE_PRO_SUBSCRIPTION',
      'RESET_DAILY_LIMIT',
      'ADD_CREDITS',    // used by admin AND reseller add-credits route
      'REMOVE_CREDITS',

      // ── Reseller actions ──────────────────────────────────────────────────
      'RESELLER_LOGIN',
      'RESELLER_LOGOUT',
      'RESELLER_GIVE_PRO',
      'RESELLER_SEARCH_USER',
      'RESELLER_ADD_CREDITS'
    ],
    required: true
  },
  targetType: {
    type: String,
    enum: ['user', 'admin', 'reseller', 'system', null],
    default: null
  },
  targetId: {
    type: mongoose.Schema.Types.Mixed, // ObjectId or null
    default: null
  },
  changes: {
    type: mongoose.Schema.Types.Mixed,
    default: null
  },
  ip: {
    type: String,
    default: null
  },
  userAgent: {
    type: String,
    default: null
  },
  success: {
    type: Boolean,
    default: true
  },
  error: {
    type: String,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// ── Indexes ───────────────────────────────────────────────────────────────────
AuditLogSchema.index({ createdAt: -1 });
AuditLogSchema.index({ actorType: 1, actorId: 1 });
// Compound index used by GET /resellers/:id/stats  (the most frequent heavy query)
AuditLogSchema.index({ actorType: 1, actorId: 1, action: 1, success: 1 });
AuditLogSchema.index({ action: 1 });
AuditLogSchema.index({ targetType: 1, targetId: 1 });

module.exports = mongoose.models.AuditLog || mongoose.model('AuditLog', AuditLogSchema);