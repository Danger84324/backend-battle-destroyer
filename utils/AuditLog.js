const mongoose = require('mongoose');

const AuditLogSchema = new mongoose.Schema({
  actorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    sparse: true
  },
  actorType: {
    type: String,
    enum: ['admin', 'reseller', 'system'], // ADDED 'system'
    required: true
  },
  action: {
    type: String,
    enum: [
      'LOGIN', 'LOGOUT', 'CREATE_USER', 'UPDATE_USER', 'DELETE_USER',
      'UPDATE_USER_CREDITS', 'UPDATE_USER_PASSWORD', 'CREATE_RESELLER',
      'UPDATE_RESELLER', 'DELETE_RESELLER', 'BLOCK_RESELLER', 'GIVE_CREDITS',
      'GIVE_PRO_SUBSCRIPTION', 'REMOVE_PRO_SUBSCRIPTION', 'EXTEND_PRO_SUBSCRIPTION',
      'REPLACE_PRO_SUBSCRIPTION', 'SEARCH_USER', 'SESSION_CREATED', 
      'SESSION_EXPIRED', 'BRUTE_FORCE_LOCKOUT', 'UNAUTHORIZED_ACCESS', 
      'INVALID_TOKEN', 'DAILY_RESET', 'DAILY_RESET_FAILED' // ADDED new actions
    ],
    required: true
  },
  targetId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    sparse: true
  },
  targetType: {
    type: String,
    enum: ['user', 'reseller', 'system'], // ADDED 'system'
    sparse: true
  },
  changes: {
    type: mongoose.Schema.Types.Mixed,
    default: null
  },
  ip: {
    type: String,
    default: 'system' // ADDED default
  },
  userAgent: {
    type: String,
    default: 'cron-job' // ADDED default
  },
  success: {
    type: Boolean,
    default: true
  },
  error: String,
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  },
  expiresAt: {
    type: Date,
    default: () => new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
    index: true
  }
});

AuditLogSchema.index({ actorId: 1, createdAt: -1 });
AuditLogSchema.index({ targetId: 1, createdAt: -1 });
AuditLogSchema.index({ action: 1, createdAt: -1 });
AuditLogSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('AuditLog', AuditLogSchema);