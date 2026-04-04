const AuditLog = require('../models/AuditLog');

const createAuditLog = async (options) => {
  try {
    const log = new AuditLog({
      actorId: options.actorId,
      actorType: options.actorType,
      action: options.action,
      targetId: options.targetId,
      targetType: options.targetType,
      changes: options.changes || null,
      ip: options.ip,
      userAgent: options.userAgent,
      success: options.success !== false,
      error: options.error || null,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
    });
    await log.save();
    return log;
  } catch (err) {
    console.error('❌ Audit Log Error:', err.message);
  }
};

const getActorLogs = async (actorId, limit = 50, skip = 0) => {
  try {
    const logs = await AuditLog.find({ actorId }).sort({ createdAt: -1 }).limit(limit).skip(skip).lean();
    const total = await AuditLog.countDocuments({ actorId });
    return { logs, total };
  } catch (err) {
    console.error('❌ Error fetching audit logs:', err.message);
    return { logs: [], total: 0 };
  }
};

const getTargetLogs = async (targetId, limit = 50, skip = 0) => {
  try {
    const logs = await AuditLog.find({ targetId }).sort({ createdAt: -1 }).limit(limit).skip(skip).lean();
    const total = await AuditLog.countDocuments({ targetId });
    return { logs, total };
  } catch (err) {
    console.error('❌ Error fetching audit logs:', err.message);
    return { logs: [], total: 0 };
  }
};

const getFailedActions = async (limit = 50, skip = 0) => {
  try {
    const logs = await AuditLog.find({ success: false }).sort({ createdAt: -1 }).limit(limit).skip(skip).lean();
    const total = await AuditLog.countDocuments({ success: false });
    return { logs, total };
  } catch (err) {
    console.error('❌ Error fetching failed audit logs:', err.message);
    return { logs: [], total: 0 };
  }
};

const getSuspiciousActivity = async (hours = 24) => {
  try {
    const since = new Date(Date.now() - hours * 60 * 60 * 1000);
    return await AuditLog.find({
      createdAt: { $gte: since },
      action: { $in: ['BRUTE_FORCE_LOCKOUT', 'UNAUTHORIZED_ACCESS', 'INVALID_TOKEN'] }
    }).sort({ createdAt: -1 });
  } catch (err) {
    console.error('❌ Error fetching suspicious activity:', err.message);
    return [];
  }
};

module.exports = {
  createAuditLog,
  getActorLogs,
  getTargetLogs,
  getFailedActions,
  getSuspiciousActivity
};