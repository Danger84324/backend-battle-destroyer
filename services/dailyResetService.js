const cron = require('node-cron');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');

class DailyResetService {
  constructor() {
    this.job = null;
    this.isRunning = false;
    this.scheduleTime = '0 0 * * *';
    this.timezone = process.env.TIMEZONE || 'Asia/Kolkata';
    this.nextRunTime = null;
  }

  calculateNextRun() {
    try {
      const schedule = this.scheduleTime;
      const parts = schedule.split(' ');
      
      if (parts.length !== 5) return null;
      
      const [minute, hour, dayOfMonth, month, dayOfWeek] = parts;
      const now = new Date();
      let nextRun = new Date(now);
      
      nextRun.setHours(parseInt(hour), parseInt(minute), 0, 0);
      
      if (nextRun <= now) {
        nextRun.setDate(nextRun.getDate() + 1);
      }
      
      if (dayOfMonth !== '*') {
        const targetDay = parseInt(dayOfMonth);
        if (nextRun.getDate() !== targetDay) {
          nextRun.setDate(targetDay);
          if (nextRun <= now) {
            nextRun.setMonth(nextRun.getMonth() + 1);
          }
        }
      }
      
      if (dayOfWeek !== '*') {
        const targetDayOfWeek = parseInt(dayOfWeek);
        while (nextRun.getDay() !== targetDayOfWeek) {
          nextRun.setDate(nextRun.getDate() + 1);
        }
      }
      
      return nextRun;
    } catch (error) {
      console.error('Error calculating next run:', error);
      return null;
    }
  }

  async logAudit(action, success, changes = {}, error = null) {
    try {
      await AuditLog.create({
        actorType: 'system',
        actorId: null,
        action: action,
        targetId: null,
        targetType: 'system',
        changes: changes,
        ip: 'system',
        userAgent: 'cron-job',
        success: success,
        error: error
      });
      console.log(`   ├─ Audit log created: ${action}`);
    } catch (err) {
      console.log(`   ├─ Audit log skipped (model not updated): ${err.message}`);
    }
  }

  async resetDailyAttacks() {
    const now = new Date();
    console.log(`\n🔄 [${now.toISOString()}] Starting daily reset...`);
    
    let attackReset = { modifiedCount: 0 };
    let proReset = { modifiedCount: 0 };
    let updatedProUsers = [];
    
    try {
      // STEP 1: Reset daily attack counts for ALL users
      attackReset = await User.updateMany(
        {},
        {
          $set: {
            'dailyAttacks.count': 0,
            'dailyAttacks.date': now
          }
        }
      );
      console.log(`   ├─ Reset daily attack counts: ${attackReset.modifiedCount} users`);
      
      // STEP 2: Find all active Pro users
      const proUsers = await User.find({
        'subscription.type': 'pro',
        'subscription.expiresAt': { $gt: now }
      });
      
      console.log(`   ├─ Found ${proUsers.length} active Pro users`);
      
      if (proUsers.length > 0) {
        // Log current credits before reset
        proUsers.forEach(user => {
          const currentCredits = user.subscription.dailyCredits;
          const lastReset = user.subscription.lastCreditReset;
          console.log(`      └─ ${user.username}: Daily credits = ${currentCredits}, Last reset = ${lastReset}`);
        });
        
        // STEP 3: Reset daily credits for Pro users to 30 AND update lastCreditReset
        proReset = await User.updateMany(
          {
            'subscription.type': 'pro',
            'subscription.expiresAt': { $gt: now }
          },
          {
            $set: {
              'subscription.dailyCredits': 30,
              'subscription.lastCreditReset': now, // CRITICAL: Update the reset timestamp
              'dailyAttacks.count': 0,
              'dailyAttacks.date': now
            }
          }
        );
        console.log(`   ├─ Reset Pro daily credits: ${proReset.modifiedCount} users`);
        
        // Verify the update
        updatedProUsers = await User.find({
          'subscription.type': 'pro',
          'subscription.expiresAt': { $gt: now }
        });
        
        updatedProUsers.forEach(user => {
          console.log(`      └─ ${user.username}: Daily credits after = ${user.subscription.dailyCredits}, Last reset = ${user.subscription.lastCreditReset}`);
        });
      } else {
        console.log(`   ├─ No active Pro users to reset`);
      }
      
      console.log(`   └─ ✅ Daily reset completed successfully`);
      console.log(`   ℹ️  Free users: Keep existing credits (${attackReset.modifiedCount - proReset.modifiedCount} users unaffected)`);
      
      this.nextRunTime = this.calculateNextRun();
      
      // Log audit (non-critical, so we don't fail if it doesn't work)
      await this.logAudit('DAILY_RESET', true, {
        attackReset: attackReset.modifiedCount,
        proReset: proReset.modifiedCount,
        freeUsers: attackReset.modifiedCount - proReset.modifiedCount,
        timestamp: now.toISOString(),
        proUsersList: updatedProUsers.map(u => u.username)
      });
      
      return {
        success: true,
        attackReset: attackReset.modifiedCount,
        proReset: proReset.modifiedCount,
        freeUsers: attackReset.modifiedCount - proReset.modifiedCount,
        timestamp: now
      };
      
    } catch (error) {
      console.error('❌ Daily reset failed:', error);
      
      await this.logAudit('DAILY_RESET_FAILED', false, {
        error: error.message,
        timestamp: now.toISOString()
      }, error.message);
      
      return {
        success: false,
        error: error.message
      };
    }
  }
  
  start() {
    if (this.isRunning) {
      console.log('⚠️ Daily reset service is already running');
      return;
    }
    
    this.nextRunTime = this.calculateNextRun();
    
    this.job = cron.schedule(this.scheduleTime, async () => {
      console.log('\n⏰ Running scheduled daily reset...');
      await this.resetDailyAttacks();
    }, {
      scheduled: true,
      timezone: this.timezone
    });
    
    this.isRunning = true;
    console.log(`✅ Daily reset service started (runs at ${this.scheduleTime} ${this.timezone})`);
    console.log(`   └─ Resets: Daily attack counts for ALL users + Pro daily credits to 30 + Update lastCreditReset`);
    console.log(`   └─ Free users: Credits remain unchanged`);
    
    if (process.env.RUN_RESET_ON_START === 'true') {
      console.log('🔄 Running initial reset on startup...');
      setTimeout(() => this.resetDailyAttacks(), 5000);
    }
  }
  
  stop() {
    if (this.job) {
      this.job.stop();
      this.isRunning = false;
      console.log('🛑 Daily reset service stopped');
    }
  }
  
  async manualReset() {
    console.log('🔧 Manual reset triggered');
    return await this.resetDailyAttacks();
  }
  
  getSchedule() {
    return this.scheduleTime;
  }
  
  getNextRun() {
    if (!this.nextRunTime) {
      this.nextRunTime = this.calculateNextRun();
    }
    
    if (this.nextRunTime) {
      return this.nextRunTime.toLocaleString('en-IN', {
        timeZone: this.timezone,
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      });
    }
    
    return 'Not scheduled';
  }
  
  updateSchedule(newSchedule, newTimezone = null) {
    this.scheduleTime = newSchedule;
    if (newTimezone) {
      this.timezone = newTimezone;
    }
    
    this.nextRunTime = this.calculateNextRun();
    
    if (this.isRunning) {
      this.stop();
      this.start();
    }
    
    console.log(`✅ Schedule updated to ${this.scheduleTime} ${this.timezone}`);
  }
  
  getStatus() {
    return {
      isRunning: this.isRunning,
      schedule: this.scheduleTime,
      timezone: this.timezone,
      nextRun: this.getNextRun(),
      lastReset: null
    };
  }
}

module.exports = new DailyResetService();