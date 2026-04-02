// models/Reseller.js
const mongoose = require('mongoose');

const ResellerSchema = new mongoose.Schema({
  username:   { type: String, required: true, unique: true, trim: true },
  email:      { type: String, required: true, unique: true, lowercase: true },
  password:   { type: String, required: true },
  credits:    { type: Number, default: 0 },    // current balance
  totalGiven: { type: Number, default: 0 },    // cumulative credits spent on plans
  isBlocked:  { type: Boolean, default: false },
  lastLogin:  { type: Date, default: Date.now },
  createdAt:  { type: Date, default: Date.now }
});

// ── Indexes ───────────────────────────────────────────────────────────────────
ResellerSchema.index({ createdAt: -1 });
ResellerSchema.index({ isBlocked: 1 });

module.exports = mongoose.models.Reseller || mongoose.model('Reseller', ResellerSchema);