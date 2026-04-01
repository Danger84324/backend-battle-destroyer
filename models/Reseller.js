// models/Reseller.js
const mongoose = require('mongoose');

const ResellerSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  credits: { type: Number, default: 0 }, // Used as currency to buy plans
  totalGiven: { type: Number, default: 0 }, // Total credits spent
  isBlocked: { type: Boolean, default: false },
  lastLogin: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Reseller', ResellerSchema);