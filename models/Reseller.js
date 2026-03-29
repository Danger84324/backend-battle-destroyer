const mongoose = require('mongoose');

const resellerSchema = new mongoose.Schema({
  username:  { type: String, required: true, unique: true, trim: true },
  email:     { type: String, required: true, unique: true, lowercase: true, trim: true },
  password:  { type: String, required: true },
  credits:   { type: Number, default: 0, min: 0 },
  isBlocked: { type: Boolean, default: false },
  totalGiven:{ type: Number, default: 0 },   // lifetime credits given to users
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date },
});

module.exports = mongoose.model('Reseller', resellerSchema);