// routes/otp.js
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { generateOTP, sendOTPEmail, sendWelcomeEmail } = require('../services/emailService');
const CryptoJS = require('crypto-js');

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'your-secret-key-2024-battle-destroyer';

// Encryption helpers
function decryptData(encryptedData) {
  try {
    const bytes = CryptoJS.AES.decrypt(encryptedData, ENCRYPTION_KEY);
    const decrypted = bytes.toString(CryptoJS.enc.Utf8);
    if (!decrypted) throw new Error('Decryption failed');
    return JSON.parse(decrypted);
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Invalid encrypted data');
  }
}

function encryptResponse(data) {
  const jsonString = JSON.stringify(data);
  return CryptoJS.AES.encrypt(jsonString, ENCRYPTION_KEY).toString();
}

function createHash(data) {
  const jsonString = JSON.stringify(data);
  return CryptoJS.SHA256(jsonString + ENCRYPTION_KEY).toString();
}

// Send OTP for email verification
router.post('/send-otp', async (req, res) => {
  try {
    let email;
    
    // Handle both encrypted and non-encrypted requests
    if (req.body.encrypted && req.body.hash) {
      const decryptedData = decryptData(req.body.encrypted);
      email = decryptedData.email;
    } else {
      email = req.body.email;
    }
    
    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }
    
    // Check if email already exists and is verified
    const existingUser = await User.findOne({ email });
    if (existingUser && existingUser.emailVerified) {
      const responseData = { success: false, message: 'Email already registered and verified' };
      if (req.body.encrypted) {
        const encryptedResponse = encryptResponse(responseData);
        const responseHash = createHash(responseData);
        return res.status(400).json({ encrypted: encryptedResponse, hash: responseHash });
      }
      return res.status(400).json(responseData);
    }
    
    // Generate OTP
    const otp = generateOTP();
    const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    
    // Store OTP in database if user exists, otherwise in memory
    if (existingUser) {
      existingUser.otpCode = otp;
      existingUser.otpExpiresAt = otpExpiresAt;
      existingUser.otpAttempts = 0;
      await existingUser.save();
    }
    
    // Send email
    const emailSent = await sendOTPEmail(email, otp);
    
    if (!emailSent) {
      const responseData = { success: false, message: 'Failed to send OTP. Please try again.' };
      if (req.body.encrypted) {
        const encryptedResponse = encryptResponse(responseData);
        const responseHash = createHash(responseData);
        return res.status(500).json({ encrypted: encryptedResponse, hash: responseHash });
      }
      return res.status(500).json(responseData);
    }
    
    const responseData = { 
      success: true, 
      message: 'OTP sent to your email',
      email: email 
    };
    
    if (req.body.encrypted) {
      const encryptedResponse = encryptResponse(responseData);
      const responseHash = createHash(responseData);
      return res.json({ encrypted: encryptedResponse, hash: responseHash });
    }
    
    res.json(responseData);
    
  } catch (err) {
    console.error('Send OTP error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify OTP
router.post('/verify-otp', async (req, res) => {
  try {
    let email, otp;
    
    if (req.body.encrypted && req.body.hash) {
      const decryptedData = decryptData(req.body.encrypted);
      email = decryptedData.email;
      otp = decryptedData.otp;
    } else {
      email = req.body.email;
      otp = req.body.otp;
    }
    
    if (!email || !otp) {
      return res.status(400).json({ error: 'Email and OTP required' });
    }
    
    const user = await User.findOne({ email });
    
    if (!user) {
      const responseData = { success: false, message: 'User not found' };
      if (req.body.encrypted) {
        const encryptedResponse = encryptResponse(responseData);
        const responseHash = createHash(responseData);
        return res.status(404).json({ encrypted: encryptedResponse, hash: responseHash });
      }
      return res.status(404).json(responseData);
    }
    
    // Check if already verified
    if (user.emailVerified) {
      const responseData = { success: false, message: 'Email already verified' };
      if (req.body.encrypted) {
        const encryptedResponse = encryptResponse(responseData);
        const responseHash = createHash(responseData);
        return res.status(400).json({ encrypted: encryptedResponse, hash: responseHash });
      }
      return res.status(400).json(responseData);
    }
    
    // Check OTP attempts (max 5)
    if (user.otpAttempts >= 5) {
      const responseData = { success: false, message: 'Too many attempts. Please request a new OTP.' };
      if (req.body.encrypted) {
        const encryptedResponse = encryptResponse(responseData);
        const responseHash = createHash(responseData);
        return res.status(400).json({ encrypted: encryptedResponse, hash: responseHash });
      }
      return res.status(400).json(responseData);
    }
    
    // Check if OTP exists and not expired
    if (!user.otpCode || !user.otpExpiresAt || user.otpExpiresAt < new Date()) {
      const responseData = { success: false, message: 'OTP expired. Please request a new one.' };
      if (req.body.encrypted) {
        const encryptedResponse = encryptResponse(responseData);
        const responseHash = createHash(responseData);
        return res.status(400).json({ encrypted: encryptedResponse, hash: responseHash });
      }
      return res.status(400).json(responseData);
    }
    
    // Verify OTP
    if (user.otpCode !== otp) {
      user.otpAttempts += 1;
      await user.save();
      
      const remainingAttempts = 5 - user.otpAttempts;
      const responseData = { 
        success: false, 
        message: `Invalid OTP. ${remainingAttempts} attempts remaining.` 
      };
      
      if (req.body.encrypted) {
        const encryptedResponse = encryptResponse(responseData);
        const responseHash = createHash(responseData);
        return res.status(400).json({ encrypted: encryptedResponse, hash: responseHash });
      }
      return res.status(400).json(responseData);
    }
    
    // Mark as verified
    user.emailVerified = true;
    user.otpCode = null;
    user.otpExpiresAt = null;
    user.otpAttempts = 0;
    await user.save();
    
    // Send welcome email
    await sendWelcomeEmail(email, user.username);
    
    const responseData = { 
      success: true, 
      message: 'Email verified successfully! You can now complete your registration.'
    };
    
    if (req.body.encrypted) {
      const encryptedResponse = encryptResponse(responseData);
      const responseHash = createHash(responseData);
      return res.json({ encrypted: encryptedResponse, hash: responseHash });
    }
    
    res.json(responseData);
    
  } catch (err) {
    console.error('Verify OTP error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Resend OTP
router.post('/resend-otp', async (req, res) => {
  try {
    let email;
    
    if (req.body.encrypted && req.body.hash) {
      const decryptedData = decryptData(req.body.encrypted);
      email = decryptedData.email;
    } else {
      email = req.body.email;
    }
    
    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }
    
    const user = await User.findOne({ email });
    
    if (!user) {
      const responseData = { success: false, message: 'User not found' };
      if (req.body.encrypted) {
        const encryptedResponse = encryptResponse(responseData);
        const responseHash = createHash(responseData);
        return res.status(404).json({ encrypted: encryptedResponse, hash: responseHash });
      }
      return res.status(404).json(responseData);
    }
    
    if (user.emailVerified) {
      const responseData = { success: false, message: 'Email already verified' };
      if (req.body.encrypted) {
        const encryptedResponse = encryptResponse(responseData);
        const responseHash = createHash(responseData);
        return res.status(400).json({ encrypted: encryptedResponse, hash: responseHash });
      }
      return res.status(400).json(responseData);
    }
    
    // Generate new OTP
    const otp = generateOTP();
    user.otpCode = otp;
    user.otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000);
    user.otpAttempts = 0;
    await user.save();
    
    // Send email
    const emailSent = await sendOTPEmail(email, otp, user.username);
    
    if (!emailSent) {
      const responseData = { success: false, message: 'Failed to send OTP. Please try again.' };
      if (req.body.encrypted) {
        const encryptedResponse = encryptResponse(responseData);
        const responseHash = createHash(responseData);
        return res.status(500).json({ encrypted: encryptedResponse, hash: responseHash });
      }
      return res.status(500).json(responseData);
    }
    
    const responseData = { 
      success: true, 
      message: 'New OTP sent to your email'
    };
    
    if (req.body.encrypted) {
      const encryptedResponse = encryptResponse(responseData);
      const responseHash = createHash(responseData);
      return res.json({ encrypted: encryptedResponse, hash: responseHash });
    }
    
    res.json(responseData);
    
  } catch (err) {
    console.error('Resend OTP error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;