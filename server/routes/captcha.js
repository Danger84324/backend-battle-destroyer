// routes/captcha.js
const axios = require('axios');

const HCAPTCHA_SECRET_KEY = process.env.HCAPTCHA_SECRET_KEY;
const HCAPTCHA_VERIFY_URL = 'https://hcaptcha.com/siteverify';

/**
 * Verify hCaptcha token
 * @param {string} token - The hCaptcha token from frontend
 * @param {string} ip - User's IP address (optional)
 * @returns {Promise<{success: boolean, score?: number, reason?: string}>}
 */
async function verifyHCaptcha(token, ip = null) {
  if (!token) {
    return { success: false, reason: 'No captcha token provided' };
  }

  if (!HCAPTCHA_SECRET_KEY) {
    console.error('HCAPTCHA_SECRET_KEY not configured in environment variables');
    return { success: false, reason: 'Captcha configuration error' };
  }

  try {
    const params = new URLSearchParams();
    params.append('secret', HCAPTCHA_SECRET_KEY);
    params.append('response', token);
    if (ip) {
      params.append('remoteip', ip);
    }

    const response = await axios.post(HCAPTCHA_VERIFY_URL, params, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 5000 // 5 second timeout
    });

    const data = response.data;

    if (data.success) {
      // Optional: Check score if you're using hCaptcha enterprise
      const score = data.score || 1.0;
      const minScore = 0.5; // Adjust threshold as needed
      
      if (score < minScore) {
        console.log(`hCaptcha score too low: ${score} < ${minScore}`);
        return { 
          success: false, 
          score: score, 
          reason: 'Bot detection triggered. Please try again.' 
        };
      }
      
      console.log(`hCaptcha verified successfully with score: ${score}`);
      return { success: true, score: score };
    } else {
      const errorCodes = data['error-codes'] || [];
      console.error('hCaptcha verification failed:', errorCodes);
      return { 
        success: false, 
        reason: 'Captcha verification failed. Please try again.' 
      };
    }
  } catch (error) {
    console.error('hCaptcha API error:', error.message);
    return { success: false, reason: 'Captcha service unavailable. Please try again.' };
  }
}

/**
 * verifyCaptcha function for compatibility with auth routes
 * @param {string|object} encryptedCaptchaData - Captcha token or data object
 * @param {string} hash - Not used for hCaptcha, kept for compatibility
 * @param {string} ip - User's IP address
 * @returns {Promise<{ok: boolean, reason?: string}>}
 */
// routes/captcha.js (updated to handle both formats)
async function verifyCaptcha(encryptedCaptchaData, hash, ip) {
    try {
        // Extract token from various possible formats
        let token;
        
        if (typeof encryptedCaptchaData === 'string') {
            token = encryptedCaptchaData;
        } else if (encryptedCaptchaData && typeof encryptedCaptchaData === 'object') {
            // Handle both { token, ekey, timestamp } and { encrypted, hash } formats
            token = encryptedCaptchaData.token || encryptedCaptchaData.encrypted || encryptedCaptchaData;
        } else {
            token = encryptedCaptchaData;
        }
        
        if (!token) {
            return { ok: false, reason: 'No captcha token provided' };
        }
        
        // Verify the token with hCaptcha
        const result = await verifyHCaptcha(token, ip);
        
        if (result.success) {
            return { ok: true };
        } else {
            return { ok: false, reason: result.reason };
        }
    } catch (error) {
        console.error('Captcha verification error:', error);
        return { ok: false, reason: 'Captcha verification failed' };
    }
}

module.exports = { verifyHCaptcha, verifyCaptcha };