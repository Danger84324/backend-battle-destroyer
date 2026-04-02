/**
 * routes/captcha.js - Complete with encrypted responses
 */

const express = require('express');
const router  = express.Router();
const crypto  = require('crypto');
const CryptoJS = require('crypto-js');

/* ─── Config ──────────────────────────────────────────────────── */

const DIFFICULTY       = 4;
const TTL_MS           = 5 * 60_000;
const MIN_SOLVE_MS     = 2_000;
const MAX_STORE        = 50_000;
const CHALLENGE_LIMIT  = 10;
const CHALLENGE_WINDOW = 5 * 60_000;
const FAIL_LIMIT       = 3;
const FAIL_WINDOW      = 15 * 60_000;

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'your-secret-key-2024-battle-destroyer';

/* ─── Stores ──────────────────────────────────────────────────── */

const challenges    = new Map();
const challengeRate = new Map();
const failedAttempts= new Map();

/* ─── Encryption Helpers ──────────────────────────────────────── */

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

function verifyHash(data, receivedHash) {
  const jsonString = JSON.stringify(data);
  const calculatedHash = CryptoJS.SHA256(jsonString + ENCRYPTION_KEY).toString();
  return calculatedHash === receivedHash;
}

function createHash(data) {
  const jsonString = JSON.stringify(data);
  return CryptoJS.SHA256(jsonString + ENCRYPTION_KEY).toString();
}

/* ─── Helpers ─────────────────────────────────────────────────── */

function getIp(req) {
  const raw = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '';
  let ip = raw.startsWith('::ffff:') ? raw.slice(7) : raw;
  if (ip === '::1') ip = '127.0.0.1';
  return ip;
}

function cleanup() {
  const now = Date.now();
  for (const [id, ch] of challenges) if (now > ch.expires) challenges.delete(id);
  for (const [ip, r] of challengeRate) if (now > r.resetAt) challengeRate.delete(ip);
  for (const [ip, r] of failedAttempts) if (now > r.resetAt) failedAttempts.delete(ip);
}
setInterval(cleanup, 2 * 60_000);

function checkChallengeRate(ip) {
  const now = Date.now();
  const entry = challengeRate.get(ip) || { count: 0, resetAt: now + CHALLENGE_WINDOW };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + CHALLENGE_WINDOW; }
  if (entry.count >= CHALLENGE_LIMIT) return false;
  entry.count++;
  challengeRate.set(ip, entry);
  return true;
}

function isIpBlocked(ip) {
  const now = Date.now();
  const entry = failedAttempts.get(ip);
  if (!entry) return false;
  if (now > entry.resetAt) { failedAttempts.delete(ip); return false; }
  return entry.count >= FAIL_LIMIT;
}

function recordFailure(ip) {
  const now = Date.now();
  const entry = failedAttempts.get(ip) || { count: 0, resetAt: now + FAIL_WINDOW };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + FAIL_WINDOW; }
  entry.count++;
  failedAttempts.set(ip, entry);
}

function clearFailures(ip) {
  failedAttempts.delete(ip);
}

/* ─── Puzzle generator ────────────────────────────────────────── */

function generatePuzzle() {
  const op = ['+', '+', '+', '-', '*'][Math.floor(Math.random() * 5)];
  let a, b, answer;

  if (op === '+') {
    a = Math.floor(Math.random() * 9) + 1;
    b = Math.floor(Math.random() * 9) + 1;
    answer = a + b;
  } else if (op === '-') {
    a = Math.floor(Math.random() * 8) + 2;
    b = Math.floor(Math.random() * (a - 1)) + 1;
    answer = a - b;
  } else {
    a = Math.floor(Math.random() * 4) + 2;
    b = Math.floor(Math.random() * 4) + 2;
    answer = a * b;
  }

  const wrongSet = new Set();
  let attempts = 0;
  while (wrongSet.size < 5 && attempts < 200) {
    attempts++;
    const delta = (Math.floor(Math.random() * 4) - 2) || 1;
    const w = answer + delta;
    if (w > 0 && w !== answer) wrongSet.add(w);
  }

  const options = [...wrongSet].slice(0, 5);
  const correctIndex = Math.floor(Math.random() * 6);
  options.splice(correctIndex, 0, answer);

  return { question: `What is ${a} ${op} ${b} ?`, options, correctIndex, correctAnswer: answer };
}

/* ─── GET /api/captcha/challenge with encryption ──────────────── */

router.get('/challenge', async (req, res) => {
  try {
    const { encrypted, hash } = req.query;
    
    if (!encrypted || !hash) {
      return res.status(400).json({ message: 'Encrypted request required' });
    }
    
    let requestData;
    try {
      requestData = decryptData(encrypted);
    } catch (err) {
      return res.status(400).json({ message: 'Invalid encrypted request' });
    }
    
    if (!verifyHash(requestData, hash)) {
      return res.status(400).json({ message: 'Request integrity check failed' });
    }
    
    const currentTime = Date.now();
    const timeDiff = Math.abs(currentTime - requestData.timestamp);
    if (timeDiff > 5 * 60 * 1000) {
      return res.status(400).json({ message: 'Request expired' });
    }
    
    const ip = getIp(req);

    if (isIpBlocked(ip)) {
      const errorResponse = { success: false, message: 'Too many failed attempts. Please wait 15 minutes.' };
      const encryptedError = encryptResponse(errorResponse);
      const errorHash = createHash(errorResponse);
      return res.status(429).json({ encrypted: encryptedError, hash: errorHash });
    }

    if (!checkChallengeRate(ip)) {
      const errorResponse = { success: false, message: 'Too many requests. Please slow down.' };
      const encryptedError = encryptResponse(errorResponse);
      const errorHash = createHash(errorResponse);
      return res.status(429).json({ encrypted: encryptedError, hash: errorHash });
    }

    cleanup();

    if (challenges.size >= MAX_STORE) {
      const errorResponse = { success: false, message: 'Server busy, please try again shortly.' };
      const encryptedError = encryptResponse(errorResponse);
      const errorHash = createHash(errorResponse);
      return res.status(503).json({ encrypted: encryptedError, hash: errorHash });
    }

    const { question, options, correctIndex, correctAnswer } = generatePuzzle();
    const challengeId = crypto.randomUUID();
    const nonce = crypto.randomBytes(16).toString('hex');

    challenges.set(challengeId, {
      nonce,
      difficulty: DIFFICULTY,
      correctIndex,
      correctAnswer,
      issuedAt: Date.now(),
      issuedToIp: ip,
      expires: Date.now() + TTL_MS,
      used: false,
    });

    const responseData = {
      success: true,
      challengeId,
      nonce,
      difficulty: DIFFICULTY,
      question,
      options,
      timestamp: Date.now(),
    };
    
    const encryptedResponse = encryptResponse(responseData);
    const responseHash = createHash(responseData);
    
    return res.json({
      encrypted: encryptedResponse,
      hash: responseHash,
    });
    
  } catch (err) {
    console.error('Challenge generation error:', err);
    const errorResponse = { success: false, message: 'Server error' };
    const encryptedError = encryptResponse(errorResponse);
    const errorHash = createHash(errorResponse);
    return res.status(500).json({ encrypted: encryptedError, hash: errorHash });
  }
});

/* ─── verifyCaptcha() with encrypted input ───────────────────── */

function verifyCaptcha(encryptedData, hash, ip) {
  if (!encryptedData || !hash) {
    return { ok: false, reason: 'Missing captcha verification data' };
  }
  
  let verificationData;
  try {
    verificationData = decryptData(encryptedData);
  } catch (err) {
    recordFailure(ip);
    return { ok: false, reason: 'Invalid encrypted verification data' };
  }
  
  if (!verifyHash(verificationData, hash)) {
    recordFailure(ip);
    return { ok: false, reason: 'Verification data integrity check failed' };
  }
  
  const { challengeId, solution, answer: answerStr, timestamp, fingerprint } = verificationData;
  
  const currentTime = Date.now();
  const timeDiff = Math.abs(currentTime - timestamp);
  if (timeDiff > 5 * 60 * 1000) {
    recordFailure(ip);
    return { ok: false, reason: 'Verification request expired' };
  }

  if (isIpBlocked(ip)) {
    return { ok: false, reason: 'Too many failed attempts. Please wait 15 minutes.' };
  }

  const ch = challenges.get(challengeId);

  if (!ch) {
    recordFailure(ip);
    return { ok: false, reason: 'Challenge not found or expired' };
  }

  if (Date.now() > ch.expires) {
    challenges.delete(challengeId);
    return { ok: false, reason: 'Challenge expired — please try again' };
  }

  if (ch.used) {
    recordFailure(ip);
    return { ok: false, reason: 'Challenge already used' };
  }

  if (ch.issuedToIp !== ip) {
    recordFailure(ip);
    challenges.delete(challengeId);
    return { ok: false, reason: 'Challenge IP mismatch' };
  }

  if (Date.now() - ch.issuedAt < MIN_SOLVE_MS) {
    recordFailure(ip);
    challenges.delete(challengeId);
    return { ok: false, reason: 'Solved too quickly — please try again' };
  }

  const answerIndex = parseInt(answerStr, 10);
  if (isNaN(answerIndex) || answerIndex !== ch.correctIndex) {
    recordFailure(ip);
    return { ok: false, reason: 'Incorrect answer — please try again' };
  }

  const expected = '0'.repeat(ch.difficulty);
  const hashResult = crypto
    .createHash('sha256')
    .update(`${ch.nonce}:${answerStr}:${solution}`)
    .digest('hex');

  if (!hashResult.startsWith(expected)) {
    recordFailure(ip);
    challenges.delete(challengeId);
    return { ok: false, reason: 'Proof-of-work invalid' };
  }

  ch.used = true;
  challenges.delete(challengeId);
  clearFailures(ip);

  return { ok: true };
}

module.exports = { router, verifyCaptcha };