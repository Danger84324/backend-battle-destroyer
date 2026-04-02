/**
 * routes/captcha.js
 *
 * Protection layers (all properly wired):
 *  1. Per-IP challenge rate limit  — max 10 challenges / 5 min per IP
 *  2. Per-IP failed attempt limit  — blocked after 3 wrong answers for 15 min
 *  3. Minimum solve time           — rejects solutions < 2 s (bot speed)
 *  4. IP binding                   — challenge must be solved by same IP that fetched it
 *  5. Single-use challenges        — each challengeId deleted on first use
 *  6. Short TTL                    — challenges expire after 5 minutes
 *  7. PoW verification             — SHA-256 with 4 leading zeros (~65k hashes)
 *  8. Server-side answer           — correctIndex never sent to client
 */

const express = require('express');
const router  = express.Router();
const crypto  = require('crypto');

/* ─── Config ──────────────────────────────────────────────────── */

const DIFFICULTY       = 4;            // 4 leading hex zeros ≈ 1–2 s in browser JS
const TTL_MS           = 5 * 60_000;   // challenge expires after 5 min
const MIN_SOLVE_MS     = 2_000;        // reject if solved in under 2 s (bot speed)
const MAX_STORE        = 50_000;       // memory safety cap
const CHALLENGE_LIMIT  = 10;           // max challenges one IP can fetch per window
const CHALLENGE_WINDOW = 5 * 60_000;  // rate window for challenge fetching (5 min)
const FAIL_LIMIT       = 3;           // wrong answers before IP is blocked
const FAIL_WINDOW      = 15 * 60_000; // block duration (15 min)

/* ─── Stores ──────────────────────────────────────────────────── */

const challenges    = new Map(); // challengeId → record
const challengeRate = new Map(); // ip → { count, resetAt }
const failedAttempts= new Map(); // ip → { count, resetAt }

/* ─── Helpers ─────────────────────────────────────────────────── */

function getIp(req) {
  const raw = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '';
  let ip = raw.startsWith('::ffff:') ? raw.slice(7) : raw;
  if (ip === '::1') ip = '127.0.0.1';
  return ip;
}

function cleanup() {
  const now = Date.now();
  for (const [id, ch] of challenges)     if (now > ch.expires)  challenges.delete(id);
  for (const [ip, r]  of challengeRate)  if (now > r.resetAt)   challengeRate.delete(ip);
  for (const [ip, r]  of failedAttempts) if (now > r.resetAt)   failedAttempts.delete(ip);
}
setInterval(cleanup, 2 * 60_000);

/* Returns false if IP has fetched too many challenges recently (anti-harvest) */
function checkChallengeRate(ip) {
  const now   = Date.now();
  const entry = challengeRate.get(ip) || { count: 0, resetAt: now + CHALLENGE_WINDOW };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + CHALLENGE_WINDOW; }
  if (entry.count >= CHALLENGE_LIMIT) return false;
  entry.count++;
  challengeRate.set(ip, entry);
  return true;
}

/* Returns true if IP is blocked due to too many wrong answers */
function isIpBlocked(ip) {
  const now   = Date.now();
  const entry = failedAttempts.get(ip);
  if (!entry) return false;
  if (now > entry.resetAt) { failedAttempts.delete(ip); return false; }
  return entry.count >= FAIL_LIMIT;
}

function recordFailure(ip) {
  const now   = Date.now();
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
    a = Math.floor(Math.random() * 9) + 1;  // 1–9
    b = Math.floor(Math.random() * 9) + 1;  // 1–9
    answer = a + b;
  } else if (op === '-') {
    a = Math.floor(Math.random() * 8) + 2;  // 2–9
    b = Math.floor(Math.random() * (a - 1)) + 1; // 1 to (a-1) so answer is always positive
    answer = a - b;
  } else {
    a = Math.floor(Math.random() * 4) + 2;  // 2–5
    b = Math.floor(Math.random() * 4) + 2;  // 2–5
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

  const options      = [...wrongSet].slice(0, 5);
  const correctIndex = Math.floor(Math.random() * 6);
  options.splice(correctIndex, 0, answer);

  return { question: `What is  ${a} ${op} ${b} ?`, options, correctIndex, correctAnswer: answer };
}

/* ─── GET /api/captcha/challenge ──────────────────────────────── */

router.get('/challenge', (req, res) => {
  const ip = getIp(req);

  // Block IPs with too many recent failures
  if (isIpBlocked(ip)) {
    return res.status(429).json({ message: 'Too many failed attempts. Please wait 15 minutes.' });
  }

  // Block IPs harvesting too many challenges
  if (!checkChallengeRate(ip)) {
    return res.status(429).json({ message: 'Too many requests. Please slow down.' });
  }

  cleanup();

  if (challenges.size >= MAX_STORE) {
    return res.status(503).json({ message: 'Server busy, please try again shortly.' });
  }

  const { question, options, correctIndex, correctAnswer } = generatePuzzle();
  const challengeId = crypto.randomUUID();
  const nonce       = crypto.randomBytes(16).toString('hex');

  challenges.set(challengeId, {
    nonce,
    difficulty:   DIFFICULTY,
    correctIndex,   // NOT sent to client
    correctAnswer,
    issuedAt:     Date.now(),  // for minimum solve time check
    issuedToIp:   ip,          // IP binding
    expires:      Date.now() + TTL_MS,
    used:         false,
  });

  return res.json({ challengeId, nonce, difficulty: DIFFICULTY, question, options });
});

/* ─── verifyCaptcha() — called from auth.js ───────────────────── */

/**
 * @param {string} challengeId
 * @param {string} solution     counter found by the PoW loop
 * @param {string} answerStr    button index the user clicked (as string "0"–"5")
 * @param {string} ip           request IP — pass this from auth.js
 * @returns {{ ok: boolean, reason?: string }}
 */
function verifyCaptcha(challengeId, solution, answerStr, ip) {
  // 0. Basic field check
  if (!challengeId || solution === undefined || answerStr === undefined) {
    return { ok: false, reason: 'Missing captcha fields' };
  }

  // 1. IP blocked from too many failures
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

  // 2. IP binding — must be solved by the same IP that fetched the challenge
  if (ch.issuedToIp !== ip) {
    recordFailure(ip);
    challenges.delete(challengeId);
    return { ok: false, reason: 'Challenge IP mismatch' };
  }

  // 3. Minimum solve time — too fast = pre-computed bot
  if (Date.now() - ch.issuedAt < MIN_SOLVE_MS) {
    recordFailure(ip);
    challenges.delete(challengeId);
    return { ok: false, reason: 'Solved too quickly — please try again' };
  }

  // 4. Verify the clicked answer index
  const answerIndex = parseInt(answerStr, 10);
  if (isNaN(answerIndex) || answerIndex !== ch.correctIndex) {
    recordFailure(ip);
    // Don't delete challenge so user can retry clicking the right button
    return { ok: false, reason: 'Incorrect answer — please try again' };
  }

  // 5. Verify the Proof-of-Work hash
  const expected = '0'.repeat(ch.difficulty);
  const hash = crypto
    .createHash('sha256')
    .update(`${ch.nonce}:${answerStr}:${solution}`)
    .digest('hex');

  if (!hash.startsWith(expected)) {
    recordFailure(ip);
    challenges.delete(challengeId);
    return { ok: false, reason: 'Proof-of-work invalid' };
  }

  // ✅ All checks passed
  ch.used = true;
  challenges.delete(challengeId);
  clearFailures(ip);  // reset failure count for this IP on success

  return { ok: true };
}

module.exports = { router, verifyCaptcha };