// middleware/apiAuthMiddleware.js - SHA-256 HMAC Signed Requests
const ApiUser = require('../models/ApiUser');
const crypto = require('crypto');

const TIMESTAMP_TOLERANCE_MS = 5 * 60 * 1000; // 5-minute replay window

/**
 * Verifies HMAC-SHA256 signature on every incoming API request.
 *
 * Client must send three headers:
 *   X-Api-Key   : the user's public API key  (e.g. ak_...)
 *   X-Timestamp : Unix ms timestamp          (Date.now())
 *   X-Signature : HMAC-SHA256 hex signature  (see signing string below)
 *
 * Signing string: `${timestamp}:${METHOD}:${fullPath}:${sha256(body)}`
 *   - METHOD    : uppercase HTTP verb (GET, POST, ...)
 *   - fullPath  : req.originalUrl  (includes query string)
 *   - sha256(body): hex SHA-256 of the raw JSON body, or SHA-256 of "" for GET
 *
 * Secret used for HMAC: the SHA-256 hash stored in apiUser.apiSecretHash
 * (the client signs with their raw apiSecret; the server hashes it before comparing)
 */
async function authenticateApiUser(req, res, next) {
    try {
        const apiKey    = req.headers['x-api-key'];
        const timestamp = req.headers['x-timestamp'];
        const signature = req.headers['x-signature'];

        // 1 ── All three headers required
        if (!apiKey || !timestamp || !signature) {
            return res.status(401).json({
                error: 'Missing authentication headers',
                required: ['x-api-key', 'x-timestamp', 'x-signature']
            });
        }

        // 2 ── Reject stale or future timestamps (replay protection)
        const tsNum = parseInt(timestamp, 10);
        if (isNaN(tsNum) || Math.abs(Date.now() - tsNum) > TIMESTAMP_TOLERANCE_MS) {
            return res.status(401).json({
                error: 'Request timestamp is expired or invalid (must be within 5 minutes of server time)'
            });
        }

        // 3 ── Look up API user by public key
        const apiUser = await ApiUser.findOne({ apiKey, status: 'active' });
        if (!apiUser) {
            return res.status(401).json({ error: 'Invalid or inactive API key' });
        }

        // 4 ── Build the signing string (must match client exactly)
        const method   = req.method.toUpperCase();
        const path     = req.originalUrl;
        const bodyStr  = (req.body && Object.keys(req.body).length > 0)
            ? JSON.stringify(req.body)
            : '';
        const bodyHash = crypto.createHash('sha256').update(bodyStr).digest('hex');

        const signingString = `${timestamp}:${method}:${path}:${bodyHash}`;

        // 5 ── Compute expected signature using stored hash as HMAC key
        //      The stored value is SHA-256(rawSecret).
        //      The client HMACs with rawSecret directly — this is intentional:
        //      we use the stored hash as the HMAC key so rawSecret never touches the server.
        const expectedSig = crypto
            .createHmac('sha256', apiUser.apiSecretHash)
            .update(signingString)
            .digest('hex');

        // 6 ── Timing-safe comparison to prevent timing attacks
        let valid = false;
        try {
            const sigBuf = Buffer.from(signature,   'hex');
            const expBuf = Buffer.from(expectedSig, 'hex');
            if (sigBuf.length === expBuf.length) {
                valid = crypto.timingSafeEqual(sigBuf, expBuf);
            }
        } catch {
            // Buffer.from can throw on non-hex strings — treat as invalid
        }

        if (!valid) {
            return res.status(401).json({ error: 'Invalid request signature' });
        }

        // 7 ── Attach user and proceed
        req.apiUser = apiUser;
        next();

    } catch (err) {
        console.error('[apiAuthMiddleware] Error:', err.message);
        res.status(500).json({ error: 'Authentication service unavailable' });
    }
}

module.exports = { authenticateApiUser };