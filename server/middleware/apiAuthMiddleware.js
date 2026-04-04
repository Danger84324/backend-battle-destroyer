// middleware/apiAuthMiddleware.js
const ApiUser = require('../models/ApiUser');

async function authenticateApiUser(req, res, next) {
    try {
        // Get API key from headers (support multiple formats)
        const apiKey = req.headers['x-api-key'] || 
                       req.headers['X-API-Key'] || 
                       req.headers['authorization']?.replace('Bearer ', '');
        
        if (!apiKey) {
            return res.status(401).json({ 
                error: 'API key required', 
                message: 'Please provide your API key in the x-api-key header' 
            });
        }
        
        // Find user by API key
        const apiUser = await ApiUser.findOne({ apiKey });
        
        if (!apiUser) {
            return res.status(401).json({ error: 'Invalid API key' });
        }
        
        // Check if account is expired
        if (apiUser.isExpired()) {
            return res.status(403).json({ 
                error: 'Account expired', 
                expiresAt: apiUser.expiresAt,
                message: 'Your API access has expired. Please contact support.'
            });
        }
        
        // Check if account is suspended
        if (apiUser.status !== 'active') {
            return res.status(403).json({ 
                error: 'Account suspended', 
                status: apiUser.status,
                message: 'Your account is not active. Please contact support.'
            });
        }
        
        // Attach user to request
        req.apiUser = apiUser;
        next();
        
    } catch (error) {
        console.error('API Auth Error:', error);
        res.status(500).json({ error: 'Authentication failed', message: error.message });
    }
}

module.exports = { authenticateApiUser };