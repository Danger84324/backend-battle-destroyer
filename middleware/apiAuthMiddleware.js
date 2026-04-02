// middleware/apiAuthMiddleware.js - SIMPLE VERSION
const ApiUser = require('../models/ApiUser');

async function authenticateApiUser(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
        return res.status(401).json({ error: 'API key required' });
    }
    
    const apiUser = await ApiUser.findOne({ apiKey, status: 'active' });
    
    if (!apiUser) {
        return res.status(401).json({ error: 'Invalid or inactive API key' });
    }
    
    req.apiUser = apiUser;
    next();
}

module.exports = { authenticateApiUser };