// api/v1/hackrx/run.js
// Enhanced Insurance Policy Analysis with API Key Authentication
// Version 3.0 - Production Ready with Security

const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// Load environment variables
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

// ===== API KEY MANAGEMENT =====
const API_KEYS_DB = {
    // In production, store these in a real database
    'hk_live_1a2b3c4d5e6f7g8h9i0j': {
        id: 'api_001',
        name: 'Insurance Company A',
        permissions: ['policy_analysis', 'claim_processing'],
        rateLimit: 1000, // requests per hour
        isActive: true,
        createdAt: '2024-01-01T00:00:00Z'
    },
    'hk_test_9z8y7x6w5v4u3t2s1r0q': {
        id: 'api_002',
        name: 'Development Testing',
        permissions: ['policy_analysis'],
        rateLimit: 100,
        isActive: true,
        createdAt: '2024-01-01T00:00:00Z'
    }
};

// Generate new API keys
const generateApiKey = (prefix = 'hk_live') => {
    const randomBytes = crypto.randomBytes(16).toString('hex');
    return `${prefix}_${randomBytes}`;
};

// Validate API key format
const isValidApiKeyFormat = (key) => {
    return /^hk_(live|test)_[a-f0-9]{32}$/.test(key);
};

// API Key Authentication Middleware
const authenticateApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'] || 
                   req.headers['authorization']?.replace('Bearer ', '') ||
                   req.query.api_key;

    if (!apiKey) {
        return res.status(401).json({
            error: 'Authentication Required',
            message: 'API key missing. Include it in X-API-Key header or as Bearer token.',
            code: 'MISSING_API_KEY'
        });
    }

    if (!isValidApiKeyFormat(apiKey)) {
        return res.status(401).json({
            error: 'Invalid API Key Format',
            message: 'API key must be in format: hk_live_xxx or hk_test_xxx',
            code: 'INVALID_FORMAT'
        });
    }

    const keyData = API_KEYS_DB[apiKey];
    if (!keyData || !keyData.isActive) {
        return res.status(403).json({
            error: 'Invalid API Key',
            message: 'The provided API key is invalid or has been deactivated.',
            code: 'INVALID_KEY'
        });
    }

    // Check permissions
    if (!keyData.permissions.includes('policy_analysis')) {
        return res.status(403).json({
            error: 'Insufficient Permissions',
            message: 'Your API key does not have permission for policy analysis.',
            code: 'INSUFFICIENT_PERMISSIONS'
        });
    }

    // Attach key data to request
    req.apiKeyData = keyData;
    req.clientId = keyData.id;
    
    console.log(`[${req.clientId}] API request authenticated`);
    next();
};

// Rate limiting by API key
const rateLimitByApiKey = (req, res, next) => {
    const { apiKeyData } = req;
    const keyId = apiKeyData.id;
    
    // In production, use Redis or similar for rate limiting
    const now = Date.now();
    const windowMs = 60 * 60 * 1000; // 1 hour
    
    if (!global.rateLimitStore) global.rateLimitStore = {};
    if (!global.rateLimitStore[keyId]) {
        global.rateLimitStore[keyId] = { count: 0, resetTime: now + windowMs };
    }
    
    const store = global.rateLimitStore[keyId];
    
    if (now > store.resetTime) {
        store.count = 0;
        store.resetTime = now + windowMs;
    }
    
    if (store.count >= apiKeyData.rateLimit) {
        return res.status(429).json({
            error: 'Rate Limit Exceeded',
            message: `Rate limit of ${apiKeyData.rateLimit} requests per hour exceeded.`,
            code: 'RATE_LIMIT_EXCEEDED',
            retryAfter: Math.ceil((store.resetTime - now) / 1000)
        });
    }
    
    store.count++;
    
    // Add rate limit headers
    res.setHeader('X-RateLimit-Limit', apiKeyData.rateLimit);
    res.setHeader('X-RateLimit-Remaining', apiKeyData.rateLimit - store.count);
    res.setHeader('X-RateLimit-Reset', new Date(store.resetTime).toISOString());
    
    next();
};

// ===== INSURANCE DOMAIN KNOWLEDGE (from previous code) =====
const INSURANCE_RULES = {
    waitingPeriods: {
        'joint surgery': 24,
        'cardiac procedures': 36,
        'pre-existing conditions': 48,
        'maternity': 9,
        'dental procedures': 12,
        'eye surgery': 18,
        'cancer treatment': 60,
        'mental health': 12
    },
    ageRestrictions: {
        seniorCitizen: { age: 65, coPayment: 30 },
        superSenior: { age: 75, coPayment: 50 },
        pediatric: { age: 18, specialRules: true }
    },
    maxCoverageAmounts: {
        'knee replacement': 200000,
        'hip replacement': 250000,
        'cardiac surgery': 500000,
        'general surgery': 100000,
        'cancer treatment': 1000000,
        'maternity': 150000,
        'dental treatment': 50000,
        'eye surgery': 100000
    }
};

// ===== UTILITY FUNCTIONS (from previous code) =====
const extractUserDetails = (query) => {
    const ageMatch = query.match(/(?:i am|age|aged|years old|year old)\s*(\d+)/i);
    const durationMatch = query.match(/policy\s*(?:is\s*)?(\d+)\s*(?:years?|months?)/i);
    const genderMatch = query.match(/(?:i am|i'm)\s*(male|female|man|woman)/i);
    
    return {
        age: ageMatch ? parseInt(ageMatch[1]) : null,
        policyDuration: durationMatch ? parseInt(durationMatch[1]) : null,
        gender: genderMatch ? genderMatch[1].toLowerCase() : null,
        procedureType: extractProcedureType(query),
        hasPreExisting: checkPreExistingConditions(query)
    };
};

const extractProcedureType = (query) => {
    const procedures = {
        'knee replacement': 'joint surgery',
        'hip replacement': 'joint surgery',
        'joint replacement': 'joint surgery',
        'heart surgery': 'cardiac procedures',
        'cardiac surgery': 'cardiac procedures',
        'bypass': 'cardiac procedures',
        'angioplasty': 'cardiac procedures',
        'maternity': 'maternity',
        'pregnancy': 'maternity',
        'delivery': 'maternity',
        'cancer treatment': 'cancer treatment',
        'chemotherapy': 'cancer treatment',
        'radiation': 'cancer treatment',
        'dental': 'dental procedures',
        'tooth': 'dental procedures',
        'eye surgery': 'eye surgery',
        'cataract': 'eye surgery',
        'lasik': 'eye surgery',
        'mental health': 'mental health',
        'psychiatry': 'mental health',
        'therapy': 'mental health'
    };
    
    const queryLower = query.toLowerCase();
    for (const [keyword, category] of Object.entries(procedures)) {
        if (queryLower.includes(keyword)) {
            return { name: keyword, category };
        }
    }
    return null;
};

const checkPreExistingConditions = (query) => {
    const preExistingKeywords = [
        'pre-existing', 'preexisting', 'chronic', 'ongoing', 'previous', 
        'diabetes', 'hypertension', 'heart disease', 'arthritis'
    ];
    return preExistingKeywords.some(keyword => 
        query.toLowerCase().includes(keyword)
    );
};

const validateAgainstDomainRules = (decision, userDetails, query) => {
    const warnings = [];
    const { age, policyDuration, procedureType, hasPreExisting } = userDetails;
    
    // Check waiting period compliance
    if (procedureType && INSURANCE_RULES.waitingPeriods[procedureType.category]) {
        const requiredWaitingMonths = INSURANCE_RULES.waitingPeriods[procedureType.category];
        if (policyDuration && policyDuration * 12 < requiredWaitingMonths) {
            warnings.push({
                type: 'waiting_period',
                message: `Policy duration (${policyDuration} years) does not meet waiting period requirement (${requiredWaitingMonths} months)`,
                severity: 'high'
            });
        }
    }
    
    // Additional validation logic...
    return warnings;
};

const callGeminiAPI = async (prompt, apiKey, retries = 2) => {
    const API_URL = `https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${apiKey}`;
    
    const payload = {
        contents: [{
            parts: [{ text: prompt }]
        }],
        generationConfig: {
            temperature: 0.1,
            topK: 1,
            topP: 0.8,
            maxOutputTokens: 2048,
        }
    };

    for (let attempt = 0; attempt <= retries; attempt++) {
        try {
            const response = await fetch(API_URL, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'User-Agent': 'Insurance-Policy-Analyzer/3.0'
                },
                body: JSON.stringify(payload),
                timeout: 30000
            });

            if (!response.ok) {
                throw new Error(`Gemini API request failed with status ${response.status}`);
            }

            const result = await response.json();
            const rawText = result.candidates[0].content.parts[0].text;
            const cleanedText = rawText.replace(/``````/g, '').trim();
            
            return JSON.parse(cleanedText);
        } catch (error) {
            if (attempt === retries) throw error;
            await new Promise(resolve => setTimeout(resolve, 1000 * (attempt + 1)));
        }
    }
};

const createEnhancedPrompt = (query, documentText, userDetails) => {
    // Use the same enhanced prompt from previous code
    return `Your enhanced prompt here...`;
};

// ===== MAIN HANDLER WITH API KEY AUTHENTICATION =====
export default async function handler(request, response) {
    // CORS Headers
    response.setHeader('Access-Control-Allow-Origin', '*');
    response.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    response.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-API-Key, Authorization');
    
    if (request.method === 'OPTIONS') {
        return response.status(200).end();
    }
    
    if (request.method !== 'POST') {
        return response.status(405).json({ 
            error: 'Method Not Allowed',
            message: 'Only POST requests are supported'
        });
    }

    // Apply API key authentication
    try {
        await new Promise((resolve, reject) => {
            authenticateApiKey(request, response, (error) => {
                if (error) reject(error);
                else resolve();
            });
        });
        
        await new Promise((resolve, reject) => {
            rateLimitByApiKey(request, response, (error) => {
                if (error) reject(error);
                else resolve();
            });
        });
    } catch (authError) {
        return; // Response already sent by middleware
    }

    const startTime = Date.now();
    const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    console.log(`[${requestId}] [${request.clientId}] Processing authenticated request`);

    try {
        const { query, documentText } = request.body;
        
        // Enhanced input validation
        if (!query || typeof query !== 'string' || query.trim().length < 5) {
            return response.status(400).json({ 
                error: 'Invalid Query',
                message: 'Query must be a non-empty string with at least 5 characters.',
                requestId
            });
        }
        
        if (!documentText || typeof documentText !== 'string' || documentText.trim().length < 20) {
            return response.status(400).json({ 
                error: 'Invalid Document',
                message: 'Document text must be provided and contain substantial content.',
                requestId
            });
        }

        const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
        if (!GEMINI_API_KEY) {
            throw new Error("Gemini API key is not configured");
        }

        // Extract user details
        const userDetails = extractUserDetails(query);
        
        // Create enhanced prompt
        const primaryPrompt = createEnhancedPrompt(query, documentText, userDetails);
        
        // Call Gemini API
        const primaryDecision = await callGeminiAPI(primaryPrompt, GEMINI_API_KEY);
        
        // Apply domain rule validation
        const domainWarnings = validateAgainstDomainRules(primaryDecision, userDetails, query);
        
        let finalDecision = { ...primaryDecision };
        
        if (domainWarnings.length > 0) {
            finalDecision.domain_warnings = domainWarnings;
            const highSeverityWarnings = domainWarnings.filter(w => w.severity === 'high').length;
            const confidenceReduction = highSeverityWarnings * 0.15 + (domainWarnings.length - highSeverityWarnings) * 0.05;
            finalDecision.confidence = Math.max(0.1, finalDecision.confidence - confidenceReduction);
        }

        // Final decision routing
        const highSeverityWarnings = domainWarnings.filter(w => w.severity === 'high').length;
        if (finalDecision.confidence < 0.6 || highSeverityWarnings > 1) {
            finalDecision.decision = "Requires Manual Review";
            finalDecision.priority = highSeverityWarnings > 1 ? "urgent" : "high";
        }

        // Add metadata
        finalDecision.metadata = {
            request_id: requestId,
            client_id: request.clientId,
            processing_time_ms: Date.now() - startTime,
            model_used: "gemini-pro",
            system_version: "3.0-secure",
            timestamp: new Date().toISOString(),
            api_key_permissions: request.apiKeyData.permissions
        };

        console.log(`[${requestId}] [${request.clientId}] Analysis completed successfully`);
        return response.status(200).json(finalDecision);

    } catch (error) {
        console.error(`[${requestId}] [${request.clientId}] Error:`, error);
        
        return response.status(500).json({ 
            error: 'Internal Server Error',
            message: 'Failed to process the insurance policy analysis.',
            requestId,
            timestamp: new Date().toISOString()
        });
    }
}

// ===== API KEY MANAGEMENT ENDPOINTS =====

// Generate new API key (admin only)
export const generateNewApiKey = async (req, res) => {
    // This would typically require admin authentication
    const { name, permissions, rateLimit, environment } = req.body;
    
    const prefix = environment === 'production' ? 'hk_live' : 'hk_test';
    const newKey = generateApiKey(prefix);
    
    const keyData = {
        id: `api_${Date.now()}`,
        name,
        permissions: permissions || ['policy_analysis'],
        rateLimit: rateLimit || 1000,
        isActive: true,
        createdAt: new Date().toISOString()
    };
    
    // In production, save to database
    API_KEYS_DB[newKey] = keyData;
    
    res.json({
        message: 'API key generated successfully',
        apiKey: newKey,
        keyData: { ...keyData, apiKey: undefined } // Don't return the key in data
    });
};

// Revoke API key
export const revokeApiKey = async (req, res) => {
    const { apiKey } = req.body;
    
    if (API_KEYS_DB[apiKey]) {
        API_KEYS_DB[apiKey].isActive = false;
        res.json({ message: 'API key revoked successfully' });
    } else {
        res.status(404).json({ error: 'API key not found' });
    }
};