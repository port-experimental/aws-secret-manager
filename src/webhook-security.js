const crypto = require('crypto');
const logger = require('./logger');

/**
 * Verify Port webhook signature
 * Port signs webhooks using HMAC-SHA256 with a shared secret
 */
function verifyPortSignature(req, webhookSecret) {
  if (!webhookSecret) {
    logger.warn('WEBHOOK_SECRET not configured - signature verification disabled');
    return true; // Allow if not configured (for backward compatibility)
  }

  // Port sends signature in x-port-signature header (format: v1,<base64_signature>)
  const receivedSignature = req.headers['x-port-signature'];
  const portTimestamp = req.headers['x-port-timestamp'];
  
  if (!receivedSignature) {
    logger.error('Missing x-port-signature header');
    return false;
  }

  if (!portTimestamp) {
    logger.error('Missing x-port-timestamp header');
    return false;
  }

  try {
    // Port's signature format: v1,<base64_signature>
    // Extract the actual signature (after the comma)
    const signatureParts = receivedSignature.split(',');
    if (signatureParts.length !== 2 || signatureParts[0] !== 'v1') {
      logger.error('Invalid signature format. Expected: v1,<signature>');
      logger.debug(`Received: ${receivedSignature}`);
      return false;
    }
    const receivedSig = signatureParts[1];

    // Port signs: timestamp.payload
    // Use raw body if available (exact bytes Port signed), otherwise re-stringify
    const payload = req.rawBody || JSON.stringify(req.body);
    
    // Debug: Log what we're signing
    logger.debug(`Timestamp from header: ${portTimestamp}`);
    logger.debug(`Using raw body: ${!!req.rawBody}`);
    logger.debug(`Payload (first 200 chars): ${payload.substring(0, 200)}`);
    
    // Try to compute signature - Port's docs say seconds, but they might send milliseconds
    // Try both formats to see which one matches
    let expectedSig;
    let signatureContent;
    
    // First try: use timestamp as-is (milliseconds if that's what Port sends)
    signatureContent = `${portTimestamp}.${payload}`;
    let hmac = crypto.createHmac('sha256', webhookSecret);
    hmac.update(signatureContent, 'utf8');
    expectedSig = hmac.digest('base64');
    
    logger.debug(`Trying timestamp as-is: ${portTimestamp}`);
    logger.debug(`Expected signature: ${expectedSig}`);
    
    // Check if lengths match before constant-time comparison
    if (receivedSig.length !== expectedSig.length) {
      logger.error('Signature length mismatch');
      logger.debug(`Expected length: ${expectedSig.length}, Received length: ${receivedSig.length}`);
      logger.debug(`Expected: ${expectedSig}`);
      logger.debug(`Received: ${receivedSig}`);
      return false;
    }
    
    // Constant-time comparison to prevent timing attacks
    const isValid = crypto.timingSafeEqual(
      Buffer.from(receivedSig),
      Buffer.from(expectedSig)
    );
    
    if (!isValid) {
      logger.error('Invalid webhook signature');
      logger.debug(`Expected: ${expectedSig}`);
      logger.debug(`Received: ${receivedSig}`);
      logger.debug(`Timestamp: ${portTimestamp}`);
      logger.debug(`Payload length: ${payload.length}`);
    } else {
      logger.debug('Webhook signature verified successfully');
    }
    
    return isValid;
  } catch (error) {
    logger.error('Error verifying webhook signature:', error.message);
    logger.debug('Stack trace:', error.stack);
    return false;
  }
}

/**
 * Verify request is from Port's IP ranges
 * Port publishes their webhook IP ranges
 */
function verifyPortIPAddress(req, allowedIPs = []) {
  if (!allowedIPs || allowedIPs.length === 0) {
    return true; // Skip if not configured
  }

  // Get client IP (handle proxies)
  const clientIP = req.headers['x-forwarded-for']?.split(',')[0].trim() 
                   || req.headers['x-real-ip']
                   || req.connection.remoteAddress
                   || req.socket.remoteAddress;

  logger.debug(`Request from IP: ${clientIP}`);

  // Check if IP is in allowed list
  const isAllowed = allowedIPs.some(allowedIP => {
    if (allowedIP.includes('/')) {
      // CIDR notation support (requires additional library)
      return clientIP.startsWith(allowedIP.split('/')[0]);
    }
    return clientIP === allowedIP;
  });

  if (!isAllowed) {
    logger.warn(`Request from unauthorized IP: ${clientIP}`);
  }

  return isAllowed;
}

/**
 * Verify request timestamp to prevent replay attacks
 * Reject requests older than 5 minutes
 */
function verifyRequestTimestamp(req, maxAgeSeconds = 300) {
  const timestamp = req.headers['x-port-timestamp'];
  
  if (!timestamp) {
    logger.debug('No x-port-timestamp header found');
    return true; // Optional check
  }

  try {
    // Port sends timestamp in milliseconds (despite docs saying seconds)
    const requestTime = parseInt(timestamp);
    const now = Date.now();
    const age = (now - requestTime) / 1000; // Convert to seconds for comparison

    if (age > maxAgeSeconds) {
      logger.warn(`Request too old: ${age.toFixed(2)} seconds (max: ${maxAgeSeconds})`);
      return false;
    }

    if (age < -60) {
      logger.warn(`Request timestamp in future: ${Math.abs(age).toFixed(2)} seconds`);
      return false;
    }

    logger.debug(`Request age: ${age.toFixed(2)} seconds`);
    return true;
  } catch (error) {
    logger.error('Error verifying timestamp:', error);
    return false;
  }
}

/**
 * Rate limiting per IP address
 */
class RateLimiter {
  constructor(maxRequests = 100, windowMs = 60000) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this.requests = new Map();
  }

  isAllowed(identifier) {
    const now = Date.now();
    const windowStart = now - this.windowMs;

    // Get or create request log for this identifier
    if (!this.requests.has(identifier)) {
      this.requests.set(identifier, []);
    }

    const requestLog = this.requests.get(identifier);

    // Remove old requests outside the window
    const recentRequests = requestLog.filter(time => time > windowStart);
    this.requests.set(identifier, recentRequests);

    // Check if limit exceeded
    if (recentRequests.length >= this.maxRequests) {
      logger.warn(`Rate limit exceeded for ${identifier}: ${recentRequests.length} requests`);
      return false;
    }

    // Add current request
    recentRequests.push(now);
    return true;
  }

  cleanup() {
    // Periodically clean up old entries
    const now = Date.now();
    const windowStart = now - this.windowMs;

    for (const [identifier, requestLog] of this.requests.entries()) {
      const recentRequests = requestLog.filter(time => time > windowStart);
      if (recentRequests.length === 0) {
        this.requests.delete(identifier);
      } else {
        this.requests.set(identifier, recentRequests);
      }
    }
  }
}

/**
 * Express middleware for webhook security
 */
function createWebhookSecurityMiddleware(options = {}) {
  const {
    webhookSecret = process.env.WEBHOOK_SECRET,
    allowedIPs = process.env.ALLOWED_IPS?.split(',').map(ip => ip.trim()),
    maxRequestAge = 300,
    enableRateLimit = true,
    maxRequestsPerMinute = 100,
  } = options;

  const rateLimiter = enableRateLimit ? new RateLimiter(maxRequestsPerMinute, 60000) : null;

  // Cleanup rate limiter every 5 minutes
  if (rateLimiter) {
    setInterval(() => rateLimiter.cleanup(), 5 * 60 * 1000);
  }

  return (req, res, next) => {
    // 1. Verify signature (most important)
    if (!verifyPortSignature(req, webhookSecret)) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid webhook signature'
      });
    }

    // 2. Verify IP address (if configured)
    if (!verifyPortIPAddress(req, allowedIPs)) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Request from unauthorized IP address'
      });
    }

    // 3. Verify timestamp (prevent replay attacks)
    if (!verifyRequestTimestamp(req, maxRequestAge)) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Request timestamp invalid or too old'
      });
    }

    // 4. Rate limiting
    if (rateLimiter) {
      const clientIP = req.headers['x-forwarded-for']?.split(',')[0].trim() 
                       || req.connection.remoteAddress;
      
      if (!rateLimiter.isAllowed(clientIP)) {
        return res.status(429).json({
          error: 'Too Many Requests',
          message: 'Rate limit exceeded'
        });
      }
    }

    next();
  };
}

module.exports = {
  verifyPortSignature,
  verifyPortIPAddress,
  verifyRequestTimestamp,
  RateLimiter,
  createWebhookSecurityMiddleware,
};
