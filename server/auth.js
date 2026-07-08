/**
 * Auth API routes
 * - POST /api/auth/generate - Generate one-time token (requires ECC signature)
 * - POST /api/auth/verify   - Consume token + create session
 * - GET  /api/auth/session  - Check session validity
 * - POST /api/auth/logout   - Destroy session
 * - GET  /api/auth/health   - Health check
 */

import { Router } from 'express';
import { store } from './store.js';
import {
  verifyECDSASignature,
  generateToken,
  generateSessionId,
  sha256,
} from './crypto.js';

const router = Router();

// Config defaults
const DEFAULT_CONFIG = {
  token_ttl: 300,        // 5 minutes in seconds
  session_ttl: 86400,    // 24 hours in seconds
  rate_limit_max: 30,
  rate_limit_window: 60, // 60 seconds
  fingerprint_mode: 'strict', // strict | fuzzy
  ecc_enabled: 'true',
};

function getConfig(key) {
  return store.hGet('auth:config', key) ?? DEFAULT_CONFIG[key] ?? null;
}

// === POST /api/auth/generate ===
// Requires: { pub_key, timestamp, nonce, fingerprint, signature }
router.post('/generate', (req, res) => {
  const { pub_key, timestamp, nonce, fingerprint, signature } = req.body;

  if (!pub_key || !timestamp || !nonce || !fingerprint || !signature) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields',
      message: 'pub_key, timestamp, nonce, fingerprint, signature are required',
    });
  }

  // Check timestamp freshness (5 minute window)
  const ts = parseInt(timestamp, 10);
  if (Math.abs(Date.now() - ts) > 5 * 60 * 1000) {
    return res.status(400).json({
      success: false,
      error: 'Timestamp expired',
      message: 'Request timestamp is too old or too far in the future',
    });
  }

  // Verify ECC signature
  const eccEnabled = getConfig('ecc_enabled');
  if (eccEnabled !== 'false') {
    const signedMessage = `${timestamp}.${nonce}.${fingerprint}`;
    const valid = verifyECDSASignature(pub_key, signedMessage, signature);
    if (!valid) {
      return res.status(400).json({
        success: false,
        error: 'Invalid signature',
        message: 'ECDSA signature verification failed',
      });
    }
  }

  // Generate one-time token
  const token = generateToken(pub_key);
  const tokenTtl = parseInt(getConfig('token_ttl') || '300', 10);

  // Store token with metadata
  store.set(`once_token:${token}`, JSON.stringify({
    pub_key,
    fingerprint,
    created_at: Date.now(),
  }), tokenTtl * 1000);

  res.json({
    success: true,
    data: {
      token,
      ttl: tokenTtl,
    },
  });
});

// === POST /api/auth/verify ===
// Requires: { token }
// Returns: session cookie
router.post('/verify', (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({
      success: false,
      error: 'Missing token',
      message: 'Token is required',
    });
  }

  // Atomic GET+DEL (use-and-destroy)
  const tokenData = store.getAndDel(`once_token:${token}`);
  if (!tokenData) {
    return res.status(401).json({
      success: false,
      error: 'Invalid or expired token',
      message: 'Token has already been used or expired',
    });
  }

  const { pub_key, fingerprint } = JSON.parse(tokenData);

  // Create session
  const sessionId = generateSessionId();
  const sessionTtl = parseInt(getConfig('session_ttl') || '86400', 10);
  const now = Math.floor(Date.now() / 1000);

  const sessionData = {
    id: sessionId,
    pub_key,
    pub_key_hash: sha256(pub_key),
    fingerprint,
    ip: req.ip || req.connection?.remoteAddress || 'unknown',
    user_agent: req.headers['user-agent'] || 'unknown',
    created_at: now,
    last_active: now,
  };

  store.set(`session:${sessionId}`, JSON.stringify(sessionData), sessionTtl * 1000);
  store.set(`session_pub:${sessionId}`, pub_key, sessionTtl * 1000);

  // Set session cookie
  res.cookie('auth_session', sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    domain: '.okok.cfd',
    maxAge: sessionTtl * 1000,
    path: '/',
  });

  res.json({
    success: true,
    data: {
      session_id: sessionId,
      ttl: sessionTtl,
      created_at: now,
    },
  });
});

// === GET /api/auth/session ===
// Requires: Authorization header or cookie
router.get('/session', (req, res) => {
  const sessionId = req.cookies?.auth_session || req.headers.authorization?.replace('Bearer ', '');

  if (!sessionId) {
    return res.status(401).json({
      success: false,
      error: 'No session',
      message: 'No session cookie or token provided',
    });
  }

  const sessionRaw = store.get(`session:${sessionId}`);
  if (!sessionRaw) {
    return res.status(401).json({
      success: false,
      error: 'Session expired',
      message: 'Session has expired or was destroyed',
    });
  }

  const session = JSON.parse(sessionRaw);
  const ttl = store.ttl(`session:${sessionId}`);

  // Update last_active
  session.last_active = Math.floor(Date.now() / 1000);
  store.set(`session:${sessionId}`, JSON.stringify(session), ttl * 1000);

  res.json({
    success: true,
    data: {
      session_id: sessionId,
      fingerprint: session.fingerprint,
      pub_key_hash: session.pub_key_hash,
      ip: session.ip,
      user_agent: session.user_agent,
      created_at: session.created_at,
      last_active: session.last_active,
      ttl,
    },
  });
});

// === POST /api/auth/logout ===
router.post('/logout', (req, res) => {
  const sessionId = req.cookies?.auth_session || req.headers.authorization?.replace('Bearer ', '');

  if (sessionId) {
    store.del(`session:${sessionId}`);
    store.del(`session_pub:${sessionId}`);
  }

  // Always clear cookie
  res.clearCookie('auth_session', {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    domain: '.okok.cfd',
    path: '/',
  });

  res.json({
    success: true,
    message: sessionId ? 'Session destroyed' : 'No active session',
  });
});

// === GET /api/auth/health ===
router.get('/health', (_req, res) => {
  res.json({
    success: true,
    data: {
      status: 'ok',
      store: 'memory',
      time: new Date().toISOString(),
    },
  });
});

export { router as authRouter, getConfig };
