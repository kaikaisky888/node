/**
 * ABC Auth System - Main Entry Point
 * 
 * Architecture:
 * - Single Node.js server handling all routes
 * - /c/*        → C site (auth entry, fingerprint + ECC signing)
 * - /b/*        → B site (auth transit, rate limiting + signature verification)
 * - /a/*        → A site (business page, session-gated)
 * - /admin/*    → Admin panel (management dashboard)
 * - /api/auth/* → Auth API endpoints
 * - /admin/api/* → Admin API endpoints (proxied)
 */

import express from 'express';
import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import { authRouter } from './auth.js';
import { adminRouter } from './admin.js';
import { store } from './store.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.DEPLOY_RUN_PORT || 5000;

// === Middleware ===
app.use(express.json());
app.use(cookieParser());

// Trust proxy for correct IP detection
app.set('trust proxy', true);

// === Rate Limiting Middleware (for /b/ and /c/ routes) ===
function rateLimitMiddleware(req, res, next) {
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  
  // Check whitelist first
  if (store.sIsMember('auth:ip:white', ip)) {
    return next();
  }
  
  // Check blacklist
  if (store.sIsMember('auth:ip:black', ip)) {
    return res.status(403).json({
      success: false,
      error: 'IP blocked',
      message: 'Your IP has been blacklisted',
    });
  }

  // Rate limiting
  const rateLimitKey = `auth:ip:limit:${ip}`;
  const maxRequests = parseInt(store.hGet('auth:config', 'rate_limit_max') || '30', 10);
  const windowSeconds = parseInt(store.hGet('auth:config', 'rate_limit_window') || '60', 10);

  let count = parseInt(store.get(rateLimitKey) || '0', 10);
  
  if (count >= maxRequests) {
    return res.status(429).json({
      success: false,
      error: 'Rate limit exceeded',
      message: `Too many requests. Try again in ${windowSeconds} seconds.`,
    });
  }

  if (count === 0) {
    store.set(rateLimitKey, '1', windowSeconds * 1000);
  } else {
    store.set(rateLimitKey, String(count + 1), store.ttl(rateLimitKey) * 1000);
  }

  next();
}

// === Session Validation Middleware (for /a/ routes) ===
function sessionMiddleware(req, res, next) {
  const sessionId = req.cookies?.auth_session || req.headers.authorization?.replace('Bearer ', '');

  if (!sessionId) {
    // Return 403 for browser requests (will show error page)
    if (req.headers.accept?.includes('text/html')) {
      return res.status(403).sendFile(path.join(__dirname, '../frontend/errors/403.html'));
    }
    return res.status(403).json({
      success: false,
      error: 'No session',
      message: 'Authentication required',
    });
  }

  const sessionRaw = store.get(`session:${sessionId}`);
  if (!sessionRaw) {
    if (req.headers.accept?.includes('text/html')) {
      return res.status(403).sendFile(path.join(__dirname, '../frontend/errors/403.html'));
    }
    return res.status(401).json({
      success: false,
      error: 'Session expired',
      message: 'Session has expired or was destroyed',
    });
  }

  const session = JSON.parse(sessionRaw);
  session.last_active = Math.floor(Date.now() / 1000);
  const ttl = store.ttl(`session:${sessionId}`);
  store.set(`session:${sessionId}`, JSON.stringify(session), ttl * 1000);

  req.session = session;
  next();
}

// === Routes ===

// Health check
app.get('/health', (_req, res) => {
  res.json({
    success: true,
    data: {
      status: 'ok',
      store: 'memory',
      time: new Date().toISOString(),
    },
  });
});

// Auth API (accessible via /b/api/auth/* or directly /api/auth/*)
app.use('/api/auth', authRouter);
app.use('/b/api/auth', rateLimitMiddleware, authRouter);

// Admin API
app.use('/api/admin', adminRouter);

// C site - Auth entry point (public, rate limited)
app.use('/c', rateLimitMiddleware, express.static(path.join(__dirname, '../frontend/site-c')));

// B site - Auth transit (rate limited)
app.use('/b', rateLimitMiddleware, express.static(path.join(__dirname, '../frontend/site-b')));

// A site - Business page (session required)
app.use('/a', sessionMiddleware, express.static(path.join(__dirname, '../frontend/site-a')));

// Admin panel
app.use('/admin', express.static(path.join(__dirname, '../frontend/admin')));

// Public downloads
app.use(express.static(path.join(__dirname, '../public')));

// Root redirect to C site
app.get('/', (_req, res) => {
  res.redirect('/c/');
});

// 404 handler
app.use((_req, res) => {
  res.status(404).json({
    success: false,
    error: 'Not found',
    message: 'The requested resource was not found',
  });
});

// Error handler
app.use((err, _req, res, _next) => {
  console.error('Server error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    message: err.message,
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`ABC Auth System running on port ${PORT}`);
  console.log(`  C site (auth entry):  http://localhost:${PORT}/c/`);
  console.log(`  B site (transit):     http://localhost:${PORT}/b/`);
  console.log(`  A site (business):    http://localhost:${PORT}/a/`);
  console.log(`  Admin panel:          http://localhost:${PORT}/admin/`);
  console.log(`  Health check:         http://localhost:${PORT}/health`);
});

export default app;
