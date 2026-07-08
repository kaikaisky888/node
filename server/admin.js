/**
 * Admin API routes
 * - IP blacklist/whitelist management
 * - System config management
 * - Session management
 * - System diagnostics
 */

import { Router } from 'express';
import { store } from './store.js';

const router = Router();

// === IP Blacklist ===

router.get('/ip/black', (_req, res) => {
  res.json({
    success: true,
    data: store.sMembers('auth:ip:black'),
  });
});

router.post('/ip/black', (req, res) => {
  const { ip } = req.body;
  if (!ip) {
    return res.status(400).json({ success: false, message: 'IP is required' });
  }
  store.sAdd('auth:ip:black', ip);
  res.json({ success: true, message: 'Added to blacklist' });
});

router.delete('/ip/black', (req, res) => {
  const { ip } = req.body;
  if (!ip) {
    return res.status(400).json({ success: false, message: 'IP is required' });
  }
  store.sRem('auth:ip:black', ip);
  res.json({ success: true, message: 'Removed from blacklist' });
});

// === IP Whitelist ===

router.get('/ip/white', (_req, res) => {
  res.json({
    success: true,
    data: store.sMembers('auth:ip:white'),
  });
});

router.post('/ip/white', (req, res) => {
  const { ip } = req.body;
  if (!ip) {
    return res.status(400).json({ success: false, message: 'IP is required' });
  }
  store.sAdd('auth:ip:white', ip);
  res.json({ success: true, message: 'Added to whitelist' });
});

router.delete('/ip/white', (req, res) => {
  const { ip } = req.body;
  if (!ip) {
    return res.status(400).json({ success: false, message: 'IP is required' });
  }
  store.sRem('auth:ip:white', ip);
  res.json({ success: true, message: 'Removed from whitelist' });
});

// === System Config ===

router.get('/config', (_req, res) => {
  res.json({
    success: true,
    data: store.hGetAll('auth:config'),
  });
});

router.put('/config', (req, res) => {
  const { field, value } = req.body;
  if (!field || value === undefined) {
    return res.status(400).json({
      success: false,
      message: 'field and value are required',
    });
  }
  store.hSet('auth:config', field, value);
  res.json({ success: true, message: 'Config updated' });
});

// === Session Management ===

router.get('/sessions', (_req, res) => {
  const sessionKeys = store.keys('session:*').filter(
    (k) => !k.startsWith('session_pub:')
  );
  const sessions = sessionKeys.map((key) => {
    const raw = store.get(key);
    if (!raw) return null;
    const session = JSON.parse(raw);
    const ttl = store.ttl(key);
    return { ...session, _ttl: ttl };
  }).filter(Boolean);

  res.json({ success: true, data: sessions });
});

router.delete('/sessions', (req, res) => {
  const { session_id } = req.body;
  if (!session_id) {
    return res.status(400).json({ success: false, message: 'session_id required' });
  }
  store.del(`session:${session_id}`);
  store.del(`session_pub:${session_id}`);
  res.json({ success: true, message: 'Session destroyed' });
});

// === System Diagnostics ===

router.get('/diagnostics', (_req, res) => {
  const onceTokenCount = store.countKeys('once_token:');
  const sessionKeys = store.keys('session:*').filter(
    (k) => !k.startsWith('session_pub:')
  );
  const blacklistCount = store.sCard('auth:ip:black');
  const whitelistCount = store.sCard('auth:ip:white');

  res.json({
    success: true,
    data: {
      store_connected: true,
      store_type: 'memory',
      total_keys: store.totalKeys(),
      once_tokens: onceTokenCount,
      sessions: sessionKeys.length,
      blacklist_count: blacklistCount,
      whitelist_count: whitelistCount,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
    },
  });
});

export { router as adminRouter };
