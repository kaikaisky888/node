/**
 * In-memory store with TTL support (Redis replacement)
 * Provides: get/set/del with automatic expiration, atomic operations
 */

class MemoryStore {
  constructor() {
    /** @type {Map<string, {value: any, expiresAt: number|null}>} */
    this.data = new Map();
    /** @type {Map<string, Set<string>>} */
    this.sets = new Map();
    /** @type {Map<string, Map<string, string>>} */
    this.hashes = new Map();
  }

  // === String operations ===

  get(key) {
    const entry = this.data.get(key);
    if (!entry) return null;
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      this.data.delete(key);
      return null;
    }
    return entry.value;
  }

  set(key, value, ttlMs = null) {
    this.data.set(key, {
      value,
      expiresAt: ttlMs ? Date.now() + ttlMs : null,
    });
    return true;
  }

  del(key) {
    return this.data.delete(key);
  }

  exists(key) {
    const entry = this.data.get(key);
    if (!entry) return false;
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      this.data.delete(key);
      return false;
    }
    return true;
  }

  ttl(key) {
    const entry = this.data.get(key);
    if (!entry) return -2;
    if (!entry.expiresAt) return -1;
    const remaining = Math.ceil((entry.expiresAt - Date.now()) / 1000);
    return remaining > 0 ? remaining : -2;
  }

  /**
   * Atomic GET + DEL (use-and-destroy pattern for one-time tokens)
   */
  getAndDel(key) {
    const entry = this.data.get(key);
    if (!entry) return null;
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      this.data.delete(key);
      return null;
    }
    this.data.delete(key);
    return entry.value;
  }

  // === Set operations ===

  sAdd(setKey, ...members) {
    if (!this.sets.has(setKey)) {
      this.sets.set(setKey, new Set());
    }
    const s = this.sets.get(setKey);
    let added = 0;
    for (const m of members) {
      if (!s.has(m)) {
        s.add(m);
        added++;
      }
    }
    return added;
  }

  sRem(setKey, ...members) {
    const s = this.sets.get(setKey);
    if (!s) return 0;
    let removed = 0;
    for (const m of members) {
      if (s.delete(m)) removed++;
    }
    return removed;
  }

  sIsMember(setKey, member) {
    const s = this.sets.get(setKey);
    return s ? s.has(member) : false;
  }

  sMembers(setKey) {
    const s = this.sets.get(setKey);
    return s ? [...s] : [];
  }

  sCard(setKey) {
    const s = this.sets.get(setKey);
    return s ? s.size : 0;
  }

  // === Hash operations ===

  hSet(hashKey, field, value) {
    if (!this.hashes.has(hashKey)) {
      this.hashes.set(hashKey, new Map());
    }
    this.hashes.get(hashKey).set(field, String(value));
    return true;
  }

  hGet(hashKey, field) {
    const h = this.hashes.get(hashKey);
    return h ? (h.get(field) ?? null) : null;
  }

  hGetAll(hashKey) {
    const h = this.hashes.get(hashKey);
    if (!h) return {};
    const result = {};
    for (const [k, v] of h) {
      result[k] = v;
    }
    return result;
  }

  hDel(hashKey, field) {
    const h = this.hashes.get(hashKey);
    return h ? h.delete(field) : false;
  }

  // === Utility ===

  keys(pattern = '*') {
    const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
    const result = [];
    for (const [key, entry] of this.data) {
      if (entry.expiresAt && Date.now() > entry.expiresAt) {
        this.data.delete(key);
        continue;
      }
      if (regex.test(key)) result.push(key);
    }
    return result;
  }

  /**
   * Count keys matching a prefix pattern
   */
  countKeys(prefix) {
    let count = 0;
    for (const [key, entry] of this.data) {
      if (entry.expiresAt && Date.now() > entry.expiresAt) {
        this.data.delete(key);
        continue;
      }
      if (key.startsWith(prefix)) count++;
    }
    return count;
  }

  /**
   * Get total key count across all data structures
   */
  totalKeys() {
    let count = this.data.size;
    for (const [, entry] of this.data) {
      if (entry.expiresAt && Date.now() > entry.expiresAt) count--;
    }
    return count;
  }

  /**
   * Cleanup expired entries
   */
  cleanup() {
    const now = Date.now();
    for (const [key, entry] of this.data) {
      if (entry.expiresAt && now > entry.expiresAt) {
        this.data.delete(key);
      }
    }
  }

  /**
   * Flush all data
   */
  flush() {
    this.data.clear();
    this.sets.clear();
    this.hashes.clear();
  }
}

// Singleton
export const store = new MemoryStore();

// Periodic cleanup every 60s
setInterval(() => store.cleanup(), 60_000);
