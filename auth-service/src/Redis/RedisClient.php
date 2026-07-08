<?php
declare(strict_types=1);

namespace AuthApp\Redis;

class RedisClient
{
    private static ?\Redis $instance = null;

    public static function getInstance(): \Redis
    {
        if (self::$instance === null) {
            $config = require __DIR__ . '/../Config/config.php';
            $r = new \Redis();
            $r->connect(
                $config['redis']['host'],
                $config['redis']['port'],
                $config['redis']['timeout']
            );
            $r->select($config['redis']['db']);
            self::$instance = $r;
        }
        return self::$instance;
    }

    // ─── Once Token ───────────────────────────────────────────
    public static function storeOnceToken(string $token, array $payload, int $ttl): bool
    {
        $redis = self::getInstance();
        $key = 'once_token:' . $token;
        return $redis->set($key, json_encode($payload), $ttl);
    }

    /** Atomic GET + DEL (use-and-destroy) */
    public static function consumeOnceToken(string $token): ?array
    {
        $redis = self::getInstance();
        $key = 'once_token:' . $token;

        // Lua script: atomic get-and-delete
        $script = <<<'LUA'
            local val = redis.call('GET', KEYS[1])
            if val then
                redis.call('DEL', KEYS[1])
                return val
            end
            return nil
LUA;
        $result = $redis->eval($script, [$key], 1);
        if ($result === false || $result === null) {
            return null;
        }
        return json_decode((string)$result, true);
    }

    // ─── Session ──────────────────────────────────────────────
    public static function storeSession(string $sessionId, array $data, int $ttl): bool
    {
        $redis = self::getInstance();
        $key = 'session:' . $sessionId;
        return $redis->set($key, json_encode($data), $ttl);
    }

    public static function getSession(string $sessionId): ?array
    {
        $redis = self::getInstance();
        $val = $redis->get('session:' . $sessionId);
        if ($val === false) return null;
        return json_decode((string)$val, true);
    }

    public static function destroySession(string $sessionId): bool
    {
        $redis = self::getInstance();
        return (bool)$redis->del('session:' . $sessionId);
    }

    // ─── Public Key Binding ───────────────────────────────────
    public static function storeSessionPub(string $sessionId, string $pubKeyHex, int $ttl): bool
    {
        $redis = self::getInstance();
        return $redis->set('session_pub:' . $sessionId, $pubKeyHex, $ttl);
    }

    public static function getSessionPub(string $sessionId): ?string
    {
        $redis = self::getInstance();
        $val = $redis->get('session_pub:' . $sessionId);
        return $val === false ? null : (string)$val;
    }

    // ─── Rate Limiting (fixed window) ─────────────────────────
    public static function checkRateLimit(string $ip, int $window, int $maxReq): array
    {
        $redis = self::getInstance();
        $key = 'auth:ip:limit:' . $ip;
        $current = (int)$redis->get($key);

        if ($current >= $maxReq) {
            $ttl = $redis->ttl($key);
            return ['allowed' => false, 'remaining' => 0, 'retry_after' => max($ttl, 1)];
        }

        $pipe = $redis->multi(\Redis::PIPELINE);
        $pipe->incr($key);
        if ($current === 0) {
            $pipe->expire($key, $window);
        }
        $pipe->exec();

        return ['allowed' => true, 'remaining' => $maxReq - $current - 1, 'retry_after' => 0];
    }

    // ─── IP Blacklist / Whitelist ─────────────────────────────
    public static function isBlacklisted(string $ip): bool
    {
        $redis = self::getInstance();
        return (bool)$redis->sIsMember('auth:ip:black', $ip);
    }

    public static function isWhitelisted(string $ip): bool
    {
        $redis = self::getInstance();
        return (bool)$redis->sIsMember('auth:ip:white', $ip);
    }

    public static function addToBlacklist(string $ip): bool
    {
        $redis = self::getInstance();
        return (bool)$redis->sAdd('auth:ip:black', $ip);
    }

    public static function addToWhitelist(string $ip): bool
    {
        $redis = self::getInstance();
        return (bool)$redis->sAdd('auth:ip:white', $ip);
    }

    public static function removeFromBlacklist(string $ip): bool
    {
        $redis = self::getInstance();
        return (bool)$redis->sRem('auth:ip:black', $ip);
    }

    public static function removeFromWhitelist(string $ip): bool
    {
        $redis = self::getInstance();
        return (bool)$redis->sRem('auth:ip:white', $ip);
    }

    public static function getBlacklist(): array
    {
        $redis = self::getInstance();
        return $redis->sMembers('auth:ip:black') ?: [];
    }

    public static function getWhitelist(): array
    {
        $redis = self::getInstance();
        return $redis->sMembers('auth:ip:white') ?: [];
    }

    // ─── System Config (Hash) ─────────────────────────────────
    public static function getConfig(string $field): mixed
    {
        $redis = self::getInstance();
        return $redis->hGet('auth:config', $field);
    }

    public static function setConfig(string $field, mixed $value): bool
    {
        $redis = self::getInstance();
        return (bool)$redis->hSet('auth:config', $field, is_string($value) ? $value : json_encode($value));
    }

    public static function getAllConfig(): array
    {
        $redis = self::getInstance();
        return $redis->hGetAll('auth:config') ?: [];
    }

    // ─── Diagnostics ──────────────────────────────────────────
    public static function getAllSessions(): array
    {
        $redis = self::getInstance();
        $keys = $redis->keys('session:*');
        $sessions = [];
        foreach ($keys as $key) {
            if (str_starts_with($key, 'session_pub:')) continue;
            $val = $redis->get($key);
            if ($val) {
                $data = json_decode((string)$val, true);
                $data['_id'] = str_replace('session:', '', $key);
                $data['_ttl'] = $redis->ttl($key);
                $sessions[] = $data;
            }
        }
        return $sessions;
    }

    public static function getDiagnostics(): array
    {
        $redis = self::getInstance();
        $info = $redis->info();
        return [
            'redis_connected' => $redis->ping() === '+OK' || $redis->ping(),
            'redis_version' => $info['redis_version'] ?? 'unknown',
            'used_memory' => $info['used_memory_human'] ?? 'unknown',
            'total_keys' => count($redis->keys('*')),
            'once_tokens' => count($redis->keys('once_token:*')),
            'sessions' => count($redis->keys('session:*')) - count($redis->keys('session_pub:*')),
            'blacklist_count' => $redis->sCard('auth:ip:black'),
            'whitelist_count' => $redis->sCard('auth:ip:white'),
        ];
    }
}
