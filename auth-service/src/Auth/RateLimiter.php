<?php
declare(strict_types=1);

namespace AuthApp\Auth;

use AuthApp\Redis\RedisClient;

class RateLimiter
{
    /**
     * Check if an IP is rate-limited.
     */
    public static function check(string $ip): array
    {
        $config = require __DIR__ . '/../Config/config.php';

        // Whitelisted IPs bypass rate limiting
        if (RedisClient::isWhitelisted($ip)) {
            return ['allowed' => true, 'remaining' => -1, 'retry_after' => 0];
        }

        return RedisClient::checkRateLimit(
            $ip,
            $config['rate_limit']['window'],
            $config['rate_limit']['max_req']
        );
    }

    /**
     * Check if IP is blacklisted.
     */
    public static function isBlocked(string $ip): bool
    {
        return RedisClient::isBlacklisted($ip);
    }
}
