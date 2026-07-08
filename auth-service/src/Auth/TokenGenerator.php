<?php
declare(strict_types=1);

namespace AuthApp\Auth;

use AuthApp\Redis\RedisClient;

class TokenGenerator
{
    /**
     * Generate a one-time token.
     * Format: base64url(32-byte CSPRNG) + "." + millisecond_timestamp + "." + base64url(sha256(pubKey)[:8])
     */
    public static function generate(string $pubKeyHex, string $fingerprint): array
    {
        $config = require __DIR__ . '/../Config/config.php';

        // CSPRNG 32 bytes
        $randomBytes = random_bytes($config['token']['random_bytes']);
        $randomPart = self::base64UrlEncode($randomBytes);

        // Millisecond timestamp
        $timestamp = (string)(int)(microtime(true) * 1000);

        // Public key hash (first 8 bytes of SHA-256)
        $pubKeyHash = self::base64UrlEncode(substr(hash('sha256', $pubKeyHex, true), 0, 8));

        // Assemble token
        $token = $randomPart . '.' . $timestamp . '.' . $pubKeyHash;

        // Store in Redis with TTL
        $payload = [
            'pub_key'     => $pubKeyHex,
            'fingerprint' => $fingerprint,
            'created_at'  => $timestamp,
            'used'        => false,
        ];

        $stored = RedisClient::storeOnceToken($token, $payload, $config['token']['once_ttl']);

        if (!$stored) {
            throw new \RuntimeException('Failed to store token in Redis');
        }

        return [
            'token'     => $token,
            'expires_in' => $config['token']['once_ttl'],
            'expires_at' => (int)$timestamp + $config['token']['once_ttl'] * 1000,
        ];
    }

    /**
     * Consume (verify + destroy) a one-time token.
     * Returns the payload if valid, null if not found or already consumed.
     */
    public static function consume(string $token): ?array
    {
        return RedisClient::consumeOnceToken($token);
    }

    /**
     * Validate token format without consuming it.
     */
    public static function validateFormat(string $token): bool
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) return false;

        // Part 1: base64url encoded 32 bytes
        $decoded = self::base64UrlDecode($parts[0]);
        if ($decoded === false || strlen($decoded) !== 32) return false;

        // Part 2: millisecond timestamp (13 digits)
        if (!preg_match('/^\d{13}$/', $parts[1])) return false;

        // Part 3: base64url encoded 8 bytes
        $decoded = self::base64UrlDecode($parts[2]);
        if ($decoded === false || strlen($decoded) !== 8) return false;

        return true;
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $data): string|false
    {
        $padded = str_pad(strtr($data, '-_', '+/'), (int)(ceil(strlen($data) / 4) * 4), '=');
        return base64_decode($padded, true);
    }
}
