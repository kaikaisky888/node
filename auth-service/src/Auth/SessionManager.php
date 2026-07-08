<?php
declare(strict_types=1);

namespace AuthApp\Auth;

use AuthApp\Redis\RedisClient;

class SessionManager
{
    /**
     * Create a long-lived session bound to a device fingerprint.
     */
    public static function create(string $pubKeyHex, string $fingerprint, string $ip): array
    {
        $config = require __DIR__ . '/../Config/config.php';

        // Generate session ID: CSPRNG-based
        $sessionId = bin2hex(random_bytes(32));

        $sessionData = [
            'pub_key'     => $pubKeyHex,
            'fingerprint' => $fingerprint,
            'ip'          => $ip,
            'created_at'  => time(),
            'last_active' => time(),
            'user_agent'  => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        ];

        $stored = RedisClient::storeSession($sessionId, $sessionData, $config['session']['ttl']);
        if (!$stored) {
            throw new \RuntimeException('Failed to store session');
        }

        // Bind public key to session
        RedisClient::storeSessionPub($sessionId, $pubKeyHex, $config['session']['ttl']);

        return [
            'session_id' => $sessionId,
            'expires_in' => $config['session']['ttl'],
            'expires_at' => time() + $config['session']['ttl'],
        ];
    }

    /**
     * Validate a session.
     * Checks existence, fingerprint match, and refreshes TTL.
     */
    public static function validate(string $sessionId, ?string $fingerprint = null): array
    {
        $config = require __DIR__ . '/../Config/config.php';

        $session = RedisClient::getSession($sessionId);
        if ($session === null) {
            return ['valid' => false, 'error' => 'Session not found or expired'];
        }

        // Fingerprint check
        if ($fingerprint !== null && $config['fingerprint']['strict_mode']) {
            if ($session['fingerprint'] !== $fingerprint) {
                return ['valid' => false, 'error' => 'Fingerprint mismatch'];
            }
        }

        // Refresh TTL (sliding window)
        RedisClient::storeSession($sessionId, $session, $config['session']['ttl']);

        return [
            'valid'   => true,
            'session' => $session,
        ];
    }

    /**
     * Destroy a session.
     */
    public static function destroy(string $sessionId): bool
    {
        return RedisClient::destroySession($sessionId);
    }

    /**
     * Get session cookie parameters.
     */
    public static function getCookieParams(): array
    {
        $config = require __DIR__ . '/../Config/config.php';
        return [
            'name'     => $config['session']['cookie_name'],
            'path'     => $config['session']['cookie_path'],
            'secure'   => $config['session']['cookie_secure'],
            'httponly'  => $config['session']['cookie_httponly'],
            'samesite' => $config['session']['cookie_samesite'],
            'max_age'  => $config['session']['ttl'],
        ];
    }
}
