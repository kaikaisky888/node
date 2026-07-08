<?php
declare(strict_types=1);

namespace AuthApp\Auth;

class SignatureVerifier
{
    /**
     * Verify an ECDSA P-256 signature.
     *
     * @param string $pubKeyHex  Hex-encoded public key (DER/SPKI or raw)
     * @param string $message    The signed message
     * @param string $signature  Base64url-encoded signature (DER format)
     */
    public static function verify(string $pubKeyHex, string $message, string $signature): bool
    {
        $config = require __DIR__ . '/../Config/config.php';

        // Convert hex public key to PEM
        $pem = self::hexToPem($pubKeyHex);
        if ($pem === null) {
            return false;
        }

        // Get public key resource
        $pubKey = openssl_pkey_get_public($pem);
        if ($pubKey === false) {
            return false;
        }

        // Decode base64url signature
        $sigBin = self::base64UrlDecode($signature);
        if ($sigBin === false) {
            return false;
        }

        // Verify with OpenSSL
        $result = openssl_verify(
            $message,
            $sigBin,
            $pubKey,
            OPENSSL_ALGO_SHA256
        );

        return $result === 1;
    }

    /**
     * Verify a signed request payload.
     * Expected payload format: JSON with fields:
     *   - pub_key: hex public key
     *   - timestamp: millisecond timestamp
     *   - nonce: random nonce
     *   - fingerprint: device fingerprint
     *   - signature: base64url ECDSA signature over "timestamp.nonce.fingerprint"
     */
    public static function verifyRequest(array $payload): array
    {
        $required = ['pub_key', 'timestamp', 'nonce', 'fingerprint', 'signature'];
        foreach ($required as $field) {
            if (empty($payload[$field])) {
                return ['valid' => false, 'error' => "Missing field: {$field}"];
            }
        }

        // Check timestamp freshness (5 minute window)
        $ts = (int)$payload['timestamp'];
        $now = (int)(microtime(true) * 1000);
        if (abs($now - $ts) > 300000) {
            return ['valid' => false, 'error' => 'Timestamp expired (>5min drift)'];
        }

        // Reconstruct signed message
        $signedMessage = $payload['timestamp'] . '.' . $payload['nonce'] . '.' . $payload['fingerprint'];

        // Verify signature
        $valid = self::verify($payload['pub_key'], $signedMessage, $payload['signature']);
        if (!$valid) {
            return ['valid' => false, 'error' => 'Invalid ECC signature'];
        }

        return ['valid' => true, 'pub_key' => $payload['pub_key'], 'fingerprint' => $payload['fingerprint']];
    }

    /**
     * Convert hex-encoded public key to PEM format.
     * Supports both raw hex and SPKI/DER hex.
     */
    private static function hexToPem(string $hex): ?string
    {
        $bin = hex2bin($hex);
        if ($bin === false) return null;

        // Check if it's already a valid DER/SPKI key
        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($bin), 64, "\n")
            . "-----END PUBLIC KEY-----\n";

        // Test if it's valid
        $key = openssl_pkey_get_public($pem);
        if ($key !== false) {
            return $pem;
        }

        // Try as raw uncompressed point (04 + x + y, 65 bytes for P-256)
        if (strlen($bin) === 65 && $bin[0] === "\x04") {
            // Wrap in SPKI header for P-256
            $spkiHeader = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200');
            $spki = $spkiHeader . $bin;
            $pem = "-----BEGIN PUBLIC KEY-----\n"
                . chunk_split(base64_encode($spki), 64, "\n")
                . "-----END PUBLIC KEY-----\n";

            $key = openssl_pkey_get_public($pem);
            if ($key !== false) {
                return $pem;
            }
        }

        return null;
    }

    private static function base64UrlDecode(string $data): string|false
    {
        $padded = str_pad(strtr($data, '-_', '+/'), (int)(ceil(strlen($data) / 4) * 4), '=');
        return base64_decode($padded, true);
    }
}
