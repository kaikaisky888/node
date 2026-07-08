<?php
declare(strict_types=1);

return [
    'redis' => [
        'host' => '127.0.0.1',
        'port' => 6379,
        'db'   => 0,
        'timeout' => 2.0,
    ],

    'ecc' => [
        'curve'       => 'prime256v1',  // P-256 / secp256r1
        'digest'      => 'sha256',
    ],

    'token' => [
        'once_ttl'      => 300,   // 5 minutes
        'random_bytes'  => 32,
    ],

    'session' => [
        'ttl'            => 86400,  // 24 hours
        'cookie_name'    => 'auth_sid',
        'cookie_path'    => '/',
        'cookie_secure'  => true,
        'cookie_httponly' => true,
        'cookie_samesite' => 'Strict',
    ],

    'rate_limit' => [
        'window'   => 60,    // 60 seconds
        'max_req'  => 30,    // 30 requests per window
    ],

    'fingerprint' => [
        'strict_mode'  => true,   // true = exact match, false = similarity
        'similarity_threshold' => 0.85,
    ],
];
