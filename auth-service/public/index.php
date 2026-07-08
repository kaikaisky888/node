<?php
declare(strict_types=1);

// ─── Autoloader ───────────────────────────────────────────────
spl_autoload_register(function (string $class): void {
    $prefix = 'AuthApp\\';
    $baseDir = __DIR__ . '/../src/';

    if (!str_starts_with($class, $prefix)) return;

    $relative = str_replace('\\', '/', substr($class, strlen($prefix)));
    $file = $baseDir . $relative . '.php';

    if (file_exists($file)) require $file;
});

// ─── CORS & Headers ───────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');

// ─── Router ───────────────────────────────────────────────────
$method = $_SERVER['REQUEST_METHOD'];
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// Strip /api/auth prefix
$path = preg_replace('#^/api/auth#', '', $uri) ?: '/';
$path = rtrim($path, '/') ?: '/';

// Also handle admin routes
$isAdmin = str_starts_with($uri, '/api/admin');
if ($isAdmin) {
    $path = '/admin' . preg_replace('#^/api/admin#', '', $uri);
    $path = rtrim($path, '/') ?: '/admin';
}

try {
    // ─── Auth Routes ──────────────────────────────────────────
    if (!$isAdmin) {
        match ($path) {
            '/generate' => handleGenerate($method),
            '/verify'   => handleVerify($method),
            '/session'  => handleSession($method),
            '/logout'   => handleLogout($method),
            '/health'   => handleHealth(),
            default     => jsonResponse(404, ['error' => 'Not found']),
        };
    } else {
        // ─── Admin Routes ─────────────────────────────────────
        match ($path) {
            '/admin'            => handleAdminIndex($method),
            '/admin/ip/black'   => handleIpBlacklist($method),
            '/admin/ip/white'   => handleIpWhitelist($method),
            '/admin/config'     => handleConfig($method),
            '/admin/sessions'   => handleSessions($method),
            '/admin/diagnostics'=> handleDiagnostics(),
            default             => jsonResponse(404, ['error' => 'Admin route not found']),
        };
    }
} catch (\Throwable $e) {
    jsonResponse(500, ['error' => 'Internal error', 'detail' => $e->getMessage()]);
}

// ═══════════════════════════════════════════════════════════════
// Auth Handlers
// ═══════════════════════════════════════════════════════════════

function handleGenerate(string $method): void
{
    if ($method !== 'POST') {
        jsonResponse(405, ['error' => 'Method not allowed']);
    }

    $body = getJsonBody();

    // Verify ECC signature first
    $sigResult = \AuthApp\Auth\SignatureVerifier::verifyRequest($body);
    if (!$sigResult['valid']) {
        jsonResponse(403, ['error' => 'Signature verification failed', 'detail' => $sigResult['error']]);
    }

    // Rate limiting
    $ip = getClientIp();
    if (\AuthApp\Auth\RateLimiter::isBlocked($ip)) {
        jsonResponse(403, ['error' => 'IP blocked']);
    }
    $rateCheck = \AuthApp\Auth\RateLimiter::check($ip);
    if (!$rateCheck['allowed']) {
        header('Retry-After: ' . $rateCheck['retry_after']);
        jsonResponse(429, ['error' => 'Rate limit exceeded', 'retry_after' => $rateCheck['retry_after']]);
    }

    // Generate one-time token
    $result = \AuthApp\Auth\TokenGenerator::generate($sigResult['pub_key'], $sigResult['fingerprint']);

    jsonResponse(200, [
        'success' => true,
        'data'    => $result,
    ]);
}

function handleVerify(string $method): void
{
    if ($method !== 'POST') {
        jsonResponse(405, ['error' => 'Method not allowed']);
    }

    $body = getJsonBody();

    if (empty($body['token'])) {
        jsonResponse(400, ['error' => 'Missing token']);
    }

    $token = $body['token'];

    // Validate token format
    if (!\AuthApp\Auth\TokenGenerator::validateFormat($token)) {
        jsonResponse(400, ['error' => 'Invalid token format']);
    }

    // Atomic consume (use-and-destroy)
    $payload = \AuthApp\Auth\TokenGenerator::consume($token);
    if ($payload === null) {
        jsonResponse(403, ['error' => 'Token not found, expired, or already used']);
    }

    // Create long-lived session
    $ip = getClientIp();
    $session = \AuthApp\Auth\SessionManager::create(
        $payload['pub_key'],
        $payload['fingerprint'],
        $ip
    );

    // Set session cookie
    $cookieParams = \AuthApp\Auth\SessionManager::getCookieParams();
    $cookieHeader = sprintf(
        '%s=%s; Path=%s; Domain=%s; Max-Age=%d; Secure; HttpOnly; SameSite=%s',
        $cookieParams['name'],
        $session['session_id'],
        $cookieParams['path'],
        $cookieParams['domain'],
        $cookieParams['max_age'],
        $cookieParams['samesite']
    );
    header('Set-Cookie: ' . $cookieHeader);

    jsonResponse(200, [
        'success' => true,
        'data'    => [
            'session_id' => $session['session_id'],
            'expires_at' => $session['expires_at'],
        ],
    ]);
}

function handleSession(string $method): void
{
    if ($method !== 'GET') {
        jsonResponse(405, ['error' => 'Method not allowed']);
    }

    // Get session from cookie
    $cookieParams = \AuthApp\Auth\SessionManager::getCookieParams();
    $sessionId = $_COOKIE[$cookieParams['name']] ?? null;

    if ($sessionId === null) {
        // Also check Authorization header
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (str_starts_with($authHeader, 'Bearer ')) {
            $sessionId = substr($authHeader, 7);
        }
    }

    if ($sessionId === null) {
        jsonResponse(401, ['error' => 'No session']);
    }

    // Optional fingerprint from header
    $fingerprint = $_SERVER['HTTP_X_DEVICE_FINGERPRINT'] ?? null;

    $result = \AuthApp\Auth\SessionManager::validate($sessionId, $fingerprint);

    if (!$result['valid']) {
        jsonResponse(401, ['error' => $result['error']]);
    }

    jsonResponse(200, [
        'success' => true,
        'data'    => [
            'valid'       => true,
            'fingerprint' => $result['session']['fingerprint'],
            'created_at'  => $result['session']['created_at'],
            'last_active' => $result['session']['last_active'],
        ],
    ]);
}

function handleLogout(string $method): void
{
    if ($method !== 'POST') {
        jsonResponse(405, ['error' => 'Method not allowed']);
    }

    $cookieParams = \AuthApp\Auth\SessionManager::getCookieParams();
    $sessionId = $_COOKIE[$cookieParams['name']] ?? null;

    if ($sessionId === null) {
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (str_starts_with($authHeader, 'Bearer ')) {
            $sessionId = substr($authHeader, 7);
        }
    }

    if ($sessionId !== null) {
        \AuthApp\Auth\SessionManager::destroy($sessionId);
    }

    // Clear cookie
    $clearCookie = sprintf(
        '%s=; Path=%s; Domain=%s; Max-Age=0; Secure; HttpOnly; SameSite=%s',
        $cookieParams['name'],
        $cookieParams['path'],
        $cookieParams['domain'],
        $cookieParams['samesite']
    );
    header('Set-Cookie: ' . $clearCookie);

    jsonResponse(200, [
        'success' => true,
        'message' => 'Session destroyed',
    ]);
}

function handleHealth(): void
{
    try {
        $redis = \AuthApp\Redis\RedisClient::getInstance();
        $ping = $redis->ping();
        jsonResponse(200, [
            'success' => true,
            'data'    => [
                'status' => 'ok',
                'redis'  => $ping === '+OK' || $ping ? 'connected' : 'disconnected',
                'time'   => date('c'),
            ],
        ]);
    } catch (\Throwable $e) {
        jsonResponse(503, ['error' => 'Service unhealthy', 'detail' => $e->getMessage()]);
    }
}

// ═══════════════════════════════════════════════════════════════
// Admin Handlers
// ═══════════════════════════════════════════════════════════════

function handleAdminIndex(string $method): void
{
    jsonResponse(200, [
        'success' => true,
        'data'    => [
            'endpoints' => [
                'GET/POST /api/admin/ip/black'   => 'IP blacklist management',
                'GET/POST /api/admin/ip/white'   => 'IP whitelist management',
                'GET/PUT  /api/admin/config'      => 'System config management',
                'GET    /api/admin/sessions'      => 'Active sessions',
                'DELETE /api/admin/sessions/{id}' => 'Destroy session',
                'GET    /api/admin/diagnostics'   => 'System diagnostics',
            ],
        ],
    ]);
}

function handleIpBlacklist(string $method): void
{
    if ($method === 'GET') {
        jsonResponse(200, ['success' => true, 'data' => \AuthApp\Redis\RedisClient::getBlacklist()]);
    } elseif ($method === 'POST') {
        $body = getJsonBody();
        if (empty($body['ip'])) jsonResponse(400, ['error' => 'Missing ip']);
        \AuthApp\Redis\RedisClient::addToBlacklist($body['ip']);
        jsonResponse(200, ['success' => true, 'message' => 'Added to blacklist']);
    } elseif ($method === 'DELETE') {
        $body = getJsonBody();
        if (empty($body['ip'])) jsonResponse(400, ['error' => 'Missing ip']);
        \AuthApp\Redis\RedisClient::removeFromBlacklist($body['ip']);
        jsonResponse(200, ['success' => true, 'message' => 'Removed from blacklist']);
    } else {
        jsonResponse(405, ['error' => 'Method not allowed']);
    }
}

function handleIpWhitelist(string $method): void
{
    if ($method === 'GET') {
        jsonResponse(200, ['success' => true, 'data' => \AuthApp\Redis\RedisClient::getWhitelist()]);
    } elseif ($method === 'POST') {
        $body = getJsonBody();
        if (empty($body['ip'])) jsonResponse(400, ['error' => 'Missing ip']);
        \AuthApp\Redis\RedisClient::addToWhitelist($body['ip']);
        jsonResponse(200, ['success' => true, 'message' => 'Added to whitelist']);
    } elseif ($method === 'DELETE') {
        $body = getJsonBody();
        if (empty($body['ip'])) jsonResponse(400, ['error' => 'Missing ip']);
        \AuthApp\Redis\RedisClient::removeFromWhitelist($body['ip']);
        jsonResponse(200, ['success' => true, 'message' => 'Removed from whitelist']);
    } else {
        jsonResponse(405, ['error' => 'Method not allowed']);
    }
}

function handleConfig(string $method): void
{
    if ($method === 'GET') {
        jsonResponse(200, ['success' => true, 'data' => \AuthApp\Redis\RedisClient::getAllConfig()]);
    } elseif ($method === 'PUT') {
        $body = getJsonBody();
        if (empty($body['field']) || !isset($body['value'])) {
            jsonResponse(400, ['error' => 'Missing field or value']);
        }
        \AuthApp\Redis\RedisClient::setConfig($body['field'], $body['value']);
        jsonResponse(200, ['success' => true, 'message' => 'Config updated']);
    } else {
        jsonResponse(405, ['error' => 'Method not allowed']);
    }
}

function handleSessions(string $method): void
{
    if ($method === 'GET') {
        jsonResponse(200, ['success' => true, 'data' => \AuthApp\Redis\RedisClient::getAllSessions()]);
    } elseif ($method === 'DELETE') {
        $body = getJsonBody();
        if (empty($body['session_id'])) jsonResponse(400, ['error' => 'Missing session_id']);
        \AuthApp\Auth\SessionManager::destroy($body['session_id']);
        jsonResponse(200, ['success' => true, 'message' => 'Session destroyed']);
    } else {
        jsonResponse(405, ['error' => 'Method not allowed']);
    }
}

function handleDiagnostics(): void
{
    jsonResponse(200, ['success' => true, 'data' => \AuthApp\Redis\RedisClient::getDiagnostics()]);
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

function getJsonBody(): array
{
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function getClientIp(): string
{
    return $_SERVER['HTTP_X_REAL_IP']
        ?? $_SERVER['HTTP_X_FORWARDED_FOR']
        ?? $_SERVER['REMOTE_ADDR']
        ?? '0.0.0.0';
}

function jsonResponse(int $code, array $data): never
{
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
