<?php
// Router for PHP built-in server
// Forward all requests to index.php
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// Serve static files if they exist
$staticFile = __DIR__ . $uri;
if (is_file($staticFile)) {
    return false;
}

// Forward everything else to index.php
require __DIR__ . '/index.php';
