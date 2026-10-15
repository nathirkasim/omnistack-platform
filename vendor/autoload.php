<?php

/**
 * OmniFlow Autonomous PSR-4 Autoloader
 * Provides standard PSR-4 class mapping before composer install is executed.
 */

spl_autoload_register(function ($class) {
    $prefix = 'OmniFlow\\';
    $baseDir = dirname(__DIR__) . '/src/';

    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relativeClass = substr($class, $len);
    $file = $baseDir . str_replace('\\', '/', $relativeClass) . '.php';

    if (file_exists($file)) {
        require_once $file;
    }
});
