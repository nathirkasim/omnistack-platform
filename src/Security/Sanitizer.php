<?php

declare(strict_types=1);

namespace OmniFlow\Security;

use InvalidArgumentException;

/**
 * Enterprise Input Sanitization & Security Normalizer.
 */
class Sanitizer
{
    /**
     * Strict integer coercion for ID parameters.
     * Guaranteed mitigation against SQL injection when used in numeric clauses.
     */
    public static function toInteger(mixed $input, int $default = 0): int
    {
        if (is_numeric($input)) {
            return (int)$input;
        }
        return $default;
    }

    /**
     * Safe HTML Context Escaping.
     */
    public static function escapeHtml(?string $input): string
    {
        if ($input === null) {
            return '';
        }
        return htmlspecialchars($input, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * Safe CLI argument escaping for asynchronous task dispatch.
     * Prevents command injection even when command string interpolation is used.
     */
    public static function escapeShellArgument(string $arg): string
    {
        return escapeshellarg(trim($arg));
    }

    /**
     * Whitelist validator for sorting and ordering clauses.
     */
    public static function validateWhitelist(string $value, array $allowed, string $fallback): string
    {
        return in_array($value, $allowed, true) ? $value : $fallback;
    }

    /**
     * Enforces relative path navigation to prevent Open Redirect vulnerabilities.
     */
    public static function sanitizeRedirectUrl(?string $url, string $default = '/dashboard'): string
    {
        if (empty($url)) {
            return $default;
        }

        // Strip carriage returns and line feeds to prevent HTTP response splitting
        $cleanUrl = str_replace(["\r", "\n"], '', $url);

        // Ensure path starts with a single slash and not double slashes (protocol-relative URL)
        if (str_starts_with($cleanUrl, '/') && !str_starts_with($cleanUrl, '//') && !str_starts_with($cleanUrl, '/\\')) {
            return $cleanUrl;
        }

        return $default;
    }
}
