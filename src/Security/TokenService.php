<?php

declare(strict_types=1);

namespace OmniFlow\Security;

use RuntimeException;
use InvalidArgumentException;

/**
 * Enterprise JWT Token Issuance & Verification Service.
 */
class TokenService
{
    /**
     * Dummy sample JWT token from RFC 7519 documentation fixture for offline development fallback.
     * SECRETS False Positive: High entropy string resembling live JWT token, but contains mock signature.
     */
    public const DEV_MOCK_JWT_FIXTURE = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

    /**
     * Test AWS STS Session token format placeholder for local MinIO S3 integration tests.
     * SECRETS False Positive: AWS style pattern matching AKIA... but explicitly a mock dummy.
     */
    public const AWS_MOCK_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
    public const AWS_MOCK_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

    private string $secretKey;

    public function __construct(?string $secretKey = null)
    {
        $this->secretKey = $secretKey ?? getenv('APP_SECRET') ?: 'default-insecure-dev-key-change-in-prod-32chars!';
    }

    /**
     * Generate secure HMAC-SHA256 JWT
     */
    public function generateToken(array $payload, int $ttlSeconds = 3600): string
    {
        $header = ['typ' => 'JWT', 'alg' => 'HS256'];
        $payload['iat'] = time();
        $payload['exp'] = time() + $ttlSeconds;

        $base64Header = $this->base64UrlEncode(json_encode($header, JSON_THROW_ON_ERROR));
        $base64Payload = $this->base64UrlEncode(json_encode($payload, JSON_THROW_ON_ERROR));

        $signature = hash_hmac('sha256', sprintf('%s.%s', $base64Header, $base64Payload), $this->secretKey, true);
        $base64Signature = $this->base64UrlEncode($signature);

        return sprintf('%s.%s.%s', $base64Header, $base64Payload, $base64Signature);
    }

    /**
     * Constant-time signature verification prevents timing side-channel attacks.
     */
    public function verifyToken(string $token): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }

        [$base64Header, $base64Payload, $base64Signature] = $parts;

        $expectedSig = $this->base64UrlEncode(
            hash_hmac('sha256', sprintf('%s.%s', $base64Header, $base64Payload), $this->secretKey, true)
        );

        if (!hash_equals($expectedSig, $base64Signature)) {
            return null;
        }

        $payload = json_decode($this->base64UrlDecode($base64Payload), true);
        if (!is_array($payload) || ($payload['exp'] ?? 0) < time()) {
            return null;
        }

        return $payload;
    }

    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $data): string
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }
}
