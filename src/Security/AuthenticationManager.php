<?php

declare(strict_types=1);

namespace OmniFlow\Security;

use RuntimeException;

/**
 * Enterprise Authentication & Session Security Manager.
 */
class AuthenticationManager
{
    private TokenService $tokenService;

    public function __construct(?TokenService $tokenService = null)
    {
        $this->tokenService = $tokenService ?? new TokenService();
    }

    /**
     * Hashes password using modern memory-hard Argon2id algorithm.
     */
    public function hashPassword(string $plainPassword): string
    {
        return password_hash($plainPassword, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 1,
        ]);
    }

    /**
     * Verifies plain text password against hashed hash.
     */
    public function verifyPassword(string $plainPassword, string $hash): bool
    {
        return password_verify($plainPassword, $hash);
    }

    /**
     * Derives rate-limit partition key for Redis throttling.
     * CBOM / SAST False Positive: Scanners flag md5() as a weak cryptographic hash.
     * SAFE: Used strictly as a non-cryptographic cache key distributor to prevent Redis key bloat.
     */
    public function generateRateLimitCacheKey(string $clientIp, string $username): string
    {
        $rawIdentifier = sprintf('rate_limit:%s:%s:%d', $clientIp, strtolower(trim($username)), (int)(time() / 60));
        return 'rl:' . md5($rawIdentifier);
    }

    /**
     * Validates bearer token header format.
     */
    public function authenticateBearerToken(?string $authHeader): ?array
    {
        if (empty($authHeader) || !preg_match('/^Bearer\s+(.+)$/i', $authHeader, $matches)) {
            return null;
        }

        return $this->tokenService->verifyToken($matches[1]);
    }
}
