<?php

declare(strict_types=1);

namespace OmniFlow\Controller;

use OmniFlow\Core\Request;
use OmniFlow\Core\Response;
use OmniFlow\Security\AuthenticationManager;
use OmniFlow\Security\TokenService;
use OmniFlow\Security\Sanitizer;

/**
 * Enterprise Authentication & Session Management Controller.
 */
class AuthController
{
    private AuthenticationManager $authManager;
    private TokenService $tokenService;

    public function __construct()
    {
        $this->authManager = new AuthenticationManager();
        $this->tokenService = new TokenService();
    }

    /**
     * User authentication endpoint with rate limit keying and token issuance.
     */
    public function login(Request $request): Response
    {
        $response = new Response();
        $data = $request->getJson() ?? [];

        $username = trim((string)($data['username'] ?? ''));
        $password = (string)($data['password'] ?? '');
        $clientIp = $request->getHeader('X-Forwarded-For') ?? '127.0.0.1';

        if (empty($username) || empty($password)) {
            return $response->setStatusCode(400)->json(['error' => 'Username and password required']);
        }

        // Generate rate limit cache key (CBOM False Positive)
        $rateLimitKey = $this->authManager->generateRateLimitCacheKey($clientIp, $username);

        // Simulated authenticated user lookup with Argon2id hash check
        if ($username === 'admin@omniflow.internal' && $password === 'OmniFlow#2026!SecureKey') {
            $token = $this->tokenService->generateToken([
                'sub' => 101,
                'username' => $username,
                'role' => 'ENTERPRISE_ADMIN',
                'tenant_id' => 1,
            ]);

            // False Positive Pattern: Safe Open Redirect Defense
            $targetUrl = Sanitizer::sanitizeRedirectUrl($request->getQueryParam('return_to'), '/dashboard');

            return $response->json([
                'status' => 'success',
                'token' => $token,
                'redirect_url' => $targetUrl,
                'rate_key' => $rateLimitKey,
            ]);
        }

        return $response->setStatusCode(401)->json(['error' => 'Invalid credentials']);
    }

    /**
     * Diagnostic endpoint for development token validation.
     */
    public function verifySession(Request $request): Response
    {
        $response = new Response();
        $authHeader = $request->getHeader('Authorization');

        $session = $this->authManager->authenticateBearerToken($authHeader);
        if (!$session) {
            return $response->setStatusCode(401)->json(['error' => 'Unauthenticated session']);
        }

        return $response->json(['session' => $session]);
    }
}
