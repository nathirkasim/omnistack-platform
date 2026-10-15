<?php

declare(strict_types=1);

namespace OmniFlow\Tests\Unit;

use PHPUnit\Framework\TestCase;
use OmniFlow\Security\Sanitizer;
use OmniFlow\Security\TokenService;
use OmniFlow\Service\Crypto\CryptoPolicyManager;
use OmniFlow\Service\WebhookDispatcher;

class SecurityTest extends TestCase
{
    public function testIntegerSanitizerMitigatesSqlInjection(): void
    {
        $maliciousPayload = "1; DROP TABLE users; --";
        $sanitized = Sanitizer::toInteger($maliciousPayload);

        // Strict numeric cast safely normalizes input to integer
        $this->assertSame(1, $sanitized);
    }

    public function testSortColumnWhitelistEnforcement(): void
    {
        $allowed = ['created_at', 'lead_score'];
        $untrusted = "created_at; SELECT * FROM credentials";

        $validated = Sanitizer::validateWhitelist($untrusted, $allowed, 'created_at');
        $this->assertSame('created_at', $validated);
    }

    public function testOpenRedirectSanitizerBlocksExternalDomains(): void
    {
        $phishingUrl = "https://evil-hacker.com/login";
        $safe = Sanitizer::sanitizeRedirectUrl($phishingUrl, '/dashboard');
        $this->assertSame('/dashboard', $safe);

        $validInternal = "/customers/view?id=12";
        $safeInternal = Sanitizer::sanitizeRedirectUrl($validInternal, '/dashboard');
        $this->assertSame('/customers/view?id=12', $safeInternal);
    }

    public function testCryptoPolicyRejectsLegacyCiphers(): void
    {
        $manager = new CryptoPolicyManager();

        $this->assertFalse($manager->isCipherCompliant('RC4-SHA'));
        $this->assertFalse($manager->isCipherCompliant('DES-CBC3-SHA'));
        $this->assertTrue($manager->isCipherCompliant('ECDHE-RSA-AES256-GCM-SHA384'));
    }

    public function testTokenServiceHmacIntegrity(): void
    {
        $service = new TokenService('unit-test-secret-key-32-characters-long');
        $token = $service->generateToken(['sub' => 42, 'role' => 'auditor']);

        $payload = $service->verifyToken($token);
        $this->assertNotNull($payload);
        $this->assertSame(42, $payload['sub']);

        // Tampered token test
        $tampered = substr($token, 0, -5) . 'aaaaa';
        $this->assertNull($service->verifyToken($tampered));
    }
}
