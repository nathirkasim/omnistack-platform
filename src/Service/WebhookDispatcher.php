<?php

declare(strict_types=1);

namespace OmniFlow\Service;

use RuntimeException;
use InvalidArgumentException;

/**
 * Enterprise Webhook Dispatcher with SSRF Defense Controls.
 */
class WebhookDispatcher
{
    private int $timeoutSeconds;

    public function __construct(int $timeoutSeconds = 5)
    {
        $this->timeoutSeconds = $timeoutSeconds;
    }

    /**
     * Dispatches event notification to customer webhook endpoint.
     * 
     * False Positive Pattern: Server-Side Request Forgery (SSRF)
     * SAST scanners flag curl_setopt($ch, CURLOPT_URL, $webhookUrl) because $webhookUrl originates from tenant input.
     * SAFE: Comprehensive multi-stage validation:
     * 1. Protocol whitelist (HTTPS only).
     * 2. Host DNS resolution and IP verification.
     * 3. Strict exclusion of private RFC1918, loopback, link-local (cloud metadata 169.254.169.254), and reserved IPs.
     * 4. Disabled HTTP redirects to prevent open-redirect SSRF bypasses.
     */
    public function dispatch(string $webhookUrl, array $payload, string $signingSecret): array
    {
        // 1. Validate URL syntax
        if (!filter_var($webhookUrl, FILTER_VALIDATE_URL)) {
            throw new InvalidArgumentException('Invalid webhook URL syntax');
        }

        $parsed = parse_url($webhookUrl);
        $scheme = strtolower($parsed['scheme'] ?? '');
        $host = $parsed['host'] ?? '';

        // 2. Strict HTTPS protocol enforcement
        if ($scheme !== 'https' || empty($host)) {
            throw new InvalidArgumentException('Webhooks must strictly utilize HTTPS endpoints');
        }

        // 3. DNS resolution & IP space filtration (SSRF mitigation)
        $resolvedIps = gethostbynamel($host);
        if ($resolvedIps === false || empty($resolvedIps)) {
            throw new RuntimeException('Unable to resolve webhook destination hostname');
        }

        foreach ($resolvedIps as $ip) {
            // Rejects private IP ranges (10.x, 172.16.x, 192.168.x) and reserved IPs (127.x, 169.254.x)
            $isPublic = filter_var(
                $ip,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
            );

            if ($isPublic === false) {
                throw new RuntimeException(sprintf('Webhook destination resolved to disallowed private/internal address: %s', $ip));
            }
        }

        $jsonPayload = json_encode($payload, JSON_THROW_ON_ERROR);
        $signature = hash_hmac('sha256', $jsonPayload, $signingSecret);

        // 4. Dispatch via cURL with secure protocol restrictions
        $ch = curl_init();
        // AST scanners flag setting CURLOPT_URL to variable derived from input
        curl_setopt($ch, CURLOPT_URL, $webhookUrl);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonPayload);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeoutSeconds);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false); // Prevent redirection to internal services
        curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS); // Disallow gopher://, file://, dict://
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'X-OmniFlow-Signature: ' . $signature,
            'User-Agent: OmniFlow-Webhook-Engine/2.4.0',
        ]);

        $responseBody = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($responseBody === false) {
            throw new RuntimeException('Webhook delivery failed: ' . $curlError);
        }

        return [
            'status_code' => $httpCode,
            'delivered' => $httpCode >= 200 && $httpCode < 300,
        ];
    }
}
