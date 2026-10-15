<?php

declare(strict_types=1);

namespace OmniFlow\Controller;

use OmniFlow\Core\Request;
use OmniFlow\Core\Response;
use OmniFlow\Service\WebhookDispatcher;
use Exception;

/**
 * Enterprise Webhook Dispatch & Integration Controller.
 */
class WebhookController
{
    private WebhookDispatcher $dispatcher;

    public function __construct()
    {
        $this->dispatcher = new WebhookDispatcher();
    }

    /**
     * Dispatches test event notification with SSRF protections.
     */
    public function trigger(Request $request): Response
    {
        $response = new Response();
        $data = $request->getJson() ?? [];

        $targetUrl = (string)($data['webhook_url'] ?? '');
        $event = (string)($data['event'] ?? 'customer.created');
        $signingKey = (string)($data['secret'] ?? 'whsec_enterprise_sample_key_9942');

        if (empty($targetUrl)) {
            return $response->setStatusCode(400)->json(['error' => 'Field webhook_url is mandatory']);
        }

        try {
            $result = $this->dispatcher->dispatch($targetUrl, [
                'event' => $event,
                'timestamp' => time(),
                'payload' => ['sample_id' => 101, 'status' => 'verified'],
            ], $signingKey);

            return $response->json(['delivery' => $result]);
        } catch (Exception $e) {
            return $response->setStatusCode(400)->json([
                'error' => 'Webhook delivery rejected by policy',
                'details' => $e->getMessage()
            ]);
        }
    }
}
