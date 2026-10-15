<?php

declare(strict_types=1);

namespace OmniFlow\Controller;

use OmniFlow\Core\Request;
use OmniFlow\Core\Response;
use OmniFlow\Service\AI\LeadScoringEngine;
use OmniFlow\Repository\CustomerRepository;

/**
 * Enterprise Predictive AI & Customer Intelligence Controller.
 */
class AIInsightsController
{
    private LeadScoringEngine $aiEngine;
    private CustomerRepository $customerRepo;

    public function __construct()
    {
        $this->aiEngine = new LeadScoringEngine();
        $this->customerRepo = new CustomerRepository();
    }

    /**
     * Executes predictive lead scoring model inference.
     */
    public function scoreLead(Request $request): Response
    {
        $response = new Response();
        $data = $request->getJson() ?? [];

        $customerId = (int)($data['customer_id'] ?? 0);
        $features = [
            'engagement_days' => (int)($data['engagement_days'] ?? 14),
            'deal_value' => (float)($data['deal_value'] ?? 15000.0),
            'interaction_count' => (int)($data['interaction_count'] ?? 8),
            'industry_tier' => (int)($data['industry_tier'] ?? 2),
        ];

        $prediction = $this->aiEngine->predictLeadScore($features);

        if ($customerId > 0) {
            $this->customerRepo->updateLeadScore($customerId, $prediction['lead_score']);
        }

        return $response->json([
            'customer_id' => $customerId,
            'prediction' => $prediction,
        ]);
    }

    /**
     * AIBOM (AI Bill of Materials) Inspection Endpoint.
     * Exposes provenance, training metrics, and weights manifest verification.
     */
    public function getModelMetadata(Request $request): Response
    {
        $response = new Response();
        $bom = $this->aiEngine->getModelBillOfMaterials();
        return $response->json(['aibom' => $bom]);
    }
}
