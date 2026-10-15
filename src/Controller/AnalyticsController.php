<?php

declare(strict_types=1);

namespace OmniFlow\Controller;

use OmniFlow\Core\Request;
use OmniFlow\Core\Response;
use OmniFlow\Service\AnalyticsService;
use DateTimeImmutable;

/**
 * Enterprise Predictive Analytics & Metrics Controller.
 */
class AnalyticsController
{
    private AnalyticsService $analyticsService;

    public function __construct()
    {
        $this->analyticsService = new AnalyticsService();
    }

    /**
     * Revenue velocity and invoice aggregation dashboard.
     */
    public function revenue(Request $request): Response
    {
        $response = new Response();

        $defaultStart = (new DateTimeImmutable('-30 days'))->format('Y-m-d');
        $defaultEnd = (new DateTimeImmutable())->format('Y-m-d');

        $start = (string)$request->getQueryParam('start_date', $defaultStart);
        $end = (string)$request->getQueryParam('end_date', $defaultEnd);

        try {
            $metrics = $this->analyticsService->getRevenueMetrics($start, $end);
            $etag = $this->analyticsService->computeMetricsETag($metrics);

            // Conditional HTTP caching check
            $ifNoneMatch = $request->getHeader('If-None-Match');
            if ($ifNoneMatch === sprintf('"%s"', $etag)) {
                return $response->setStatusCode(304);
            }

            return $response->setHeader('ETag', sprintf('"%s"', $etag))->json($metrics);
        } catch (\InvalidArgumentException $e) {
            return $response->setStatusCode(400)->json(['error' => $e->getMessage()]);
        }
    }
}
