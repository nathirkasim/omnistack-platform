<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use OmniFlow\Core\Request;
use OmniFlow\Core\Response;
use OmniFlow\Core\Router;
use OmniFlow\Controller\AuthController;
use OmniFlow\Controller\CustomerController;
use OmniFlow\Controller\AnalyticsController;
use OmniFlow\Controller\ReportController;
use OmniFlow\Controller\AIInsightsController;
use OmniFlow\Controller\WebhookController;

$request = Request::createFromGlobals();
$router = new Router();

// Authentication Routes
$router->register('POST', '/api/auth/login', AuthController::class, 'login');
$router->register('GET', '/api/auth/verify', AuthController::class, 'verifySession');

// Customer Management Routes
$router->register('GET', '/api/customers', CustomerController::class, 'index');
$router->register('GET', '/api/customers/show', CustomerController::class, 'show');
$router->register('GET', '/api/customers/search', CustomerController::class, 'search');

// Revenue Analytics Routes
$router->register('GET', '/api/analytics/revenue', AnalyticsController::class, 'revenue');

// Export & Report Routes
$router->register('POST', '/api/reports/export', ReportController::class, 'exportPdf');
$router->register('GET', '/api/reports/download', ReportController::class, 'download');

// AI Lead Scoring & AIBOM Routes
$router->register('POST', '/api/ai/score-lead', AIInsightsController::class, 'scoreLead');
$router->register('GET', '/api/ai/bom', AIInsightsController::class, 'getModelMetadata');

// Webhook Integration Routes
$router->register('POST', '/api/webhooks/trigger', WebhookController::class, 'trigger');

// Web Dashboard View
$router->register('GET', '/', CustomerController::class, 'index');

try {
    $response = $router->dispatch($request);
    $response->send();
} catch (Throwable $e) {
    $errRes = new Response();
    $errRes->setStatusCode(500)->json([
        'error' => 'Internal Application Exception',
        'code' => $e->getCode(),
        'message' => 'An error occurred during request lifecycle processing',
    ])->send();
}
