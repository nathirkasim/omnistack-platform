<?php

declare(strict_types=1);

namespace OmniFlow\Controller;

use OmniFlow\Core\Request;
use OmniFlow\Core\Response;
use OmniFlow\Service\CustomerService;
use OmniFlow\Repository\CustomerRepository;
use OmniFlow\Security\Sanitizer;

/**
 * Enterprise Customer Management Controller.
 */
class CustomerController
{
    private CustomerService $customerService;
    private CustomerRepository $repository;

    public function __construct()
    {
        $this->customerService = new CustomerService();
        $this->repository = new CustomerRepository();
    }

    /**
     * Lists customers with dynamic column sorting.
     */
    public function index(Request $request): Response
    {
        $response = new Response();

        $sort = (string)$request->getQueryParam('sort', 'created_at');
        $dir = (string)$request->getQueryParam('dir', 'DESC');
        $page = Sanitizer::toInteger($request->getQueryParam('page', 1), 1);

        $customers = $this->repository->listCustomers($sort, $dir, $page);

        // Sanitize string output values
        $sanitized = array_map(function ($c) {
            return [
                'id' => (int)$c['id'],
                'name' => Sanitizer::escapeHtml($c['name'] ?? ''),
                'email' => Sanitizer::escapeHtml($c['email'] ?? ''),
                'company' => Sanitizer::escapeHtml($c['company'] ?? ''),
                'status' => Sanitizer::escapeHtml($c['status'] ?? ''),
                'lead_score' => (float)($c['lead_score'] ?? 0.0),
                'created_at' => $c['created_at'] ?? '',
            ];
        }, $customers);

        return $response->json([
            'customers' => $sanitized,
            'page' => $page,
            'sort_applied' => $sort,
            'direction' => strtoupper($dir) === 'DESC' ? 'DESC' : 'ASC',
        ]);
    }

    /**
     * Customer details endpoint with cache inspection.
     */
    public function show(Request $request): Response
    {
        $response = new Response();
        $id = $request->getQueryParam('id');

        $customer = $this->customerService->getCustomer($id);
        if (!$customer) {
            return $response->setStatusCode(404)->json(['error' => 'Customer record not found']);
        }

        return $response->json(['customer' => $customer]);
    }

    /**
     * Search customer records by keyword.
     */
    public function search(Request $request): Response
    {
        $response = new Response();
        $term = (string)$request->getQueryParam('q', '');

        if (strlen(trim($term)) < 2) {
            return $response->setStatusCode(400)->json(['error' => 'Search term must be at least 2 characters']);
        }

        $results = $this->repository->searchCustomers($term);
        return $response->json(['results' => $results]);
    }
}
