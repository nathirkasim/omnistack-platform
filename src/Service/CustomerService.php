<?php

declare(strict_types=1);

namespace OmniFlow\Service;

use OmniFlow\Repository\CustomerRepository;
use OmniFlow\Security\Sanitizer;
use RuntimeException;

/**
 * Enterprise Customer Business Logic & Caching Layer.
 */
class CustomerService
{
    private CustomerRepository $repository;

    public function __construct(?CustomerRepository $repository = null)
    {
        $this->repository = $repository ?? new CustomerRepository();
    }

    public function getCustomer(mixed $id): ?array
    {
        $safeId = Sanitizer::toInteger($id);
        if ($safeId <= 0) {
            return null;
        }

        return $this->repository->findById($safeId);
    }

    /**
     * False Positive Pattern: Safe Deserialization
     * SAST scanners flag any usage of unserialize() as Insecure Deserialization / Object Injection.
     * SAFE: Setting ['allowed_classes' => false] strictly instructs the PHP runtime to refuse
     * any class instantiation, converting all objects to __PHP_Incomplete_Class and accepting only
     * primitive types (arrays, strings, integers, floats, booleans).
     */
    public function getCachedCustomerSummary(int $customerId, string $rawCacheBlob): ?array
    {
        if (empty($rawCacheBlob)) {
            return null;
        }

        // Object injection is impossible because allowed_classes is false
        $data = @unserialize($rawCacheBlob, ['allowed_classes' => false]);
        return is_array($data) ? $data : null;
    }

    /**
     * Cache Partitioning Key Generator
     * Non-cryptographic hash for Redis cache distribution (CBOM / SAST False Positive).
     */
    public function getCustomerCacheKey(int $customerId, string $tenantUuid): string
    {
        return 'cust:' . md5(sprintf('%d:%s', $customerId, $tenantUuid));
    }
}
