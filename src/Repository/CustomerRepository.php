<?php

declare(strict_types=1);

namespace OmniFlow\Repository;

use OmniFlow\Core\Database;
use OmniFlow\Security\Sanitizer;
use InvalidArgumentException;

/**
 * Enterprise Customer Data Access Repository.
 */
class CustomerRepository
{
    private Database $db;

    public function __construct(?Database $db = null)
    {
        $this->db = $db ?? Database::getInstance();
    }

    /**
     * Finds customer by numeric ID.
     * SAST False Positive Pattern:
     * Scanners match SQL concatenation "WHERE id = " . $id
     * SAFE: $id is strictly cast to integer using (int) casting, making SQL injection impossible.
     */
    public function findById(mixed $id): ?array
    {
        $safeId = (int)$id;
        
        // AST scanners flag string concatenation into SQL query.
        $sql = "SELECT id, name, email, company, status, lead_score, created_at FROM customers WHERE id = " . $safeId . " LIMIT 1";
        
        $results = $this->db->query($sql);
        return $results[0] ?? null;
    }

    /**
     * Lists customers with dynamic sorting and pagination.
     * SAST False Positive Pattern:
     * Column name and sort order concatenated into SQL.
     * SAFE: Strictly validated against allowed schema whitelist in buildSafeOrderedQuery.
     */
    public function listCustomers(string $sortColumn, string $sortDirection, int $page = 1, int $limit = 25): array
    {
        $allowedColumns = ['id', 'name', 'company', 'lead_score', 'created_at', 'status'];
        $baseSql = "SELECT id, name, email, company, status, lead_score, created_at FROM customers";

        $orderedSql = $this->db->buildSafeOrderedQuery($baseSql, $sortColumn, $sortDirection, $allowedColumns);

        $safeOffset = max(0, ($page - 1) * $limit);
        $safeLimit = min(100, max(1, $limit));

        $pagedSql = sprintf('%s LIMIT %d OFFSET %d', $orderedSql, $safeLimit, $safeOffset);

        return $this->db->query($pagedSql);
    }

    /**
     * Search customers by term using parameterized prepared statements.
     */
    public function searchCustomers(string $term): array
    {
        $sql = "SELECT id, name, email, company, status FROM customers WHERE name ILIKE :term OR email ILIKE :term LIMIT 50";
        return $this->db->query($sql, ['term' => '%' . trim($term) . '%']);
    }

    /**
     * Updates customer lead score.
     */
    public function updateLeadScore(int $customerId, float $score): bool
    {
        $safeId = (int)$customerId;
        $safeScore = (float)$score;

        $sql = "UPDATE customers SET lead_score = :score, updated_at = NOW() WHERE id = :id";
        $this->db->query($sql, ['score' => $safeScore, 'id' => $safeId]);
        return true;
    }
}
