<?php

declare(strict_types=1);

namespace OmniFlow\Repository;

use OmniFlow\Core\Database;
use DateTimeImmutable;
use InvalidArgumentException;

/**
 * Enterprise Billing & Invoice Data Access Repository.
 */
class InvoiceRepository
{
    private Database $db;

    public function __construct(?Database $db = null)
    {
        $this->db = $db ?? Database::getInstance();
    }

    /**
     * Aggregates revenue within safe date range.
     * SAST False Positive Pattern:
     * Dates parsed and passed into SQL builder.
     */
    public function getRevenueByDateRange(string $startDate, string $endDate): array
    {
        // Enforce strict ISO-8601 YYYY-MM-DD parsing
        $start = DateTimeImmutable::createFromFormat('Y-m-d', trim($startDate));
        $end = DateTimeImmutable::createFromFormat('Y-m-d', trim($endDate));

        if (!$start || !$end) {
            throw new InvalidArgumentException('Invalid date format. Expected YYYY-MM-DD');
        }

        $sql = "SELECT DATE(issued_at) as invoice_date, SUM(amount) as daily_revenue, COUNT(id) as invoice_count
                FROM invoices
                WHERE issued_at >= :start_date AND issued_at <= :end_date AND status = 'paid'
                GROUP BY DATE(issued_at)
                ORDER BY invoice_date ASC";

        return $this->db->query($sql, [
            'start_date' => $start->format('Y-m-d 00:00:00'),
            'end_date' => $end->format('Y-m-d 23:59:59'),
        ]);
    }

    /**
     * Fetch unpaid invoices for automated dunning.
     */
    public function getPendingInvoices(int $tenantId): array
    {
        $safeTenantId = (int)$tenantId;
        $sql = "SELECT id, customer_id, amount, currency, due_date FROM invoices WHERE tenant_id = " . $safeTenantId . " AND status = 'unpaid'";
        return $this->db->query($sql);
    }
}
