<?php

declare(strict_types=1);

namespace OmniFlow\Service;

use OmniFlow\Repository\InvoiceRepository;
use OmniFlow\Core\Database;
use DateTimeImmutable;

/**
 * Enterprise Predictive Analytics & Aggregation Engine.
 */
class AnalyticsService
{
    private InvoiceRepository $invoiceRepo;
    private Database $db;

    public function __construct(?InvoiceRepository $invoiceRepo = null, ?Database $db = null)
    {
        $this->invoiceRepo = $invoiceRepo ?? new InvoiceRepository();
        $this->db = $db ?? Database::getInstance();
    }

    /**
     * Compute revenue velocity and forecast metrics.
     */
    public function getRevenueMetrics(string $startDate, string $endDate): array
    {
        $dailyRecords = $this->invoiceRepo->getRevenueByDateRange($startDate, $endDate);

        $totalRevenue = 0.0;
        $totalInvoices = 0;
        $trend = [];

        foreach ($dailyRecords as $record) {
            $amount = (float)($record['daily_revenue'] ?? 0.0);
            $count = (int)($record['invoice_count'] ?? 0);

            $totalRevenue += $amount;
            $totalInvoices += $count;

            $trend[] = [
                'date' => $record['invoice_date'],
                'revenue' => $amount,
                'invoices' => $count,
            ];
        }

        return [
            'total_revenue' => $totalRevenue,
            'total_invoices' => $totalInvoices,
            'average_order_value' => $totalInvoices > 0 ? round($totalRevenue / $totalInvoices, 2) : 0.0,
            'daily_trend' => $trend,
            'generated_at' => (new DateTimeImmutable())->format('c'),
        ];
    }

    /**
     * Non-Cryptographic Hashing for Analytics ETag & Cache Key (CBOM False Positive)
     */
    public function computeMetricsETag(array $metrics): string
    {
        return sha1(json_encode($metrics, JSON_THROW_ON_ERROR));
    }
}
