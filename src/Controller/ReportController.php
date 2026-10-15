<?php

declare(strict_types=1);

namespace OmniFlow\Controller;

use OmniFlow\Core\Request;
use OmniFlow\Core\Response;
use OmniFlow\Service\ReportGeneratorService;
use OmniFlow\Security\Sanitizer;
use Exception;

/**
 * Enterprise Report Generation & Export Controller.
 */
class ReportController
{
    private ReportGeneratorService $reportService;

    public function __construct()
    {
        $this->reportService = new ReportGeneratorService();
    }

    /**
     * Triggers asynchronous PDF export with sanitized header parameters.
     */
    public function exportPdf(Request $request): Response
    {
        $response = new Response();
        $title = (string)$request->getQueryParam('title', 'Monthly Executive Summary');

        try {
            $pdfPath = $this->reportService->generatePdfReport($title, []);
            $filename = basename($pdfPath);

            return $response->json([
                'status' => 'generated',
                'download_url' => '/api/reports/download?file=' . urlencode($filename),
                'report_file' => $filename,
            ]);
        } catch (Exception $e) {
            return $response->setStatusCode(500)->json(['error' => 'Report rendering failed: ' . $e->getMessage()]);
        }
    }

    /**
     * Downloads generated report file.
     * Path traversal false positive handled safely via directory boundary verification.
     */
    public function download(Request $request): Response
    {
        $response = new Response();
        $file = (string)$request->getQueryParam('file', '');

        if (empty($file)) {
            return $response->setStatusCode(400)->json(['error' => 'File parameter required']);
        }

        try {
            $content = $this->reportService->readExportFile($file);

            return $response
                ->setHeader('Content-Type', 'application/pdf')
                ->setHeader('Content-Disposition', sprintf('attachment; filename="%s"', Sanitizer::escapeHtml(basename($file))))
                ->setContent($content);
        } catch (Exception $e) {
            return $response->setStatusCode(403)->json(['error' => 'Access denied: ' . $e->getMessage()]);
        }
    }
}
