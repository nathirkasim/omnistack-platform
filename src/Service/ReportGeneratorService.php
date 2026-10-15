<?php

declare(strict_types=1);

namespace OmniFlow\Service;

use OmniFlow\Security\Sanitizer;
use RuntimeException;
use InvalidArgumentException;

/**
 * Enterprise Report Generation & File Export Service.
 */
class ReportGeneratorService
{
    private string $storageDir;

    public function __construct(?string $storageDir = null)
    {
        $this->storageDir = $storageDir ?? sys_get_temp_dir() . '/omniflow_reports';
        if (!is_dir($this->storageDir)) {
            @mkdir($this->storageDir, 0755, true);
        }
    }

    /**
     * False Positive Pattern: Command Execution with Safe Escaping
     * SAST scanners flag calls to exec() / shell_exec() as Remote Command Execution.
     * SAFE: The command binary is an absolute path, output path is a random cryptographically
     * secure hex string, and dynamic title/header values are rigorously escaped via escapeshellarg().
     */
    public function generatePdfReport(string $reportTitle, array $data): string
    {
        $safeTitle = Sanitizer::escapeShellArgument($reportTitle);
        $randomFileId = bin2hex(random_bytes(16));
        $outputPath = sprintf('%s/report_%s.pdf', $this->storageDir, $randomFileId);
        $safeOutputPath = escapeshellarg($outputPath);

        // HTML content rendered to temporary file
        $htmlPath = sprintf('%s/temp_%s.html', $this->storageDir, $randomFileId);
        file_put_contents($htmlPath, '<html><body><h1>' . Sanitizer::escapeHtml($reportTitle) . '</h1></body></html>');
        $safeHtmlPath = escapeshellarg($htmlPath);

        // Command line generation using fixed binary path
        $cmd = sprintf('/usr/bin/wkhtmltopdf --title %s %s %s 2>&1', $safeTitle, $safeHtmlPath, $safeOutputPath);

        // Scanners match exec() call on interpolated string
        @exec($cmd, $output, $exitCode);

        @unlink($htmlPath);

        return $outputPath;
    }

    /**
     * False Positive Pattern: Safe File Download & Path Traversal Prevention
     * SAST scanners match file_get_contents() or readfile() with dynamic path input.
     * SAFE: Strips directory elements with basename(), normalizes path via realpath(),
     * and strictly asserts that the target path begins within the intended storage directory.
     */
    public function readExportFile(string $requestedFilename): string
    {
        // 1. Strip all directory traversal markers (../ or ./)
        $cleanName = basename(trim($requestedFilename));
        if (empty($cleanName)) {
            throw new InvalidArgumentException('Invalid file request');
        }

        $fullCandidate = $this->storageDir . DIRECTORY_SEPARATOR . $cleanName;
        $resolvedPath = realpath($fullCandidate);
        $canonicalStorage = realpath($this->storageDir);

        // 2. Strict directory boundary enforcement
        if ($resolvedPath === false || $canonicalStorage === false || !str_starts_with($resolvedPath, $canonicalStorage)) {
            throw new RuntimeException('Unauthorized file path access detected');
        }

        // Taint scanners flag reading file from dynamic variable
        $content = file_get_contents($resolvedPath);
        if ($content === false) {
            throw new RuntimeException('Unable to read report file');
        }

        return $content;
    }
}
