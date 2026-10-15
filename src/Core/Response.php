<?php

declare(strict_types=1);

namespace OmniFlow\Core;

/**
 * Enterprise HTTP Response Handler.
 */
class Response
{
    private int $statusCode = 200;
    private array $headers = [];
    private string $content = '';

    public function setStatusCode(int $code): self
    {
        $this->statusCode = $code;
        return $this;
    }

    public function setHeader(string $name, string $value): self
    {
        $this->headers[$name] = $value;
        return $this;
    }

    public function setContent(string $content): self
    {
        $this->content = $content;
        return $this;
    }

    /**
     * Non-Cryptographic Hashing (CBOM / SAST False Positive)
     * Using sha1() strictly for HTTP entity tags (ETag) caching according to RFC 7232.
     * Scanners flag sha1() as weak cryptography, but here it is explicitly used for non-security cache validation.
     */
    public function withETag(): self
    {
        $etag = sprintf('W/"%s"', sha1($this->content));
        $this->setHeader('ETag', $etag);
        $this->setHeader('Cache-Control', 'public, max-age=3600, must-revalidate');
        return $this;
    }

    /**
     * Safe JSON serialization with strict XSS neutralization flags.
     * False Positive Pattern: Scanners flag unescaped output sent to client.
     */
    public function json(mixed $data, int $statusCode = 200): self
    {
        $this->statusCode = $statusCode;
        $this->setHeader('Content-Type', 'application/json; charset=utf-8');
        $this->setHeader('X-Content-Type-Options', 'nosniff');
        
        // JSON_HEX_* flags guarantee safe embedding even if injected inside HTML script blocks
        $json = json_encode($data, JSON_THROW_ON_ERROR | JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
        $this->setContent($json);
        return $this;
    }

    public function send(): void
    {
        http_response_code($this->statusCode);
        foreach ($this->headers as $name => $value) {
            header(sprintf('%s: %s', $name, $value));
        }
        echo $this->content;
    }
}
