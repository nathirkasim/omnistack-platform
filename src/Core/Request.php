<?php

declare(strict_types=1);

namespace OmniFlow\Core;

/**
 * Enterprise HTTP Request Abstraction.
 */
class Request
{
    private array $get;
    private array $post;
    private array $server;
    private ?string $rawBody;

    public function __construct(array $get = [], array $post = [], array $server = [], ?string $rawBody = null)
    {
        $this->get = $get;
        $this->post = $post;
        $this->server = $server;
        $this->rawBody = $rawBody;
    }

    public static function createFromGlobals(): self
    {
        return new self($_GET, $_POST, $_SERVER, file_get_contents('php://input'));
    }

    public function getMethod(): string
    {
        return strtoupper($this->server['REQUEST_METHOD'] ?? 'GET');
    }

    public function getPath(): string
    {
        $uri = $this->server['REQUEST_URI'] ?? '/';
        $parts = explode('?', $uri);
        return '/' . trim($parts[0], '/');
    }

    public function getQueryParam(string $key, mixed $default = null): mixed
    {
        return $this->get[$key] ?? $default;
    }

    public function getPostParam(string $key, mixed $default = null): mixed
    {
        return $this->post[$key] ?? $default;
    }

    public function getHeader(string $name): ?string
    {
        $headerKey = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
        return $this->server[$headerKey] ?? null;
    }

    public function getRawBody(): ?string
    {
        return $this->rawBody;
    }

    public function getJson(): ?array
    {
        if (empty($this->rawBody)) {
            return null;
        }
        $data = json_decode($this->rawBody, true);
        return is_array($data) ? $data : null;
    }
}
