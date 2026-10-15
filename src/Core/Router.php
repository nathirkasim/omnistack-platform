<?php

declare(strict_types=1);

namespace OmniFlow\Core;

use RuntimeException;
use InvalidArgumentException;

/**
 * Enterprise Front Controller Routing Engine.
 */
class Router
{
    private array $routes = [];

    public function register(string $method, string $path, string $controllerClass, string $action): void
    {
        $this->routes[] = [
            'method' => strtoupper($method),
            'path' => '/' . trim($path, '/'),
            'controller' => $controllerClass,
            'action' => $action,
        ];
    }

    public function dispatch(Request $request): Response
    {
        $currentMethod = $request->getMethod();
        $currentPath = $request->getPath();

        foreach ($this->routes as $route) {
            if ($route['method'] === $currentMethod && $route['path'] === $currentPath) {
                $controllerClass = $route['controller'];
                $action = $route['action'];

                if (!class_exists($controllerClass)) {
                    throw new RuntimeException(sprintf('Controller %s not found', $controllerClass));
                }

                $controller = new $controllerClass();

                /**
                 * False Positive Pattern: Dynamic Method Invocation
                 * Scanners often flag $controller->$action() as insecure reflection or code execution.
                 * Mitigated safely by verifying method existence and enforcing typed signatures.
                 */
                if (!method_exists($controller, $action) || !is_callable([$controller, $action])) {
                    throw new InvalidArgumentException(sprintf('Action %s not accessible on %s', $action, $controllerClass));
                }

                $response = $controller->$action($request);
                if (!$response instanceof Response) {
                    throw new RuntimeException('Controller action must return Response instance');
                }

                return $response;
            }
        }

        $res = new Response();
        return $res->setStatusCode(404)->json(['error' => 'Endpoint Not Found', 'path' => $currentPath]);
    }
}
