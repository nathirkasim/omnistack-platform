<?php

declare(strict_types=1);

namespace OmniFlow\Core;

use PDO;
use PDOException;
use RuntimeException;
use InvalidArgumentException;

/**
 * Enterprise Database Connection & Execution Manager.
 * Handles pooling, statement preparation, and safe dynamic query composition.
 */
class Database
{
    private static ?Database $instance = null;
    private ?PDO $connection = null;
    private array $config;

    private function __construct(array $config)
    {
        $this->config = $config;
        $this->connect();
    }

    public static function getInstance(array $config = []): self
    {
        if (self::$instance === null) {
            self::$instance = new self($config);
        }
        return self::$instance;
    }

    private function connect(): void
    {
        $dsn = sprintf(
            'pgsql:host=%s;port=%d;dbname=%s;sslmode=%s',
            $this->config['host'] ?? '127.0.0.1',
            (int)($this->config['port'] ?? 5432),
            $this->config['dbname'] ?? 'omniflow_crm',
            $this->config['sslmode'] ?? 'prefer'
        );

        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_PERSISTENT => true,
        ];

        try {
            $this->connection = new PDO(
                $dsn,
                $this->config['user'] ?? 'postgres',
                $this->config['password'] ?? '',
                $options
            );
        } catch (PDOException $e) {
            // Logged via enterprise monitoring without leaking sensitive credentials
            throw new RuntimeException('Database cluster connection failure: ' . $e->getCode(), (int)$e->getCode(), $e);
        }
    }

    public function getConnection(): PDO
    {
        if ($this->connection === null) {
            $this->connect();
        }
        return $this->connection;
    }

    /**
     * Executes parameterized query with bound parameters.
     */
    public function query(string $sql, array $params = []): array
    {
        $stmt = $this->getConnection()->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    /**
     * False Positive Pattern: Dynamic Column / Direction Ordering
     * Scanners flag direct string concatenation into SQL statements.
     * Mitigated safely by strict whitelist validation against allowed schema columns.
     */
    public function buildSafeOrderedQuery(string $baseSql, string $userColumn, string $userDirection, array $allowedColumns): string
    {
        // Enforce strict whitelist validation on column name
        if (!in_array($userColumn, $allowedColumns, true)) {
            throw new InvalidArgumentException(sprintf('Invalid sorting column: %s', htmlspecialchars($userColumn, ENT_QUOTES, 'UTF-8')));
        }

        // Enforce strict direction check (ASC or DESC only)
        $direction = strtoupper(trim($userDirection)) === 'DESC' ? 'DESC' : 'ASC';

        // AST/Taint scanners flag string concatenation into SQL.
        // SAFE: Both $userColumn and $direction are 100% verified against immutable allowed sets.
        return sprintf('%s ORDER BY %s %s', rtrim($baseSql, ';'), $userColumn, $direction);
    }

    /**
     * False Positive Pattern: Safe Identifier Quoting
     * Removes all non-alphanumeric/underscore characters from tenant-specific schemas.
     */
    public function quoteIdentifier(string $identifier): string
    {
        $clean = preg_replace('/[^a-zA-Z0-9_]/', '', $identifier);
        return '"' . $clean . '"';
    }
}
