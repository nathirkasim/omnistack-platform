<?php
/**
 * SAST Test Fixture: SQL Injection, XSS, and Command Injection (PHP)
 * Covers paired True Positives and False Positives.
 */

// ==============================================================================
// TP-SAST-025: SQL Injection via PDO query string concatenation
// CWE-89 | High Severity
// ==============================================================================
function get_account_vulnerable(PDO $pdo, string $userId) {
    // Vulnerable: Direct interpolation in query
    $sql = "SELECT id, username, email FROM users WHERE id = '" . $userId . "'";
    return $pdo->query($sql)->fetch();
}

// ==============================================================================
// FP-SAST-034: Safe Parameterized PDO Prepared Statement
// Expected: Safe / Parameterized
// ==============================================================================
function get_account_safe(PDO $pdo, string $userId) {
    // Safe: Prepared statement with placeholder parameter
    $stmt = $pdo->prepare("SELECT id, username, email FROM users WHERE id = :id");
    $stmt->execute(['id' => $userId]);
    return $stmt->fetch();
}

// ==============================================================================
// TP-SAST-026: Reflected Cross-Site Scripting (XSS)
// CWE-79 | High Severity
// ==============================================================================
function render_greeting_vulnerable() {
    $name = $_GET['name'] ?? '';
    // Vulnerable: Direct echo without contextual output encoding
    echo "<h1>Welcome, " . $name . "!</h1>";
}

// ==============================================================================
// FP-SAST-035: Safe Output Encoding via htmlspecialchars
// Expected: Safe / Encoded
// ==============================================================================
function render_greeting_safe() {
    $name = $_GET['name'] ?? '';
    // Safe: Encodes HTML entities
    echo "<h1>Welcome, " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "!</h1>";
}

// ==============================================================================
// TP-SAST-027: Command Injection via shell_exec
// CWE-78 | Critical Severity
// ==============================================================================
function run_network_check_vulnerable(string $host) {
    // Vulnerable: Untrusted input concatenated into shell command
    return shell_exec("ping -c 1 " . $host);
}

// ==============================================================================
// FP-SAST-036: Safe Command Execution with escapeshellarg
// Expected: Safe / Sanitized
// ==============================================================================
function run_network_check_safe(string $host) {
    // Safe: Host argument escaped
    $safeHost = escapeshellarg($host);
    return shell_exec("ping -c 1 " . $safeHost);
}

// ==============================================================================
// TP-SAST-028: Insecure Deserialization via PHP unserialize
// CWE-502 | Critical Severity
// ==============================================================================
function parse_user_session_vulnerable(string $serializedInput) {
    // Vulnerable: PHP object injection via unserialize
    return unserialize($serializedInput);
}

// ==============================================================================
// FP-SAST-037: Safe JSON Deserialization
// Expected: Safe / Non-executable
// ==============================================================================
function parse_user_session_safe(string $jsonInput) {
    // Safe: JSON decode produces associative array/stdClass without magic methods
    return json_decode($jsonInput, true);
}
