/**
 * SAST Test Fixture: SQL Injection (TypeScript / Node.js)
 * Covers paired True Positives and False Positives.
 */
import { Client } from 'pg';
import { Sequelize } from 'sequelize';

const client = new Client();
const sequelize = new Sequelize('sqlite::memory:');

// ==============================================================================
// TP-SAST-015: Direct SQL Injection via String Concatenation in PostgreSQL
// CWE-89 | High Severity
// ==============================================================================
export async function findUserVulnerable(userInputId: string) {
    // Vulnerable: raw string concatenation into query
    const sql = "SELECT id, name, email FROM accounts WHERE id = '" + userInputId + "'";
    return await client.query(sql);
}

// ==============================================================================
// FP-SAST-021: Safe Parameterized PostgreSQL Query
// Expected: Safe / No detection
// ==============================================================================
export async function findUserSafe(userInputId: string) {
    // Safe: Query parameters with positional $1 binding
    const sql = 'SELECT id, name, email FROM accounts WHERE id = $1';
    return await client.query(sql, [userInputId]);
}

// ==============================================================================
// TP-SAST-016: Sequelize ORM Insecure Raw Query
// CWE-89 | High Severity
// ==============================================================================
export async function getOrdersByCustomerVulnerable(customerName: string) {
    // Vulnerable: Template literal interpolation in ORM raw query
    return await sequelize.query(`SELECT * FROM orders WHERE customer = '${customerName}'`);
}

// ==============================================================================
// FP-SAST-022: Sequelize ORM Parameterized Replacements
// Expected: Safe / No detection
// ==============================================================================
export async function getOrdersByCustomerSafe(customerName: string) {
    // Safe: Parameter replacements dictionary handled by Sequelize driver
    return await sequelize.query('SELECT * FROM orders WHERE customer = :customer', {
        replacements: { customer: customerName },
    });
}
