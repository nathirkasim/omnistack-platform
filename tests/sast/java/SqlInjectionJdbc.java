package com.security.test.sast;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import jakarta.persistence.EntityManager;

/**
 * SAST Test Fixture: SQL Injection (Java / JDBC / JPA)
 * Covers paired True Positives and False Positives.
 */
public class SqlInjectionJdbc {

    // =========================================================================
    // TP-SAST-020: SQL Injection via JDBC Statement Concatenation
    // CWE-89 | High Severity
    // =========================================================================
    public ResultSet findUserVulnerable(Connection conn, String userInputId) throws SQLException {
        Statement stmt = conn.createStatement();
        // Vulnerable: Direct string concatenation into SQL query
        String query = "SELECT id, name, role FROM accounts WHERE id = '" + userInputId + "'";
        return stmt.executeQuery(query);
    }

    // =========================================================================
    // FP-SAST-030: Safe Parameterized Query via PreparedStatement
    // Expected: Safe / No detection
    // =========================================================================
    public ResultSet findUserSafe(Connection conn, String userInputId) throws SQLException {
        String query = "SELECT id, name, role FROM accounts WHERE id = ?";
        // Safe: PreparedStatement with bind variable
        PreparedStatement pstmt = conn.prepareStatement(query);
        pstmt.setString(1, userInputId);
        return pstmt.executeQuery();
    }

    // =========================================================================
    // TP-SAST-021: JPA JPQL Injection via String Concatenation
    // CWE-89 | High Severity
    // =========================================================================
    public Object findAccountByEmailVulnerable(EntityManager em, String emailInput) {
        // Vulnerable: Dynamic JPQL query construction
        String jpql = "SELECT a FROM Account a WHERE a.email = '" + emailInput + "'";
        return em.createQuery(jpql).getResultList();
    }

    // =========================================================================
    // FP-SAST-031: Safe JPA Named Parameter Binding
    // Expected: Safe / Parameterized
    // =========================================================================
    public Object findAccountByEmailSafe(EntityManager em, String emailInput) {
        // Safe: JPQL named parameter
        String jpql = "SELECT a FROM Account a WHERE a.email = :email";
        return em.createQuery(jpql)
                 .setParameter("email", emailInput)
                 .getResultList();
    }
}
