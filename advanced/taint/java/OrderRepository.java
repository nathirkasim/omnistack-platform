package com.example.benchmark.advanced;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

public class OrderRepository {
    private Connection getConnection() throws Exception {
        return DriverManager.getConnection("jdbc:sqlite::memory:");
    }

    public String executeRawSql(String filter) throws Exception {
        Statement stmt = getConnection().createStatement();
        // GT: id=TAINT-JAVA-001 type=TP cwe=CWE-89 rule=deep-taint-sqli
        ResultSet rs = stmt.executeQuery("SELECT id FROM orders WHERE status = '" + filter + "'");
        return rs.next() ? rs.getString("id") : "none";
    }

    public String executeParameterized(String orderId) throws Exception {
        // GT: id=TAINT-JAVA-011 type=FP reason=multi-hop-parameterized-query
        PreparedStatement ps = getConnection().prepareStatement("SELECT id FROM orders WHERE id = ?");
        ps.setString(1, orderId);
        ResultSet rs = ps.executeQuery();
        return rs.next() ? rs.getString("id") : "none";
    }

    public String executeSecondOrder(String tag) throws Exception {
        Statement stmt = getConnection().createStatement();
        // GT: id=TAINT-JAVA-005 type=TP cwe=CWE-89 rule=second-order-sqli
        ResultSet rs = stmt.executeQuery("SELECT summary FROM audit_trail WHERE tag = '" + tag + "'");
        return rs.next() ? rs.getString("summary") : "none";
    }

    public String executeConstantQuery(String _unused) throws Exception {
        Statement stmt = getConnection().createStatement();
        // GT: id=TAINT-JAVA-019 type=FP reason=constant-query-sink
        ResultSet rs = stmt.executeQuery("SELECT 'constant-val'");
        return rs.next() ? rs.getString(1) : "ok";
    }

    public void updateAccountBalance(String targetId, double amount) throws Exception {
        // GT: id=TAINT-JAVA-010 type=TP cwe=CWE-639 rule=idor-unauthorized-update
        PreparedStatement ps = getConnection().prepareStatement("UPDATE accounts SET balance = balance + ? WHERE id = ?");
        ps.setDouble(1, amount);
        ps.setString(2, targetId);
        ps.executeUpdate();
    }
}
