package com.example.benchmark.advanced.mutants;

import java.io.*;
import java.sql.*;

public class Mutants {
    // GT: id=MUTANT-JAVA-001 type=TP cwe=CWE-89 rule=sql-injection parent_id=SAST-JAVA-001 mutation=extract_helper
    public static void executeExtracted(Statement stmt, String val) throws Exception {
        PreparedStatement ps = stmt.getConnection().prepareStatement("SELECT * FROM users WHERE status = ?"); ps.setString(1, val); ps.executeQuery();
    }

    public static void runRenamedVars(String paramBeta) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement stmt = conn.createStatement();
        // GT: id=MUTANT-JAVA-002 type=TP cwe=CWE-89 rule=sql-injection parent_id=SAST-JAVA-001 mutation=rename_vars
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE code = ?"); ps.setString(1, paramBeta); ps.executeQuery();
    }

    public static void runWrappedTryCatch(String cmd) {
        try {
            // GT: id=MUTANT-JAVA-003 type=TP cwe=CWE-78 rule=command-injection parent_id=SAST-JAVA-002 mutation=wrap_try_catch
            Runtime.getRuntime().exec(new String[]{"echo", cmd});
        } catch (Exception ignored) {}
    }

    // --- False Positive Mutants ---

    public static void runSafeParameterized(PreparedStatement ps, String id) throws Exception {
        // GT: id=MUTANT-JAVA-004 type=FP reason=parameterized-query parent_id=SAST-JAVA-015 mutation=extract_helper
        ps.setString(1, id);
        ps.executeQuery();
    }
}
