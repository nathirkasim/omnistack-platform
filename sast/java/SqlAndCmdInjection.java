package org.tigergate.benchmark;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class SqlAndCmdInjection {

    public static void executeUserSearch(String username) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:sqlite:test.db");
        Statement stmt = conn.createStatement();
        // VULNERABLE: Concatenating unsanitized input into SQL statement (CWE-89)
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        ResultSet rs = stmt.executeQuery(query);
        while (rs.next()) {
            System.out.println("User: " + rs.getString("username"));
        }
        conn.close();
    }

    public static void pingHost(String ipAddress) throws Exception {
        // VULNERABLE: Passing untrusted parameter directly to OS runtime command execution (CWE-78)
        Process proc = Runtime.getRuntime().exec("ping -c 1 " + ipAddress);
        BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
    }
}
