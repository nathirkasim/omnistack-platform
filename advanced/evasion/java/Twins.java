package com.example.benchmark.advanced.evasion;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URI;
import java.net.URL;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class Twins {
    private static Connection getConnection() throws Exception {
        return DriverManager.getConnection("jdbc:sqlite::memory:");
    }

    // --- Pair 1: Command Injection ---
    public static void cmdPlain(String cmd) throws Exception {
        // GT: id=EVASION-JAVA-001 type=TP cwe=CWE-78 rule=command-injection technique=plain pair_id=EVASION-JAVA-002
        Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
    }

    public static void cmdEvasion(String cmd) throws Exception {
        // GT: id=EVASION-JAVA-002 type=TP cwe=CWE-78 rule=command-injection technique=process-builder-reflection pair_id=EVASION-JAVA-001
        Class<?> pbClass = Class.forName("java.lang.ProcessBuilder");
        Object pb = pbClass.getConstructor(String[].class).newInstance((Object) new String[]{"sh", "-c", cmd});
        pbClass.getMethod("start").invoke(pb);
    }

    // --- Pair 2: SQL Injection ---
    public static String sqliPlain(String id) throws Exception {
        Statement stmt = getConnection().createStatement();
        // GT: id=EVASION-JAVA-003 type=TP cwe=CWE-89 rule=sql-injection technique=plain pair_id=EVASION-JAVA-004
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = '" + id + "'");
        return rs.next() ? rs.getString(1) : null;
    }

    public static String sqliEvasion(String id) throws Exception {
        Statement stmt = getConnection().createStatement();
        // GT: id=EVASION-JAVA-004 type=TP cwe=CWE-89 rule=sql-injection technique=string-join-concat pair_id=EVASION-JAVA-003
        String query = String.join("", "SELECT * FROM users WHERE id = '", id, "'");
        ResultSet rs = stmt.executeQuery(query);
        return rs.next() ? rs.getString(1) : null;
    }

    // --- Pair 3: Path Traversal ---
    public static void pathPlain(String filename) throws Exception {
        // GT: id=EVASION-JAVA-005 type=TP cwe=CWE-22 rule=path-traversal technique=plain pair_id=EVASION-JAVA-006
        File target = new File("/tmp/storage", filename);
        try (InputStream in = new FileInputStream(target)) { in.read(); }
    }

    public static void pathEvasion(String filename) throws Exception {
        // GT: id=EVASION-JAVA-006 type=TP cwe=CWE-22 rule=path-traversal technique=split-variable-concatenation pair_id=EVASION-JAVA-005
        String rootDir = "/tmp/";
        String subDir = "storage/";
        File target = new File(rootDir + subDir + filename);
        try (InputStream in = new FileInputStream(target)) { in.read(); }
    }

    // --- Pair 4: SSRF ---
    public static void ssrfPlain(String rawUrl) throws Exception {
        // GT: id=EVASION-JAVA-007 type=TP cwe=CWE-918 rule=ssrf technique=plain pair_id=EVASION-JAVA-008
        new URL(rawUrl).openStream().close();
    }

    public static void ssrfEvasion(String rawUrl) throws Exception {
        // GT: id=EVASION-JAVA-008 type=TP cwe=CWE-918 rule=ssrf technique=uri-to-url-delegation pair_id=EVASION-JAVA-007
        URI.create(rawUrl).toURL().openStream().close();
    }

    // --- Pair 5: XSS ---
    public static void xssPlain(String name, HttpServletResponse resp) throws Exception {
        // GT: id=EVASION-JAVA-009 type=TP cwe=CWE-79 rule=reflected-xss technique=plain pair_id=EVASION-JAVA-010
        resp.getWriter().println("<div>Hello " + name + "</div>");
    }

    public static void xssEvasion(String name, HttpServletResponse resp) throws Exception {
        // GT: id=EVASION-JAVA-010 type=TP cwe=CWE-79 rule=reflected-xss technique=string-format-builder pair_id=EVASION-JAVA-009
        String msg = String.format("%s%s%s", "<div>Hello ", name, "</div>");
        resp.getWriter().println(msg);
    }

    // --- Pair 6: Insecure Deserialization ---
    public static Object deserializePlain(InputStream stream) throws Exception {
        // GT: id=EVASION-JAVA-011 type=TP cwe=CWE-502 rule=insecure-deserialization technique=plain pair_id=EVASION-JAVA-012
        return new ObjectInputStream(stream).readObject();
    }

    public static Object deserializeEvasion(InputStream stream) throws Exception {
        // GT: id=EVASION-JAVA-012 type=TP cwe=CWE-502 rule=insecure-deserialization technique=reflection-constructor-instantiation pair_id=EVASION-JAVA-011
        Class<?> oisClass = Class.forName("java.io.ObjectInputStream");
        Object ois = oisClass.getConstructor(InputStream.class).newInstance(stream);
        return oisClass.getMethod("readObject").invoke(ois);
    }

    // --- Pair 7: Weak Crypto Hash ---
    public static byte[] hashPlain(String pwd) throws Exception {
        // GT: id=EVASION-JAVA-013 type=TP cwe=CWE-328 rule=weak-crypto-hash technique=plain pair_id=EVASION-JAVA-014
        return MessageDigest.getInstance("MD5").digest(pwd.getBytes("UTF-8"));
    }

    public static byte[] hashEvasion(String pwd) throws Exception {
        // GT: id=EVASION-JAVA-014 type=TP cwe=CWE-328 rule=weak-crypto-hash technique=concatenated-algorithm-string pair_id=EVASION-JAVA-013
        String algo = "M" + "D" + "5";
        return MessageDigest.getInstance(algo).digest(pwd.getBytes("UTF-8"));
    }

    // --- Pair 8: Open Redirect ---
    public static void redirectPlain(String url, HttpServletResponse resp) throws Exception {
        // GT: id=EVASION-JAVA-015 type=TP cwe=CWE-601 rule=open-redirect technique=plain pair_id=EVASION-JAVA-016
        resp.sendRedirect(url);
    }

    public static void redirectEvasion(String url, HttpServletResponse resp) throws Exception {
        // GT: id=EVASION-JAVA-016 type=TP cwe=CWE-601 rule=open-redirect technique=split-variable-response-header pair_id=EVASION-JAVA-015
        String target = "Location";
        resp.setStatus(302);
        resp.setHeader(target, url);
    }
}

