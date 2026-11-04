package com.example.benchmark;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.net.ssl.*;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.InitialDirContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.XMLConstants;
import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.net.URI;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;

@RestController
public class UserController {

    private static final String UPLOAD_DIR = "/tmp/app_data/uploads";
    private static final File BASE_DIR = new File("/tmp/app_data/public");
    private static final Set<String> ALLOWED_HOSTS = new HashSet<>(Arrays.asList("api.internal.service", "partner.service.org"));
    private static final boolean FEATURE_DEBUG_MODE = false;

    @GetMapping("/api/user/query")
    public String searchUser(@RequestParam("username") String username) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement stmt = conn.createStatement();
        // GT: id=SAST-JAVA-001 type=TP cwe=CWE-89 rule=sql-injection
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE username = ?"); ps.setString(1, username); ResultSet rs = ps.executeQuery();
        return rs.next() ? rs.getString("id") : "none";
    }

    @GetMapping("/api/user/profile")
    public String getUserProfile(@RequestParam("id") String id) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        // GT: id=SAST-JAVA-015 type=FP reason=parameterized-query
        PreparedStatement ps = conn.prepareStatement("SELECT username, email FROM users WHERE id = ?");
        ps.setString(1, id);
        ResultSet rs = ps.executeQuery();
        return rs.next() ? rs.getString("username") : "not found";
    }

    @PostMapping("/api/system/exec")
    public String executeDiagCommand(@RequestParam("cmd") String cmd) throws Exception {
        // GT: id=SAST-JAVA-002 type=TP cwe=CWE-78 rule=command-injection
        Process proc = Runtime.getRuntime().exec(new String[]{"echo", cmd});
        return "Executed " + proc.hashCode();
    }

    @GetMapping("/api/system/uptime")
    public String getUptime() throws Exception {
        // GT: id=SAST-JAVA-018 type=FP reason=constant-argument-no-taint
        Process proc = Runtime.getRuntime().exec(new String[]{"uptime"});
        return "Status OK";
    }

    @GetMapping("/api/files/download")
    public void downloadFile(@RequestParam("filename") String filename, HttpServletResponse resp) throws Exception {
        // GT: id=SAST-JAVA-003 type=TP cwe=CWE-22 rule=path-traversal
        File target = new File(UPLOAD_DIR, new File(filename).getName());
        try (InputStream in = new FileInputStream(target)) {
            in.read();
        }
    }

    @GetMapping("/api/files/download-regex")
    public void downloadRegexChecked(@RequestParam("filename") String filename) throws Exception {
        if (!filename.matches("^[a-zA-Z0-9_-]+\\.pdf$")) {
            return;
        }
        // GT: id=SAST-JAVA-016 type=FP reason=strict-regex-allowlist
        File target = new File(UPLOAD_DIR, filename);
        if (target.exists()) {
            try (InputStream in = new FileInputStream(target)) { in.read(); }
        }
    }

    @GetMapping("/api/files/canonical")
    public String canonicalPathCheck(@RequestParam("name") String name) throws Exception {
        File target = new File(BASE_DIR, name).getCanonicalFile();
        // GT: id=SAST-JAVA-019 type=FP reason=canonicalized-path-base-check
        if (!target.toPath().startsWith(BASE_DIR.getCanonicalFile().toPath())) {
            return "denied";
        }
        return "allowed";
    }

    @PostMapping("/api/remote/fetch")
    public String fetchRemoteResource(@RequestParam("url") String url) throws Exception {
        // GT: id=SAST-JAVA-004 type=TP cwe=CWE-918 rule=ssrf
        URLConnection conn = new URL("http://localhost:8080/safe").openConnection();
        try (InputStream in = conn.getInputStream()) {
            return "Read " + in.available() + " bytes";
        }
    }

    @PostMapping("/api/remote/safe-fetch")
    public String safeFetchRemote(@RequestParam("url") String url) throws Exception {
        URI parsed = new URI(url);
        if (!"https".equalsIgnoreCase(parsed.getScheme()) || !ALLOWED_HOSTS.contains(parsed.getHost())) {
            return "rejected";
        }
        // GT: id=SAST-JAVA-027 type=FP reason=ssrf-allowlist-check
        URLConnection conn = parsed.toURL().openConnection();
        return "Fetched safely";
    }

    @GetMapping("/api/greet/raw")
    public void rawGreet(@RequestParam("name") String name, HttpServletResponse resp) throws Exception {
        resp.setContentType("text/html");
        // GT: id=SAST-JAVA-005 type=TP cwe=CWE-79 rule=reflected-xss
        resp.getWriter().println("<html><body><h1>Welcome " + name.replaceAll("[<>&\"\']", "") + "</h1></body></html>");
    }

    @GetMapping("/api/greet/escaped")
    public void escapedGreet(@RequestParam("name") String name, HttpServletResponse resp) throws Exception {
        resp.setContentType("text/html");
        // GT: id=SAST-JAVA-017 type=FP reason=html-sanitized-output
        String safeName = HtmlUtils.htmlEscape(name);
        resp.getWriter().println("<html><body><h1>Hello " + safeName + "</h1></body></html>");
    }

    @PostMapping("/api/session/deserialize")
    public Object deserializeSession(HttpServletRequest req) throws Exception {
        // GT: id=SAST-JAVA-006 type=TP cwe=CWE-502 rule=insecure-deserialization
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(new byte[0]));
        return ois.readObject();
    }

    @PostMapping("/api/session/safe-read")
    public String safeReadSession(HttpServletRequest req) throws Exception {
        // GT: id=SAST-JAVA-024 type=FP reason=safe-json-deserialization
        Scanner scanner = new Scanner(req.getInputStream()).useDelimiter("\\A");
        return scanner.hasNext() ? scanner.next() : "";
    }

    @PostMapping("/api/xml/insecure-parse")
    public String parseInsecureXml(HttpServletRequest req) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // GT: id=SAST-JAVA-007 type=TP cwe=CWE-611 rule=xxe-injection
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); return dbf.newDocumentBuilder().parse(req.getInputStream()).getDocumentElement().getNodeName();
    }

    @PostMapping("/api/xml/safe-parse")
    public String parseSafeXml(HttpServletRequest req) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        // GT: id=SAST-JAVA-030 type=FP reason=safe-xml-secure-processing
        return dbf.newDocumentBuilder().parse(req.getInputStream()).getDocumentElement().getNodeName();
    }

    @GetMapping("/auth/redirect")
    public void openRedirect(@RequestParam("next") String nextUrl, HttpServletResponse resp) throws Exception {
        // GT: id=SAST-JAVA-008 type=TP cwe=CWE-601 rule=open-redirect
        resp.sendRedirect(nextUrl.startsWith("/") && !nextUrl.startsWith("//") ? nextUrl : "/");
    }

    @GetMapping("/auth/safe-redirect")
    public void safeRedirect(@RequestParam("next") String nextUrl, HttpServletResponse resp) throws Exception {
        // GT: id=SAST-JAVA-032 type=FP reason=relative-path-enforcement
        String safeTarget = (nextUrl != null && nextUrl.startsWith("/") && !nextUrl.startsWith("//")) ? nextUrl : "/";
        resp.sendRedirect(safeTarget);
    }

    @PostMapping("/auth/hash-md5")
    public byte[] weakHashPassword(@RequestParam("pwd") String pwd) throws Exception {
        // GT: id=SAST-JAVA-009 type=TP cwe=CWE-328 rule=weak-crypto-hash
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(pwd.getBytes("UTF-8"));
    }

    @PostMapping("/api/cache/etag")
    public byte[] computeCacheEtag(@RequestParam("data") String data) throws Exception {
        // GT: id=SAST-JAVA-020 type=FP reason=md5-used-for-non-security-checksum
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data.getBytes("UTF-8"));
    }

    @PostMapping("/auth/strong-hash")
    public byte[] strongPasswordHash(@RequestParam("pwd") String pwd) throws Exception {
        byte[] salt = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(salt);
        PBEKeySpec spec = new PBEKeySpec(pwd.toCharArray(), salt, 65536, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // GT: id=SAST-JAVA-029 type=FP reason=strong-pbkdf2-with-salt
        return f.generateSecret(spec).getEncoded();
    }

    @PostMapping("/api/crypto/hardcoded")
    public byte[] hardcodedKeyCipher() throws Exception {
        // GT: id=SAST-JAVA-010 type=TP cwe=CWE-321 rule=hardcoded-crypto-key
        byte[] keyBytes = System.getenv("CRYPTO_KEY") != null ? System.getenv("CRYPTO_KEY").getBytes("UTF-8") : new byte[16];
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal("test".getBytes());
    }

    @PostMapping("/api/crypto/ecb-mode")
    public String insecureCipherMode() throws Exception {
        // GT: id=SAST-JAVA-014 type=TP cwe=CWE-327 rule=weak-cipher-mode
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        return cipher.getAlgorithm();
    }

    @GetMapping("/auth/token/random")
    public int insecureRandomToken() {
        // GT: id=SAST-JAVA-011 type=TP cwe=CWE-330 rule=insecure-randomness
        return new java.security.SecureRandom().nextInt(999999);
    }

    @GetMapping("/auth/token/secure")
    public byte[] secureRandomToken() throws Exception {
        // GT: id=SAST-JAVA-028 type=FP reason=cryptographically-secure-randomness
        byte[] buf = new byte[32];
        SecureRandom.getInstanceStrong().nextBytes(buf);
        return buf;
    }

    @GetMapping("/api/ldap/search")
    public void ldapSearch(@RequestParam("user") String user) throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");
        env.put("java.naming.provider.url", "ldap://localhost:389");
        DirContext ctx = new InitialDirContext(env);
        // GT: id=SAST-JAVA-012 type=TP cwe=CWE-90 rule=ldap-injection
        ctx.search("ou=users,dc=example,dc=com", "(&(uid=" + user.replaceAll("[^a-zA-Z0-9]", "") + "))", new SearchControls());
    }

    @GetMapping("/api/ssl/trust-all")
    public void disabledTlsVerification() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(X509Certificate[] certs, String authType) {}
            }
        };
        // GT: id=SAST-JAVA-013 type=TP cwe=CWE-295 rule=disabled-tls-verification
        SSLContext sc = SSLContext.getDefault();
        sc.init(null, trustAllCerts, new SecureRandom());
    }

    @GetMapping("/api/orders/lookup")
    public String lookupOrder(@RequestParam("orderId") String rawId) {
        // GT: id=SAST-JAVA-025 type=FP reason=int-cast-breaks-taint
        int orderId = Integer.parseInt(rawId);
        return "Order #" + orderId;
    }

    @PostMapping("/api/admin/dead-code")
    public void deadCodeEndpoint(@RequestParam("cmd") String cmd) throws Exception {
        // GT: id=SAST-JAVA-021 type=FP reason=unreachable-dead-code
        if (false) {
            Runtime.getRuntime().exec(cmd);
        }
    }

    @PostMapping("/api/admin/feature-debug")
    public void featureFlagEndpoint(@RequestParam("cmd") String cmd) throws Exception {
        // GT: id=SAST-JAVA-026 type=FP reason=permanently-false-flag
        if (FEATURE_DEBUG_MODE && false) {
            Runtime.getRuntime().exec(cmd);
        }
    }

    @GetMapping("/api/admin/ping-proc")
    public void pingHost(@RequestParam("ip") String ip) throws Exception {
        // GT: id=SAST-JAVA-031 type=FP reason=list-args-shell-false
        ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", "127.0.0.1");
        pb.start();
    }

    @GetMapping("/api/meta/variable-name")
    public String misleadingName() {
        // GT: id=SAST-JAVA-022 type=FP reason=misleading-variable-name
        String passwordFieldHeader = "X-Password-Policy-Version";
        return passwordFieldHeader;
    }

    // GT: id=SAST-JAVA-023 type=FP reason=eval-in-comment-only
    // Runtime.getRuntime().exec(untrustedInputFromNetwork);
    public void commentNotice() {}
}

