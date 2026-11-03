package com.example.benchmark.advanced;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

public class OrderService {
    private final OrderRepository repo = new OrderRepository();
    private static final Set<String> ALLOWED_HOSTS = new HashSet<>(Arrays.asList("api.internal.service", "partner.service.org"));
    private String pendingCommand = "";
    private String sanitizedField = "";

    public String processDeepOrder(String rawFilter) throws Exception {
        return stepOne(rawFilter);
    }

    private String stepOne(String f) throws Exception {
        return stepTwo(f);
    }

    private String stepTwo(String f) throws Exception {
        return repo.executeRawSql(f);
    }

    public String processSafeOrder(String id) throws Exception {
        return repo.executeParameterized(id);
    }

    public void stageCommand(String cmd) {
        this.pendingCommand = cmd;
    }

    public void stageSafeField(String field) {
        this.sanitizedField = SanitizerUtils.strictAlphaNumeric(field) ? field : "default";
    }

    public String dispatchPending() throws Exception {
        // GT: id=TAINT-JAVA-002 type=TP cwe=CWE-78 rule=class-field-taint-exec
        Process proc = Runtime.getRuntime().exec(new String[]{"sh", "-c", this.pendingCommand});
        return "Executed " + proc.hashCode();
    }

    public String dispatchSafe() throws Exception {
        // GT: id=TAINT-JAVA-012 type=FP reason=sanitized-class-field-exec
        Process proc = Runtime.getRuntime().exec(new String[]{"echo", this.sanitizedField});
        return "Executed safe";
    }

    public void runStreamCommand(String cmd) {
        // GT: id=TAINT-JAVA-003 type=TP cwe=CWE-78 rule=stream-lambda-command-injection
        Stream.of(cmd).forEach(c -> {
            try {
                Runtime.getRuntime().exec(new String[]{"sh", "-c", c});
            } catch (Exception ignored) {}
        });
    }

    public void runSafeStreamCommand(String val) {
        // GT: id=TAINT-JAVA-013 type=FP reason=stream-filter-allowlist-validated
        Stream.of(val).filter(SanitizerUtils::strictAlphaNumeric).forEach(c -> {
            try {
                Runtime.getRuntime().exec(new String[]{"echo", c});
            } catch (Exception ignored) {}
        });
    }

    public String fetchWithNoop(String rawUrl) throws Exception {
        String url = SanitizerUtils.noopSanitize(rawUrl);
        // GT: id=TAINT-JAVA-006 type=TP cwe=CWE-918 rule=noop-sanitizer-ssrf
        URLConnection conn = new URL(url).openConnection();
        try (InputStream in = conn.getInputStream()) {
            return "Read " + in.available() + " bytes";
        }
    }

    public String fetchWithAllowlist(String rawUrl) throws Exception {
        URL parsed = new URL(rawUrl);
        if (!ALLOWED_HOSTS.contains(parsed.getHost())) {
            return "rejected";
        }
        // GT: id=TAINT-JAVA-017 type=FP reason=strict-url-host-allowlist
        URLConnection conn = parsed.openConnection();
        try (InputStream in = conn.getInputStream()) {
            return "Read safe " + in.available();
        }
    }

    public String queryWithWrongSanitizer(String userStr) throws Exception {
        String htmlEscaped = SanitizerUtils.wrongContextSanitize(userStr);
        // GT: id=TAINT-JAVA-007 type=TP cwe=CWE-89 rule=wrong-context-sanitizer-sqli
        return repo.executeRawSql(htmlEscaped);
    }

    public void readWithBypassableBlocklist(File baseDir, String filename) throws Exception {
        String cleaned = SanitizerUtils.bypassableBlocklist(filename);
        // GT: id=TAINT-JAVA-009 type=TP cwe=CWE-22 rule=bypassable-blocklist-traversal
        File target = new File(baseDir, cleaned);
        try (InputStream in = new FileInputStream(target)) { in.read(); }
    }

    public void readWithCanonicalCheck(File baseDir, String filename) throws Exception {
        if (!SanitizerUtils.isSafeCanonicalPath(baseDir, filename)) {
            return;
        }
        // GT: id=TAINT-JAVA-018 type=FP reason=canonical-validator-path-traversal
        File target = new File(baseDir, filename);
        try (InputStream in = new FileInputStream(target)) { in.read(); }
    }

    public OrderRepository getRepo() { return repo; }
}

