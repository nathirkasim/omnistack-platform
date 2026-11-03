package com.example.benchmark.advanced;

import org.springframework.web.util.HtmlUtils;
import java.io.File;

public class SanitizerUtils {
    public static String noopSanitize(String in) {
        return in;
    }

    public static String wrongContextSanitize(String in) {
        return HtmlUtils.htmlEscape(in);
    }

    public static String bypassableBlocklist(String in) {
        return in == null ? "" : in.replace("../", "");
    }

    public static boolean strictAlphaNumeric(String in) {
        return in != null && in.matches("^[a-zA-Z0-9_\\-]+$");
    }

    public static boolean isSafeCanonicalPath(File baseDir, String filename) {
        try {
            File target = new File(baseDir, filename).getCanonicalFile();
            return target.toPath().startsWith(baseDir.getCanonicalFile().toPath());
        } catch (Exception e) {
            return false;
        }
    }
}

