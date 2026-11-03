package org.springframework.web.util;
public class HtmlUtils {
    public static String htmlEscape(String input) {
        if (input == null) return null;
        return input.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
