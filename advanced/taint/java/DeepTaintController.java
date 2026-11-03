package com.example.benchmark.advanced;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;

@RestController
public class DeepTaintController {
    private final OrderService orderService = new OrderService();

    @GetMapping("/advanced/taint/deep-sql")
    public String deepSql(@RequestParam("filter") String filter) throws Exception {
        return orderService.processDeepOrder(filter);
    }

    @GetMapping("/advanced/taint/safe-sql")
    public String safeSql(@RequestParam("id") String id) throws Exception {
        return orderService.processSafeOrder(id);
    }

    @PostMapping("/advanced/taint/stateful/stage")
    public String stageCmd(@RequestParam("cmd") String cmd) {
        orderService.stageCommand(cmd);
        return "staged";
    }

    @PostMapping("/advanced/taint/stateful/dispatch")
    public String dispatchCmd() throws Exception {
        return orderService.dispatchPending();
    }

    @PostMapping("/advanced/taint/stateful/safe-dispatch")
    public String dispatchSafeCmd() throws Exception {
        return orderService.dispatchSafe();
    }

    @PostMapping("/advanced/taint/stream/exec")
    public void streamExec(@RequestParam("cmd") String cmd) {
        orderService.runStreamCommand(cmd);
    }

    @PostMapping("/advanced/taint/stream/safe-exec")
    public void safeStreamExec(@RequestParam("val") String val) {
        orderService.runSafeStreamCommand(val);
    }

    @PostMapping("/advanced/taint/reflection/invoke")
    public Object reflectionInvoke(@RequestParam("methodName") String methodName, @RequestParam("arg") String arg) throws Exception {
        // GT: id=TAINT-JAVA-004 type=TP cwe=CWE-470 rule=unsafe-reflection-invocation
        Method m = Runtime.class.getMethod(methodName, String.class);
        return m.invoke(Runtime.getRuntime(), arg);
    }

    @GetMapping("/advanced/taint/int-cast/lookup")
    public String intCastLookup(@RequestParam("id") String rawId) throws Exception {
        // GT: id=TAINT-JAVA-014 type=FP reason=int-cast-breaks-taint
        int safeId = Integer.parseInt(rawId);
        return "Lookup: " + safeId;
    }

    @PostMapping("/advanced/taint/framework/raw-query")
    public String springRawConcatQuery(@RequestParam("user") String user) throws Exception {
        // GT: id=TAINT-JAVA-008 type=TP cwe=CWE-89 rule=framework-query-string-concat
        String dynamicQuery = "SELECT u FROM User u WHERE u.username = '" + user + "'";
        return "Simulated query: " + dynamicQuery;
    }

    @GetMapping("/advanced/taint/framework/safe-escape")
    public void safeEscapeHtml(@RequestParam("comment") String comment, HttpServletResponse resp) throws Exception {
        // GT: id=TAINT-JAVA-016 type=FP reason=correct-html-escape
        String safe = HtmlUtils.htmlEscape(comment);
        resp.getWriter().println("<div>" + safe + "</div>");
    }

    @GetMapping("/advanced/taint/branch/guarded")
    public String branchGuarded(@RequestParam("mode") String mode) {
        if ("safe".equals(mode)) {
            // GT: id=TAINT-JAVA-015 type=FP reason=sink-on-safe-branch-only
            return "safe-constant-result";
        }
        return "unknown mode";
    }

    @PostMapping("/advanced/taint/auth/admin-action")
    public String adminAction(HttpServletRequest req) {
        String role = req.getHeader("X-User-Role");
        if (!"SUPERADMIN".equals(role)) {
            return "forbidden";
        }
        // GT: id=TAINT-JAVA-020 type=FP reason=role-based-auth-guard
        return "admin-success";
    }

    @PostMapping("/advanced/taint/auth/idor-transfer")
    public void idorTransfer(@RequestParam("target") String target, @RequestParam("amt") double amt) throws Exception {
        orderService.getRepo().updateAccountBalance(target, amt);
    }
}
