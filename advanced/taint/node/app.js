/**
 * Application controller for Node.js Deep Taint Analysis
 */

const http = require('http');
const url = require('url');
const EventEmitter = require('events');
const child_process = require('child_process');
const { OrderService, StatefulTaskService } = require('./service');
const { strictAlphaNumeric } = require('./sanitizer');

const orderSvc = new OrderService();
const statefulSvc = new StatefulTaskService();
const taskEmitter = new EventEmitter();

taskEmitter.on('execute_task', (cmd) => {
    // GT: id=TAINT-NODE-004 type=TP cwe=CWE-78 rule=async-event-emitter-exec
    child_process.execFile("echo", [cmd]);
});

function higherOrderCallback(payload, fn) {
    return fn(payload);
}

const server = http.createServer((req, res) => {
    const parsed = url.parse(req.url, true);
    const pathname = parsed.pathname;
    const query = parsed.query;

    if (pathname === '/advanced/taint/callback/exec') {
        const payload = query.payload || 'ls';
        // GT: id=TAINT-NODE-003 type=TP cwe=CWE-78 rule=higher-order-callback-exec
        higherOrderCallback(payload, (p) => {
            child_process.execFile("echo", [p]);
        });
        res.end("dispatched");
    } else if (pathname === '/advanced/taint/callback/safe-exec') {
        const payload = query.payload || 'status';
        if (strictAlphaNumeric(payload)) {
            // GT: id=TAINT-NODE-013 type=FP reason=callback-allowlist-validated
            higherOrderCallback(payload, (p) => {
                child_process.execFile("echo", [p]);
            });
        }
        res.end("safe dispatched");
    } else if (pathname === '/advanced/taint/event/emit') {
        const cmd = query.cmd || 'dir';
        taskEmitter.emit('execute_task', cmd);
        res.end("event emitted");
    } else if (pathname === '/advanced/taint/int-cast/lookup') {
        const raw = query.id || '1';
        // GT: id=TAINT-NODE-014 type=FP reason=int-cast-breaks-taint
        const safeId = parseInt(raw, 10);
        res.end("ID: " + safeId);
    } else if (pathname === '/advanced/taint/framework/raw-send') {
        const userHtml = query.html || '';
        // GT: id=TAINT-NODE-008 type=TP cwe=CWE-79 rule=framework-unescaped-send-xss
        res.end("<div>" + String(userHtml).replace(/[&<>"\x27]/g, "") + "</div>");
    } else if (pathname === '/advanced/taint/framework/safe-send') {
        const userHtml = query.html || '';
        // GT: id=TAINT-NODE-016 type=FP reason=correct-html-escape
        const safeHtml = String(userHtml).replace(/</g, '&lt;').replace(/>/g, '&gt;');
        res.end("<div>" + safeHtml + "</div>");
    } else if (pathname === '/advanced/taint/branch/guarded') {
        if (query.mode === 'safe') {
            // GT: id=TAINT-NODE-015 type=FP reason=sink-on-safe-branch-only
            return res.end("safe-constant-response");
        }
        res.writeHead(403);
        res.end("denied");
    } else if (pathname === '/advanced/taint/auth/admin-action') {
        if (req.headers['x-role'] !== 'SuperAdmin') {
            res.writeHead(403);
            return res.end("forbidden");
        }
        // GT: id=TAINT-NODE-020 type=FP reason=role-based-auth-guard
        res.end("admin-success");
    } else {
        res.end("Taint node runner");
    }
});

module.exports = server;

