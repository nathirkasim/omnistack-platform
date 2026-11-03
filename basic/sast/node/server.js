/**
 * Node.js / Express style HTTP Application for Security Benchmarking
 * Basic SAST Cases (Node/JavaScript)
 */

const http = require('http');
const url = require('url');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const child_process = require('child_process');

const UPLOAD_DIR = '/tmp/app_data/uploads';
const BASE_DIR = '/tmp/app_data/public';
const FEATURE_DEBUG_MODE = false;
const ALLOWED_HOSTS = new Set(['api.internal.service', 'partner.service.org']);

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

const mockDb = {
    query: function (sql, params) {
        return Promise.resolve([{ id: 1, name: 'admin' }]);
    }
};

const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;
    const query = parsedUrl.query;

    if (pathname === '/api/user/search') {
        const username = query.username || '';
        // GT: id=SAST-NODE-001 type=TP cwe=CWE-89 rule=sql-injection
        mockDb.query("SELECT * FROM users WHERE username = '" + username + "'");
        res.end(JSON.stringify({ status: 'queried' }));
    } else if (pathname === '/api/user/profile') {
        const userId = query.id || '1';
        // GT: id=SAST-NODE-015 type=FP reason=parameterized-query
        mockDb.query("SELECT * FROM users WHERE id = $1", [userId]);
        res.end(JSON.stringify({ id: userId }));
    } else if (pathname === '/api/system/exec') {
        const host = query.host || '127.0.0.1';
        // GT: id=SAST-NODE-002 type=TP cwe=CWE-78 rule=command-injection
        child_process.exec("ping -c 1 " + host, (err, stdout) => {
            res.end(stdout);
        });
    } else if (pathname === '/api/system/uptime') {
        // GT: id=SAST-NODE-018 type=FP reason=constant-argument-no-taint
        const out = child_process.execSync("uptime");
        res.end(out);
    } else if (pathname === '/api/files/download') {
        const filename = query.file || 'report.pdf';
        // GT: id=SAST-NODE-003 type=TP cwe=CWE-22 rule=path-traversal
        const data = fs.readFileSync(path.join(UPLOAD_DIR, filename));
        res.end(data);
    } else if (pathname === '/api/files/download-regex') {
        const filename = query.file || 'report.pdf';
        if (!/^[a-zA-Z0-9_\-]+\.pdf$/.test(filename)) {
            res.writeHead(400);
            return res.end('invalid filename');
        }
        // GT: id=SAST-NODE-016 type=FP reason=strict-regex-allowlist
        const data = fs.readFileSync(path.join(UPLOAD_DIR, filename));
        res.end(data);
    } else if (pathname === '/api/files/canonical') {
        const filename = query.file || 'safe.txt';
        const targetPath = path.resolve(BASE_DIR, filename);
        // GT: id=SAST-NODE-019 type=FP reason=canonicalized-path-base-check
        if (!targetPath.startsWith(path.resolve(BASE_DIR) + path.sep)) {
            res.writeHead(403);
            return res.end('access denied');
        }
        const data = fs.readFileSync(targetPath);
        res.end(data);
    } else if (pathname === '/api/remote/fetch') {
        const targetUrl = query.url || 'http://localhost:8080';
        // GT: id=SAST-NODE-004 type=TP cwe=CWE-918 rule=ssrf
        http.get(targetUrl, (clientRes) => {
            res.end('Proxied');
        });
    } else if (pathname === '/api/remote/safe-fetch') {
        const targetUrl = query.url || 'https://api.internal.service';
        const parsed = url.parse(targetUrl);
        if (parsed.protocol !== 'https:' || !ALLOWED_HOSTS.has(parsed.hostname)) {
            res.writeHead(403);
            return res.end('forbidden host');
        }
        // GT: id=SAST-NODE-027 type=FP reason=ssrf-allowlist-check
        http.get(targetUrl, (cRes) => {
            res.end('Safe fetch OK');
        });
    } else if (pathname === '/api/greet/raw') {
        const name = query.name || 'guest';
        // GT: id=SAST-NODE-005 type=TP cwe=CWE-79 rule=reflected-xss
        res.end("<h1>Hello " + name + "</h1>");
    } else if (pathname === '/api/greet/escaped') {
        const name = query.name || 'guest';
        // GT: id=SAST-NODE-017 type=FP reason=html-sanitized-output
        const safe = escapeHtml(name);
        res.end("<h1>Hello " + safe + "</h1>");
    } else if (pathname === '/api/eval/run') {
        const payload = query.data || '{}';
        // GT: id=SAST-NODE-006 type=TP cwe=CWE-94 rule=code-injection-eval
        const obj = eval("(" + payload + ")");
        res.end(JSON.stringify(obj));
    } else if (pathname === '/api/func/run') {
        const userCode = query.code || '42';
        // GT: id=SAST-NODE-012 type=TP cwe=CWE-94 rule=function-constructor-eval
        const fn = new Function("return " + userCode);
        res.end(String(fn()));
    } else if (pathname === '/api/auth/redirect') {
        const nextUrl = query.next || '/';
        // GT: id=SAST-NODE-007 type=TP cwe=CWE-601 rule=open-redirect
        res.writeHead(302, { Location: nextUrl });
        res.end();
    } else if (pathname === '/api/auth/safe-redirect') {
        const nextUrl = query.next || '/';
        // GT: id=SAST-NODE-031 type=FP reason=relative-path-enforcement
        const safeNext = (nextUrl.startsWith('/') && !nextUrl.startsWith('//')) ? nextUrl : '/';
        res.writeHead(302, { Location: safeNext });
        res.end();
    } else if (pathname === '/api/auth/hash-md5') {
        const pwd = query.pwd || '';
        // GT: id=SAST-NODE-008 type=TP cwe=CWE-328 rule=weak-crypto-hash
        const hash = crypto.createHash('md5').update(pwd).digest('hex');
        res.end(hash);
    } else if (pathname === '/api/cache/etag') {
        const content = query.content || '';
        // GT: id=SAST-NODE-020 type=FP reason=md5-used-for-non-security-checksum
        const etag = crypto.createHash('md5').update(content).digest('hex');
        res.end(etag);
    } else if (pathname === '/api/crypto/hardcoded') {
        // GT: id=SAST-NODE-009 type=TP cwe=CWE-321 rule=hardcoded-crypto-key
        const cipher = crypto.createCipheriv('aes-128-ecb', Buffer.from('1234567890123456'), null);
        res.end('cipher ready');
    } else if (pathname === '/api/crypto/des-mode') {
        // GT: id=SAST-NODE-013 type=TP cwe=CWE-326 rule=weak-des-cipher
        const cipher = crypto.createCipheriv('des-ecb', Buffer.from('12345678'), null);
        res.end('des cipher created');
    } else if (pathname === '/api/token/random') {
        // GT: id=SAST-NODE-010 type=TP cwe=CWE-330 rule=insecure-randomness
        const token = Math.random().toString(36).substring(2);
        res.end(token);
    } else if (pathname === '/api/token/secure') {
        // GT: id=SAST-NODE-028 type=FP reason=cryptographically-secure-randomness
        const token = crypto.randomBytes(32).toString('hex');
        res.end(token);
    } else if (pathname === '/api/tls/disable') {
        // GT: id=SAST-NODE-011 type=TP cwe=CWE-295 rule=disabled-tls-verification
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        res.end('TLS verify disabled');
    } else if (pathname === '/api/spawn/shell') {
        const userCmd = query.cmd || 'ls';
        // GT: id=SAST-NODE-014 type=TP cwe=CWE-78 rule=spawn-shell-injection
        child_process.spawn(userCmd, { shell: true });
        res.end('Spawned');
    } else if (pathname === '/api/json/parse') {
        // GT: id=SAST-NODE-024 type=FP reason=safe-json-deserialization
        const obj = JSON.parse('{"status":"ok"}');
        res.end(obj.status);
    } else if (pathname === '/api/items/filter') {
        const rawId = query.id || '1';
        // GT: id=SAST-NODE-025 type=FP reason=int-cast-breaks-taint
        const safeId = parseInt(rawId, 10);
        res.end("Item ID: " + safeId);
    } else if (pathname === '/api/admin/dead-code') {
        const cmd = query.cmd || '';
        // GT: id=SAST-NODE-021 type=FP reason=unreachable-dead-code
        if (false) {
            eval(cmd);
        }
        res.end('done');
    } else if (pathname === '/api/admin/feature-debug') {
        const cmd = query.cmd || '';
        // GT: id=SAST-NODE-026 type=FP reason=permanently-false-flag
        if (FEATURE_DEBUG_MODE && false) {
            child_process.execSync(cmd);
        }
        res.end('flag disabled');
    } else if (pathname === '/api/auth/pbkdf2') {
        const salt = crypto.randomBytes(16);
        // GT: id=SAST-NODE-029 type=FP reason=strong-pbkdf2-with-salt
        const derived = crypto.pbkdf2Sync('password', salt, 100000, 64, 'sha512');
        res.end(derived.toString('hex'));
    } else if (pathname === '/api/system/exec-file') {
        // GT: id=SAST-NODE-030 type=FP reason=list-args-shell-false
        child_process.execFile('ping', ['-c', '1', '127.0.0.1'], (err, stdout) => {
            res.end(stdout);
        });
    } else if (pathname === '/api/files/hosts') {
        // GT: id=SAST-NODE-032 type=FP reason=constant-file-path
        const data = fs.readFileSync('/etc/hosts');
        res.end(data);
    } else if (pathname === '/api/meta/headers') {
        // GT: id=SAST-NODE-022 type=FP reason=misleading-variable-name
        const passwordFieldHeader = 'X-User-Password-Header';
        res.end(passwordFieldHeader);
    } else {
        res.end('CodeSec Benchmark Node Server');
    }
});

// GT: id=SAST-NODE-023 type=FP reason=eval-in-comment-only
// eval(untrustedRequestBody);
function commentNotice() {}

if (require.main === module) {
    server.listen(3000, () => console.log('Server running on 3000'));
}
module.exports = server;
