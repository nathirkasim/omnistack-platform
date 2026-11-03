/**
 * Obfuscation and Evasion Twin Pairs (Node.js SAST)
 */

const child_process = require('child_process');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');

const mockDb = {
    query: (sql) => Promise.resolve([])
};

// --- Pair 1: Command Injection ---
function cmdPlain(cmd) {
    // GT: id=EVASION-NODE-001 type=TP cwe=CWE-78 rule=command-injection technique=plain pair_id=EVASION-NODE-002
    return child_process.exec(cmd);
}

function cmdEvasion(cmd) {
    // GT: id=EVASION-NODE-002 type=TP cwe=CWE-78 rule=command-injection technique=computed-property-require pair_id=EVASION-NODE-001
    const cp = require('child_' + 'process');
    const method = 'ex' + 'ec';
    return cp[method](cmd);
}

// --- Pair 2: SQL Injection ---
function sqliPlain(id) {
    // GT: id=EVASION-NODE-003 type=TP cwe=CWE-89 rule=sql-injection technique=plain pair_id=EVASION-NODE-004
    return mockDb.query("SELECT * FROM users WHERE id = '" + id + "'");
}

function sqliEvasion(id) {
    // GT: id=EVASION-NODE-004 type=TP cwe=CWE-89 rule=sql-injection technique=array-join-string-concat pair_id=EVASION-NODE-003
    const q = ["SELECT * FROM users WHERE id = '", id, "'"].join('');
    return mockDb.query(q);
}

// --- Pair 3: Code Injection / Eval ---
function evalPlain(userCode) {
    // GT: id=EVASION-NODE-005 type=TP cwe=CWE-94 rule=code-injection-eval technique=plain pair_id=EVASION-NODE-006
    return eval(userCode);
}

function evalEvasion(userCode) {
    // GT: id=EVASION-NODE-006 type=TP cwe=CWE-94 rule=code-injection-eval technique=global-scope-computed-access pair_id=EVASION-NODE-005
    const runner = global['ev' + 'al'];
    return runner(userCode);
}

// --- Pair 4: Path Traversal ---
function pathPlain(filename) {
    // GT: id=EVASION-NODE-007 type=TP cwe=CWE-22 rule=path-traversal technique=plain pair_id=EVASION-NODE-008
    return fs.readFileSync("/tmp/storage/" + filename);
}

function pathEvasion(filename) {
    // GT: id=EVASION-NODE-008 type=TP cwe=CWE-22 rule=path-traversal technique=object-property-dynamic-read pair_id=EVASION-NODE-007
    const fnName = ['readFile', 'Sync'].join('');
    return fs[fnName]("/tmp/storage/" + filename);
}

// --- Pair 5: SSRF ---
function ssrfPlain(targetUrl) {
    // GT: id=EVASION-NODE-009 type=TP cwe=CWE-918 rule=ssrf technique=plain pair_id=EVASION-NODE-010
    return http.get(targetUrl);
}

function ssrfEvasion(targetUrl) {
    // GT: id=EVASION-NODE-010 type=TP cwe=CWE-918 rule=ssrf technique=dynamic-http-module-dispatch pair_id=EVASION-NODE-009
    const mod = require('ht' + 'tp');
    const getFn = mod['g' + 'et'];
    return getFn(targetUrl);
}

// --- Pair 6: Reflected XSS ---
function xssPlain(res, name) {
    // GT: id=EVASION-NODE-011 type=TP cwe=CWE-79 rule=reflected-xss technique=plain pair_id=EVASION-NODE-012
    res.end("<div>Hello " + name + "</div>");
}

function xssEvasion(res, name) {
    // GT: id=EVASION-NODE-012 type=TP cwe=CWE-79 rule=reflected-xss technique=template-array-join pair_id=EVASION-NODE-011
    const body = ['<div>Hello ', name, '</div>'].join('');
    res.end(body);
}

// --- Pair 7: Weak Crypto Hash ---
function hashPlain(pwd) {
    // GT: id=EVASION-NODE-013 type=TP cwe=CWE-328 rule=weak-crypto-hash technique=plain pair_id=EVASION-NODE-014
    return crypto.createHash('md5').update(pwd).digest('hex');
}

function hashEvasion(pwd) {
    // GT: id=EVASION-NODE-014 type=TP cwe=CWE-328 rule=weak-crypto-hash technique=computed-algorithm-identifier pair_id=EVASION-NODE-013
    const algo = ['m', 'd', '5'].join('');
    return crypto.createHash(algo).update(pwd).digest('hex');
}

// --- Pair 8: Open Redirect ---
function redirectPlain(res, nextUrl) {
    // GT: id=EVASION-NODE-015 type=TP cwe=CWE-601 rule=open-redirect technique=plain pair_id=EVASION-NODE-016
    res.writeHead(302, { Location: nextUrl });
    res.end();
}

function redirectEvasion(res, nextUrl) {
    // GT: id=EVASION-NODE-016 type=TP cwe=CWE-601 rule=open-redirect technique=computed-header-name-set pair_id=EVASION-NODE-015
    const headerKey = ['Loc', 'ation'].join('');
    res.setHeader(headerKey, nextUrl);
    res.statusCode = 302;
    res.end();
}

module.exports = {
    cmdPlain, cmdEvasion,
    sqliPlain, sqliEvasion,
    evalPlain, evalEvasion,
    pathPlain, pathEvasion,
    ssrfPlain, ssrfEvasion,
    xssPlain, xssEvasion,
    hashPlain, hashEvasion,
    redirectPlain, redirectEvasion
};
