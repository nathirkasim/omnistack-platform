/**
 * Service orchestration layer for Node.js Deep Taint Analysis
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const child_process = require('child_process');
const { OrderRepository } = require('./repository');
const {
    noopSanitize,
    wrongContextSanitize,
    bypassableBlocklist,
    strictAlphaNumeric,
    isSafeCanonicalPath
} = require('./sanitizer');

class StatefulTaskService {
    constructor() {
        this.pendingCmd = '';
        this.sanitizedField = '';
    }

    stageCommand(cmd) {
        this.pendingCmd = cmd;
    }

    stageSafeField(field) {
        this.sanitizedField = strictAlphaNumeric(field) ? field : 'safe_default';
    }

    dispatchPending() {
        // GT: id=TAINT-NODE-002 type=TP cwe=CWE-78 rule=class-field-taint-exec
        return child_process.execSync(this.pendingCmd).toString();
    }

    dispatchSafe() {
        // GT: id=TAINT-NODE-012 type=FP reason=sanitized-class-field-exec
        return child_process.execFileSync('echo', [this.sanitizedField]).toString();
    }
}

class OrderService {
    constructor() {
        this.repo = new OrderRepository();
    }

    async processOrderFilter(rawFilter) {
        return this._stepOne(rawFilter);
    }

    async _stepOne(f) {
        return this._stepTwo(f);
    }

    async _stepTwo(f) {
        return this.repo.executeRawSql(f);
    }

    async processSafeOrder(rawId) {
        return this.repo.executeParameterized(rawId);
    }

    fetchWithNoop(rawUrl) {
        const cleaned = noopSanitize(rawUrl);
        // GT: id=TAINT-NODE-006 type=TP cwe=CWE-918 rule=noop-sanitizer-ssrf
        http.get(cleaned, () => {});
    }

    fetchWithAllowlist(rawUrl) {
        const parsed = new URL(rawUrl);
        if (parsed.hostname !== 'api.internal.service') {
            return;
        }
        // GT: id=TAINT-NODE-017 type=FP reason=strict-url-host-allowlist
        http.get(rawUrl, () => {});
    }

    async queryWithWrongSanitizer(userStr) {
        const escaped = wrongContextSanitize(userStr);
        // GT: id=TAINT-NODE-007 type=TP cwe=CWE-89 rule=wrong-context-sanitizer-sqli
        return this.repo.executeRawSql(escaped);
    }

    readWithBypassableBlocklist(baseDir, filename) {
        const cleaned = bypassableBlocklist(filename);
        // GT: id=TAINT-NODE-009 type=TP cwe=CWE-22 rule=bypassable-blocklist-traversal
        return fs.readFileSync(path.join(baseDir, cleaned));
    }

    readWithCanonicalCheck(baseDir, filename) {
        if (!isSafeCanonicalPath(baseDir, filename)) {
            return null;
        }
        // GT: id=TAINT-NODE-018 type=FP reason=canonical-validator-path-traversal
        return fs.readFileSync(path.join(baseDir, filename));
    }
}

module.exports = { StatefulTaskService, OrderService };

