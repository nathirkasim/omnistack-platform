/**
 * Sanitizer and validator utilities for Node.js Deep Taint Analysis
 */

const path = require('path');

function noopSanitize(inStr) {
    return inStr;
}

function wrongContextSanitize(inStr) {
    if (!inStr) return '';
    return inStr.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function bypassableBlocklist(inStr) {
    return inStr ? inStr.replace(/\.\.\//g, '') : '';
}

function strictAlphaNumeric(inStr) {
    return /^[a-zA-Z0-9_\-]+$/.test(inStr);
}

function isSafeCanonicalPath(baseDir, filename) {
    const full = path.resolve(baseDir, filename);
    return full.startsWith(path.resolve(baseDir) + path.sep);
}

module.exports = {
    noopSanitize,
    wrongContextSanitize,
    bypassableBlocklist,
    strictAlphaNumeric,
    isSafeCanonicalPath
};

