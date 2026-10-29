/**
 * Reachability Test Fixture: Patched / Safe Dependency Version
 * TN-REACH-003: Safe, patched version of dependency installed (e.g. lodash >= 4.17.21 or safe native API)
 * Expected: SCA = Safe / No CVE match, Reachability = Safe
 */

// Simulating safe call to patched package or modern standard object utility
function safeObjectMerge(base, updates) {
    // In patched lodash (4.17.21+) or standard modern JS, prototype pollution on Object.prototype is blocked
    return Object.assign({}, base, updates);
}

module.exports = { safeObjectMerge };
