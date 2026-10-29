/**
 * Reachability Test Fixture: Transitive Reachability & DevDependency Isolation
 * Covers TP-REACH-002 and TN-REACH-004.
 */
const axios = require('axios');

// ==============================================================================
// TP-REACH-002: Transitive Dependency Reachable
// axios 0.21.0 depends transitively on follow-redirects
// When followRedirects is triggered with user-supplied URL, transitive CVE is reached
// ==============================================================================
async function fetchWebhookContent(userSuppliedUrl) {
    // Reaches transitive follow-redirects module
    return await axios.get(userSuppliedUrl, {
        maxRedirects: 5,
    });
}

// ==============================================================================
// TN-REACH-004: Vulnerable package in devDependencies only
// minimist 1.2.5 (CVE-2020-7598) is in devDependencies for test runner script only
// Not imported or referenced in production code
// Expected: Reachability = Dev-only / Not reachable in production
// ==============================================================================
function productionLogic() {
    return { status: 'healthy' };
}

module.exports = {
    fetchWebhookContent,
    productionLogic,
};
