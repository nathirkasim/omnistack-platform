/**
 * Reachability Test Fixture: Reachable Vulnerability
 * TP-REACH-001: lodash.merge called with untrusted user input
 * Vulnerability: CVE-2020-8203 (Prototype Pollution)
 * Expected: Reachable Vulnerability (High / Critical Reachability Finding)
 */
const _ = require('lodash');

function handleUserProfileUpdate(userPayload) {
    const defaultProfile = { theme: 'light', notifications: true };
    // Reachable: untrusted userPayload passed directly to vulnerable merge function
    return _.merge({}, defaultProfile, userPayload);
}

module.exports = { handleUserProfileUpdate };
