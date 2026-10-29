/**
 * Reachability Test Fixture: Defended / Sanitized Call Path
 * TN-REACH-005: lodash.merge called, but input is strictly sanitized/validated against prototype pollution
 * Expected: Reachable syntactic call, but exploit path neutralized (Safe / Guarded)
 */
const _ = require('lodash');

function hasPrototypePollutionKeys(obj) {
    if (typeof obj !== 'object' || obj === null) return false;
    for (const key of Object.keys(obj)) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            return true;
        }
        if (typeof obj[key] === 'object' && hasPrototypePollutionKeys(obj[key])) {
            return true;
        }
    }
    return false;
}

function safeMergeUserData(untrustedData) {
    // Defense: strictly check and reject any payload attempting prototype pollution
    if (hasPrototypePollutionKeys(untrustedData)) {
        throw new Error('SecurityException: Prototype pollution payload rejected');
    }

    const baseConfig = { role: 'user' };
    return _.merge({}, baseConfig, untrustedData);
}

module.exports = { safeMergeUserData };
