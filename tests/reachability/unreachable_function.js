/**
 * Reachability Test Fixture: Unreachable Functions
 * Covers TN-REACH-001 and TN-REACH-002.
 */
const _ = require('lodash');

// ==============================================================================
// TN-REACH-001: Vulnerable package present, but ONLY unaffected safe API called
// lodash is 4.17.15, but application only calls _.compact and _.isString
// Expected: SCA Detection (present), but Reachability = NOT REACHABLE / SAFE
// ==============================================================================
function sanitizeList(items) {
    if (!Array.isArray(items)) return [];
    return _.compact(items);
}

function checkType(val) {
    return _.isString(val);
}

// ==============================================================================
// TN-REACH-002: Vulnerable function exists in source but is unreachable (Dead Code)
// Vulnerable _.merge is referenced inside an unreachable dead conditional block
// Expected: Reachability = UNREACHABLE
// ==============================================================================
function processProductionData(inputData) {
    if (false) {
        // Dead code: never executed in any runtime path
        return _.merge({}, inputData);
    }
    return Object.assign({}, inputData);
}

module.exports = {
    sanitizeList,
    checkType,
    processProductionData,
};
