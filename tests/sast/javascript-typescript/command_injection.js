/**
 * SAST Test Fixture: Command Injection (Node.js)
 * Covers paired True Positives and False Positives.
 */
const { exec, execFile, spawn } = require('child_process');

// ==============================================================================
// TP-SAST-018: Command Injection via child_process.exec
// CWE-78 | Critical Severity
// ==============================================================================
function convertImageVulnerable(userFilename) {
    // Vulnerable: Concatenating untrusted argument to shell string
    exec(`convert input.png -resize 100x100 ${userFilename}`, (err, stdout) => {
        if (err) console.error(err);
    });
}

// ==============================================================================
// FP-SAST-026: Safe Command Execution via execFile (No Shell)
// Expected: Safe / No detection
// ==============================================================================
function convertImageSafe(userFilename) {
    // Safe: Invokes binary directly without shell interpretation; arguments are isolated
    execFile('convert', ['input.png', '-resize', '100x100', userFilename], (err, stdout) => {
        if (err) console.error(err);
    });
}

// ==============================================================================
// FP-SAST-027: Safe Process Spawn with Static Arguments
// Expected: Safe / Fixed commands
// ==============================================================================
function runGitStatusSafe() {
    // Safe: Static trusted command, no user input
    return spawn('git', ['status', '--porcelain']);
}

module.exports = {
    convertImageVulnerable,
    convertImageSafe,
    runGitStatusSafe,
};
