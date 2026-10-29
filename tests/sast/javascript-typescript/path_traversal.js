/**
 * SAST Test Fixture: Path Traversal (Node.js)
 * Covers paired True Positives and False Positives.
 */
const fs = require('fs');
const path = require('path');

const UPLOADS_DIR = '/var/www/uploads';

// ==============================================================================
// TP-SAST-019: Path Traversal via unvalidated path.join
// CWE-22 | High Severity
// ==============================================================================
function serveUserFileVulnerable(userFilename, res) {
    // Vulnerable: path.join allows traversal if userFilename contains "../"
    const filePath = path.join(UPLOADS_DIR, userFilename);
    fs.readFile(filePath, (err, data) => {
        if (err) return res.status(404).send('Not found');
        res.send(data);
    });
}

// ==============================================================================
// FP-SAST-028: Safe Path Traversal Defense via path.resolve & prefix boundary
// Expected: Safe / No detection
// ==============================================================================
function serveUserFileSafe(userFilename, res) {
    const safeBase = path.resolve(UPLOADS_DIR);
    const resolvedPath = path.resolve(safeBase, userFilename);

    // Safe: Guard condition verifies target path is inside safe directory
    if (!resolvedPath.startsWith(safeBase + path.sep)) {
        return res.status(403).send('Forbidden: invalid path');
    }

    fs.readFile(resolvedPath, (err, data) => {
        if (err) return res.status(404).send('Not found');
        res.send(data);
    });
}

// ==============================================================================
// FP-SAST-029: Static relative file path used in test fixture
// Expected: Safe (harmless relative path in local build/test context)
// ==============================================================================
function loadLocalConfig() {
    const configPath = path.resolve(__dirname, '../config/settings.json');
    return fs.readFileSync(configPath, 'utf8');
}

module.exports = {
    serveUserFileVulnerable,
    serveUserFileSafe,
    loadLocalConfig,
};
