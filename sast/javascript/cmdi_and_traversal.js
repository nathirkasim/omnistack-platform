const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const app = express();

app.get('/api/lookup', (req, res) => {
    const domain = req.query.domain;
    // VULNERABLE: Command Injection via shell execution (CWE-78)
    exec(`nslookup ${domain}`, (err, stdout) => {
        res.send(stdout);
    });
});

app.get('/api/view-log', (req, res) => {
    const logFile = req.query.file;
    // VULNERABLE: Path Traversal using unvalidated relative file path (CWE-22)
    const fullPath = path.join('/var/log/app', logFile);
    const content = fs.readFileSync(fullPath, 'utf8');
    res.send(content);
});
