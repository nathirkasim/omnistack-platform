const express = require('express');
const app = express();

app.get('/profile', (req, res) => {
    const username = req.query.name || 'Anonymous';
    // VULNERABLE: Reflecting unescaped user input into HTML document (CWE-79)
    res.send(`<html><body><h1>User Profile: ${username}</h1></body></html>`);
});

app.get('/login/redirect', (req, res) => {
    const returnUrl = req.query.next;
    // VULNERABLE: Unvalidated redirect to attacker-controlled external destination (CWE-601)
    res.redirect(returnUrl);
});
