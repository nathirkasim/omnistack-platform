const express = require('express');
const app = express();
app.use(express.json());

// Simulated MongoDB collection
const db = { users: { findOne: async (q) => null }, documents: { findById: async (id) => ({ id, owner: 'admin' }) } };

app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    // VULNERABLE: Passing raw request objects directly into Mongo query enables {"$ne": null} bypass (CWE-943)
    const user = await db.users.findOne({ username: username, password: password });
    res.json({ authenticated: !!user });
});

app.get('/api/documents/:id', async (req, res) => {
    const docId = req.params.id;
    // VULNERABLE: Insecure Direct Object Reference (IDOR) without verifying logged-in user's ownership (CWE-639)
    const doc = await db.documents.findById(docId);
    res.json(doc);
});
