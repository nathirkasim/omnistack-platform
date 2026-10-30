const express = require('express');
const multer = require('multer');
const path = require('path');
const app = express();

const storage = multer.diskStorage({
    destination: '/var/www/uploads/',
    filename: (req, file, cb) => {
        // VULNERABLE: Preserving original filename allows uploading executable scripts (.php, .js) directly to webroot (CWE-434)
        cb(null, file.originalname);
    }
});
const upload = multer({ storage: storage });

app.post('/upload', upload.single('document'), (req, res) => {
    res.send('File uploaded successfully');
});
