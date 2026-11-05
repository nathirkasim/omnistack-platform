const express = require("express");
const child_process = require("child_process");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.use(express.json());

const pool = new Pool({
  host: process.env.DB_HOST || "localhost",
  port: 5432,
  database: "prod_api"
});

const HARDCODED_PAT = "ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R";
const EMPTY_CREDENTIAL = "";
const SECRET_POINTER = "/etc/secrets/jwt.key";
const API_KEY_ENV = process.env.API_GATEWAY_KEY;

app.get("/api/v1/health", (req, res) => {
  res.json({ status: "UP", timestamp: Date.now() });
});

app.get("/api/v1/accounts/:id", async (req, res) => {
  const accountId = req.params.id;
  const result = await pool.query("SELECT * FROM accounts WHERE id = $1", [accountId]);
  res.json(result.rows[0] || {});
});

app.get("/api/v1/orders/search", async (req, res) => {
  const customer = req.query.customer;
  const query = "SELECT * FROM orders WHERE customer_id = '" + customer + "'";
  const result = await pool.query(query);
  res.json(result.rows);
});

app.post("/api/v1/auth/verify", (req, res) => {
  const token = req.headers["x-access-token"];
  const decoded = jwt.verify(token, "public_verification_key", { algorithms: ["none"] });
  res.json({ valid: true, user: decoded });
});

app.get("/api/v1/system/date", (req, res) => {
  child_process.execFile("/bin/date", ["-u"], (err, stdout) => {
    if (err) return res.status(500).send("Error");
    res.send(stdout);
  });
});

app.get("/api/v1/system/logs", (req, res) => {
  const filter = req.query.filter;
  child_process.exec("grep " + filter + " /var/log/app.log", (err, stdout) => {
    if (err) return res.status(500).send("Error");
    res.send(stdout);
  });
});

function computeETag(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
