from typing import List
from .base import FixtureBuilder, TargetLine

def generate_l3_cases() -> List[FixtureBuilder]:
    fixtures: List[FixtureBuilder] = []

    # =============================================================
    # 1. Flask Production Microservice (Python)
    # =============================================================
    fb = FixtureBuilder("l3_advanced/flask_service/app.py")
    fb.add('import ast')
    fb.add('import hashlib')
    fb.add('import logging')
    fb.add('import os')
    fb.add('import random')
    fb.add('import sqlite3')
    fb.add('import yaml')
    fb.add('from flask import Flask, jsonify, request').add()
    fb.add('logging.basicConfig(level=logging.INFO)')
    fb.add('logger = logging.getLogger("auth_service")').add()
    fb.add('app = Flask(__name__)')
    fb.add_target(
        'DATABASE_URI = "postgres://admin:S3cr3tP4ss@db.internal:5432/app"',
        "FLAG", "SECRETS", "L3_ADVANCED", "L3-FLASK-001",
        "Cleartext database credentials embedded in connection string"
    )
    fb.add_target(
        'DATABASE_URI_DEV = "postgres://user:password@localhost/db"',
        "DEBATABLE", "SECRETS", "L3_ADVANCED", "L3-FLASK-002",
        "Local development database URI with standard dummy credentials"
    )
    fb.add_target(
        'app.config["SECRET_KEY_PATH"] = "/var/run/secrets/flask_secret"',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-FLASK-003",
        "Secret file path pointer in application configuration"
    )
    fb.add_target(
        'app.config["TOKEN_PLACEHOLDER"] = "REPLACE_ME"',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-FLASK-004",
        "Standard documentation template placeholder string"
    )
    fb.add_target(
        'app.config["EMPTY_PASSWORD"] = ""',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-FLASK-005",
        "Empty string password configuration variable"
    )
    fb.add().add('def get_db_connection():')
    fb.add('    conn = sqlite3.connect(":memory:")')
    fb.add('    conn.row_factory = sqlite3.Row')
    fb.add('    return conn').add()
    fb.add('@app.route("/health", methods=["GET"])')
    fb.add('def health_check():')
    fb.add('    return jsonify({"status": "healthy", "service": "user-auth"})').add()
    fb.add('@app.route("/api/v1/users/<int:user_id>", methods=["GET"])')
    fb.add('def get_user_profile(user_id):')
    fb.add('    conn = get_db_connection()')
    fb.add('    cursor = conn.cursor()')
    fb.add_target(
        '    cursor.execute("SELECT id, username, email FROM users WHERE id = %s", (user_id,))',
        "NO_FLAG", "SAST", "L3_ADVANCED", "L3-FLASK-006",
        "Secure parameterized query using tuple substitution"
    )
    fb.add('    row = cursor.fetchone()')
    fb.add('    conn.close()')
    fb.add('    if not row:')
    fb.add('        return jsonify({"error": "User not found"}), 404')
    fb.add('    return jsonify(dict(row))').add()
    fb.add('@app.route("/api/v1/search", methods=["POST"])')
    fb.add('def search_users():')
    fb.add('    query = request.json.get("query", "")')
    fb.add('    conn = get_db_connection()')
    fb.add('    cursor = conn.cursor()')
    fb.add_target(
        '    cursor.execute("SELECT id, username FROM users WHERE username = \'%s\'" % query)',
        "FLAG", "SAST", "L3_ADVANCED", "L3-FLASK-007",
        "SQL injection via string interpolation in user search route"
    )
    fb.add('    rows = cursor.fetchall()')
    fb.add('    conn.close()')
    fb.add('    return jsonify([dict(r) for r in rows])').add()
    fb.add('@app.route("/api/v1/config/parse", methods=["POST"])')
    fb.add('def parse_user_config():')
    fb.add('    payload = request.data.decode("utf-8")')
    fb.add_target(
        '    data = yaml.safe_load(payload)',
        "NO_FLAG", "SAST", "L3_ADVANCED", "L3-FLASK-008",
        "Safe YAML deserializer restricted to declarative types"
    )
    fb.add('    return jsonify({"parsed": bool(data)})').add()
    fb.add('@app.route("/api/v1/login", methods=["POST"])')
    fb.add('def login():')
    fb.add('    username = request.json.get("username", "")')
    fb.add('    password = request.json.get("password", "")')
    fb.add_target(
        '    field_name = "password"',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-FLASK-009",
        "Authentication field identifier string"
    )
    fb.add_target(
        '    logger.info("Login attempt for user: %s", username)',
        "NO_FLAG", "SAST", "L3_ADVANCED", "L3-FLASK-010",
        "Safe logging of username without sensitive credentials"
    )
    fb.add('    conn = get_db_connection()')
    fb.add('    cursor = conn.cursor()')
    fb.add('    cursor.execute("SELECT id, password_hash FROM accounts WHERE username = ?", (username,))')
    fb.add('    account = cursor.fetchone()')
    fb.add('    conn.close()')
    fb.add('    if not account:')
    fb.add('        return jsonify({"authenticated": False}), 401')
    fb.add('    return jsonify({"authenticated": True})').add()
    fb.add('def generate_metrics():')
    fb.add_target(
        '    metric_hash = hashlib.sha256(b"sample_data").hexdigest()',
        "NO_FLAG", "SAST", "L3_ADVANCED", "L3-FLASK-011",
        "SHA-256 digest computation for data integrity"
    )
    fb.add_target(
        '    palette = ["#4f46e5", "#06b6d4", "#10b981"]',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-FLASK-012",
        "CSS hex color codes in cosmetic palette list"
    )
    fb.add_target(
        '    selected_color = random.choice(palette)',
        "NO_FLAG", "SAST", "L3_ADVANCED", "L3-FLASK-013",
        "Non-security random selection for theme presentation"
    )
    fb.add('    return {"hash": metric_hash, "color": selected_color}').add()
    fb.add('if __name__ == "__main__":')
    fb.add_target(
        '    app.run(host="0.0.0.0", port=5000, debug=True)',
        "FLAG", "SAST", "L3_ADVANCED", "L3-FLASK-014",
        "Flask development server run on all interfaces with debug mode enabled"
    )
    fixtures.append(fb)

    # =============================================================
    # 2. Express.js Production API (JavaScript)
    # =============================================================
    fb = FixtureBuilder("l3_advanced/express_api/server.js")
    fb.add('const express = require("express");')
    fb.add('const child_process = require("child_process");')
    fb.add('const crypto = require("crypto");')
    fb.add('const jwt = require("jsonwebtoken");')
    fb.add('const { Pool } = require("pg");').add()
    fb.add('const app = express();')
    fb.add('app.use(express.json());').add()
    fb.add('const pool = new Pool({')
    fb.add('  host: process.env.DB_HOST || "localhost",')
    fb.add('  port: 5432,')
    fb.add('  database: "prod_api"')
    fb.add('});').add()
    fb.add_target(
        'const HARDCODED_PAT = "ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R";',
        "FLAG", "SECRETS", "L3_ADVANCED", "L3-EXPRESS-001",
        "Personal access token hardcoded in API setup"
    )
    fb.add_target(
        'const EMPTY_CREDENTIAL = "";',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-EXPRESS-002",
        "Empty string credential definition"
    )
    fb.add_target(
        'const SECRET_POINTER = "/etc/secrets/jwt.key";',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-EXPRESS-003",
        "Filesystem reference string for signing key storage"
    )
    fb.add_target(
        'const API_KEY_ENV = process.env.API_GATEWAY_KEY;',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-EXPRESS-004",
        "Dynamic environment variable lookup for API key"
    )
    fb.add().add('app.get("/api/v1/health", (req, res) => {')
    fb.add('  res.json({ status: "UP", timestamp: Date.now() });')
    fb.add('});').add()
    fb.add('app.get("/api/v1/accounts/:id", async (req, res) => {')
    fb.add('  const accountId = req.params.id;')
    fb.add_target(
        '  const result = await pool.query("SELECT * FROM accounts WHERE id = $1", [accountId]);',
        "NO_FLAG", "SAST", "L3_ADVANCED", "L3-EXPRESS-005",
        "Parameterized Postgres query protecting against SQL injection"
    )
    fb.add('  res.json(result.rows[0] || {});')
    fb.add('});').add()
    fb.add('app.get("/api/v1/orders/search", async (req, res) => {')
    fb.add('  const customer = req.query.customer;')
    fb.add_target(
        '  const query = "SELECT * FROM orders WHERE customer_id = \'" + customer + "\'";',
        "FLAG", "SAST", "L3_ADVANCED", "L3-EXPRESS-006",
        "SQL query concatenation vulnerability in search handler"
    )
    fb.add('  const result = await pool.query(query);')
    fb.add('  res.json(result.rows);')
    fb.add('});').add()
    fb.add('app.post("/api/v1/auth/verify", (req, res) => {')
    fb.add('  const token = req.headers["x-access-token"];')
    fb.add_target(
        '  const decoded = jwt.verify(token, "public_verification_key", { algorithms: ["none"] });',
        "FLAG", "SAST", "L3_ADVANCED", "L3-EXPRESS-007",
        "JWT signature verification bypassed using algorithms: none"
    )
    fb.add('  res.json({ valid: true, user: decoded });')
    fb.add('});').add()
    fb.add('app.get("/api/v1/system/date", (req, res) => {')
    fb.add_target(
        '  child_process.execFile("/bin/date", ["-u"], (err, stdout) => {',
        "NO_FLAG", "SAST", "L3_ADVANCED", "L3-EXPRESS-008",
        "Safe binary execution via execFile without shell wrapping"
    )
    fb.add('    if (err) return res.status(500).send("Error");')
    fb.add('    res.send(stdout);')
    fb.add('  });')
    fb.add('});').add()
    fb.add('app.get("/api/v1/system/logs", (req, res) => {')
    fb.add('  const filter = req.query.filter;')
    fb.add_target(
        '  child_process.exec("grep " + filter + " /var/log/app.log", (err, stdout) => {',
        "FLAG", "SAST", "L3_ADVANCED", "L3-EXPRESS-009",
        "Command injection via string concatenation in child_process.exec"
    )
    fb.add('    if (err) return res.status(500).send("Error");')
    fb.add('    res.send(stdout);')
    fb.add('  });')
    fb.add('});').add()
    fb.add('function computeETag(data) {')
    fb.add_target(
        '  return crypto.createHash("sha256").update(data).digest("hex");',
        "NO_FLAG", "SAST", "L3_ADVANCED", "L3-EXPRESS-010",
        "Cryptographically sound SHA-256 digest computation"
    )
    fb.add('}').add()
    fb.add('const PORT = process.env.PORT || 3000;')
    fb.add('app.listen(PORT, () => {')
    fb.add('  console.log(`Server listening on port ${PORT}`);')
    fb.add('});')
    fixtures.append(fb)

    # =============================================================
    # 3. Go HTTP Microservice (Go)
    # =============================================================
    fb = FixtureBuilder("l3_advanced/go_microservice/main.go")
    fb.add('package main').add()
    fb.add('import (')
    fb.add('	"context"')
    fb.add('	"crypto/tls"')
    fb.add('	"database/sql"')
    fb.add('	"fmt"')
    fb.add('	"log"')
    fb.add('	"net/http"')
    fb.add('	"os"')
    fb.add('	"os/exec"')
    fb.add('	"time"')
    fb.add(')').add()
    fb.add('type AppConfig struct {')
    fb.add('	Port string')
    fb.add('	DBUrl string')
    fb.add('}').add()
    fb.add('func healthHandler(w http.ResponseWriter, r *http.Request) {')
    fb.add('	w.WriteHeader(http.StatusOK)')
    fb.add('	_, _ = w.Write([]byte(`{"status":"UP"}`))')
    fb.add('}').add()
    fb.add('func queryUserSafe(ctx context.Context, db *sql.DB, uid string) error {')
    fb.add_target(
        '	row := db.QueryRowContext(ctx, "SELECT email FROM users WHERE id = $1", uid)',
        "NO_FLAG", "SAST", "L3_ADVANCED", "L3-GO-001",
        "Safe parameterized SQL query execution in Go"
    )
    fb.add('	var email string')
    fb.add('	return row.Scan(&email)')
    fb.add('}').add()
    fb.add('func queryUserUnsafe(ctx context.Context, db *sql.DB, uid string) (*sql.Rows, error) {')
    fb.add_target(
        '	query := fmt.Sprintf("SELECT email FROM users WHERE id = \'%s\'", uid)',
        "FLAG", "SAST", "L3_ADVANCED", "L3-GO-002",
        "SQL injection constructed via fmt.Sprintf interpolation"
    )
    fb.add('	return db.QueryContext(ctx, query)')
    fb.add('}').add()
    fb.add('func executeUptime() error {')
    fb.add_target(
        '	cmd := exec.Command("/usr/bin/uptime")',
        "NO_FLAG", "SAST", "L3_ADVANCED", "L3-GO-003",
        "Direct invocation of system executable with fixed argument path"
    )
    fb.add('	return cmd.Run()')
    fb.add('}').add()
    fb.add('func executeDynamicShell(input string) error {')
    fb.add_target(
        '	cmd := exec.Command("sh", "-c", input)',
        "FLAG", "SAST", "L3_ADVANCED", "L3-GO-004",
        "Arbitrary shell execution using command interpreter with dynamic input"
    )
    fb.add('	return cmd.Run()')
    fb.add('}').add()
    fb.add('func createInsecureTransport() *http.Transport {')
    fb.add('	return &http.Transport{')
    fb.add('		TLSClientConfig: &tls.Config{')
    fb.add_target(
        '			InsecureSkipVerify: true,',
        "FLAG", "SAST", "L3_ADVANCED", "L3-GO-005",
        "Insecure TLS transport configuration skipping server certificate checks"
    )
    fb.add('		},')
    fb.add('	}')
    fb.add('}').add()
    fb.add('func main() {')
    fb.add_target(
        '	apiKey := os.Getenv("API_SECRET_KEY")',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-GO-006",
        "Secure environment lookup for service secret key"
    )
    fb.add('	if apiKey == "" {')
    fb.add('		log.Println("API key unset")')
    fb.add('	}')
    fb.add('	mux := http.NewServeMux()')
    fb.add('	mux.HandleFunc("/health", healthHandler)')
    fb.add('	server := &http.Server{')
    fb.add('		Addr:         ":8080",')
    fb.add('		Handler:      mux,')
    fb.add('		ReadTimeout:  5 * time.Second,')
    fb.add('		WriteTimeout: 10 * time.Second,')
    fb.add('	}')
    fb.add('	log.Fatal(server.ListenAndServe())')
    fb.add('}')
    fixtures.append(fb)

    # =============================================================
    # 4. Django Production Settings (Python)
    # =============================================================
    fb = FixtureBuilder("l3_advanced/django_portal/settings.py")
    fb.add('import os')
    fb.add('from pathlib import Path').add()
    fb.add('BASE_DIR = Path(__file__).resolve().parent.parent').add()
    fb.add_target(
        'SECRET_KEY = "django-insecure-wJalrXUtnFEMI/K7MDENG/bPxRfiCYz8947KlMnP"',
        "FLAG", "SECRETS", "L3_ADVANCED", "L3-DJANGO-001",
        "Hardcoded Django production secret key literal"
    )
    fb.add_target(
        'DEBUG = True',
        "FLAG", "SAST", "L3_ADVANCED", "L3-DJANGO-002",
        "Production settings file with DEBUG mode set to True"
    )
    fb.add_target(
        'ALLOWED_HOSTS = ["*"]',
        "FLAG", "SAST", "L3_ADVANCED", "L3-DJANGO-003",
        "Wildcard ALLOWED_HOSTS opening portal to host header poisoning"
    )
    fb.add().add('INSTALLED_APPS = [')
    fb.add('    "django.contrib.admin",')
    fb.add('    "django.contrib.auth",')
    fb.add('    "django.contrib.contenttypes",')
    fb.add('    "django.contrib.sessions",')
    fb.add('    "django.contrib.messages",')
    fb.add('    "django.contrib.staticfiles",')
    fb.add(']').add()
    fb.add('MIDDLEWARE = [')
    fb.add('    "django.middleware.security.SecurityMiddleware",')
    fb.add('    "django.contrib.sessions.middleware.SessionMiddleware",')
    fb.add('    "django.middleware.common.CommonMiddleware",')
    fb.add('    "django.middleware.csrf.CsrfViewMiddleware",')
    fb.add('    "django.contrib.auth.middleware.AuthenticationMiddleware",')
    fb.add('    "django.contrib.messages.middleware.MessageMiddleware",')
    fb.add(']').add()
    fb.add('ROOT_URLCONF = "portal.urls"')
    fb.add('WSGI_APPLICATION = "portal.wsgi.application"').add()
    fb.add('DATABASES = {')
    fb.add('    "default": {')
    fb.add('        "ENGINE": "django.db.backends.sqlite3",')
    fb.add('        "NAME": BASE_DIR / "db.sqlite3",')
    fb.add('    }')
    fb.add('}').add()
    fb.add('AUTH_PASSWORD_VALIDATORS = [')
    fb.add_target(
        '    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-DJANGO-004",
        "Django password validation framework class reference"
    )
    fb.add('    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},')
    fb.add(']').add()
    fb.add('LANGUAGE_CODE = "en-us"')
    fb.add('TIME_ZONE = "UTC"')
    fb.add('USE_I18N = True')
    fb.add('USE_TZ = True').add()
    fb.add_target(
        'PASSWORD_RESET_TIMEOUT = 3600',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-DJANGO-005",
        "Integer configuration timeout for password reset token"
    )
    fb.add_target(
        'STATIC_URL = "/static/"',
        "NO_FLAG", "SAST", "L3_ADVANCED", "L3-DJANGO-006",
        "Static asset routing URL path prefix"
    )
    fixtures.append(fb)

    # =============================================================
    # 5. Spring Boot Application Config (Java)
    # =============================================================
    fb = FixtureBuilder("l3_advanced/spring_backend/ApplicationConfig.java")
    fb.add('package com.example.backend;')
    fb.add('import java.security.MessageDigest;')
    fb.add('import java.sql.Connection;')
    fb.add('import java.sql.PreparedStatement;')
    fb.add('import java.sql.Statement;')
    fb.add('import java.sql.ResultSet;')
    fb.add('import java.sql.SQLException;').add()
    fb.add('public class ApplicationConfig {')
    fb.add('    private final Connection connection;').add()
    fb.add('    public ApplicationConfig(Connection connection) {')
    fb.add('        this.connection = connection;')
    fb.add('    }').add()
    fb.add('    public void fetchSafeUser(int userId) throws SQLException {')
    fb.add_target(
        '        String sql = "SELECT username, email FROM users WHERE id = ?";',
        "NO_FLAG", "SAST", "L3_ADVANCED", "L3-JAVA-001",
        "Parameterized SQL query string with question mark placeholder"
    )
    fb.add('        try (PreparedStatement stmt = connection.prepareStatement(sql)) {')
    fb.add('            stmt.setInt(1, userId);')
    fb.add('            ResultSet rs = stmt.executeQuery();')
    fb.add('        }')
    fb.add('    }').add()
    fb.add('    public void fetchUnsafeUser(String username) throws SQLException {')
    fb.add_target(
        '        String sql = "SELECT * FROM users WHERE username = \'" + username + "\'";',
        "FLAG", "SAST", "L3_ADVANCED", "L3-JAVA-002",
        "SQL injection via string concatenation in Java JDBC statement"
    )
    fb.add('        try (Statement stmt = connection.createStatement()) {')
    fb.add('            ResultSet rs = stmt.executeQuery(sql);')
    fb.add('        }')
    fb.add('    }').add()
    fb.add('    public byte[] computeSha256(byte[] data) throws Exception {')
    fb.add_target(
        '        MessageDigest md = MessageDigest.getInstance("SHA-256");',
        "NO_FLAG", "SAST", "L3_ADVANCED", "L3-JAVA-003",
        "Cryptographically secure SHA-256 message digest instantiation"
    )
    fb.add('        return md.digest(data);')
    fb.add('    }').add()
    fb.add('    public byte[] computeWeakMd5(byte[] data) throws Exception {')
    fb.add_target(
        '        MessageDigest md = MessageDigest.getInstance("MD5");',
        "FLAG", "SAST", "L3_ADVANCED", "L3-JAVA-004",
        "Insecure MD5 message digest instantiation in Java"
    )
    fb.add('        return md.digest(data);')
    fb.add('    }')
    fb.add('}')
    fixtures.append(fb)

    # =============================================================
    # 6. Terraform Enterprise Infrastructure (Terraform)
    # =============================================================
    fb = FixtureBuilder("l3_advanced/terraform_infra/main.tf")
    fb.add('terraform {')
    fb.add('  required_version = ">= 1.5.0"')
    fb.add('  required_providers {')
    fb.add('    aws = {')
    fb.add('      source  = "hashicorp/aws"')
    fb.add('      version = "~> 5.0"')
    fb.add('    }')
    fb.add('  }')
    fb.add('}').add()
    fb.add('resource "aws_vpc" "production" {')
    fb.add('  cidr_block           = "10.0.0.0/16"')
    fb.add('  enable_dns_hostnames = true')
    fb.add('}').add()
    fb.add('resource "aws_security_group" "alb" {')
    fb.add('  name        = "alb-security-group"')
    fb.add('  vpc_id      = aws_vpc.production.id')
    fb.add('  ingress {')
    fb.add('    from_port   = 443')
    fb.add('    to_port     = 443')
    fb.add('    protocol    = "tcp"')
    fb.add_target(
        '    cidr_blocks = ["0.0.0.0/0"]',
        "DEBATABLE", "TERRAFORM", "L3_ADVANCED", "L3-TF-001",
        "Public web ALB ingress on HTTPS port 443"
    )
    fb.add('  }')
    fb.add('  ingress {')
    fb.add('    from_port   = 22')
    fb.add('    to_port     = 22')
    fb.add('    protocol    = "tcp"')
    fb.add_target(
        '    cidr_blocks = ["0.0.0.0/0"]',
        "FLAG", "TERRAFORM", "L3_ADVANCED", "L3-TF-002",
        "Administrative SSH port 22 exposed globally to 0.0.0.0/0"
    )
    fb.add('  }')
    fb.add('  ingress {')
    fb.add('    from_port   = 22')
    fb.add('    to_port     = 22')
    fb.add('    protocol    = "tcp"')
    fb.add_target(
        '    cidr_blocks = ["10.0.0.0/8"]',
        "NO_FLAG", "TERRAFORM", "L3_ADVANCED", "L3-TF-003",
        "Private network ingress on SSH port 22"
    )
    fb.add('  }')
    fb.add('  ingress {')
    fb.add('    from_port   = 22')
    fb.add('    to_port     = 22')
    fb.add('    protocol    = "tcp"')
    fb.add_target(
        '    cidr_blocks = ["3.251.148.96/29"]',
        "NO_FLAG", "TERRAFORM", "L3_ADVANCED", "L3-TF-004",
        "Specific /29 IP block access on SSH port 22"
    )
    fb.add('  }')
    fb.add('  ingress {')
    fb.add_target(
        '    from_port   = 2200',
        "NO_FLAG", "TERRAFORM", "L3_ADVANCED", "L3-TF-005",
        "High port number containing digit prefix 22 without being port 22"
    )
    fb.add('    to_port     = 2299')
    fb.add('    protocol    = "tcp"')
    fb.add('    cidr_blocks = ["0.0.0.0/0"]')
    fb.add('  }')
    fb.add('}').add()
    fb.add('resource "aws_db_instance" "analytics" {')
    fb.add('  allocated_storage   = 50')
    fb.add('  engine              = "postgres"')
    fb.add('  instance_class      = "db.t3.medium"')
    fb.add_target(
        '  publicly_accessible = true',
        "FLAG", "TERRAFORM", "L3_ADVANCED", "L3-TF-006",
        "Production database marked publicly accessible"
    )
    fb.add_target(
        '  storage_encrypted   = false',
        "FLAG", "TERRAFORM", "L3_ADVANCED", "L3-TF-007",
        "Database storage encryption disabled"
    )
    fb.add('}').add()
    fb.add('resource "aws_db_instance" "core_replica" {')
    fb.add('  allocated_storage   = 50')
    fb.add('  engine              = "postgres"')
    fb.add('  instance_class      = "db.t3.medium"')
    fb.add_target(
        '  publicly_accessible = false',
        "NO_FLAG", "TERRAFORM", "L3_ADVANCED", "L3-TF-008",
        "Replica database secluded from public internet"
    )
    fb.add_target(
        '  storage_encrypted   = true',
        "NO_FLAG", "TERRAFORM", "L3_ADVANCED", "L3-TF-009",
        "Replica database storage encrypted"
    )
    fb.add('}').add()
    fb.add('resource "aws_s3_bucket" "audit_logs" {')
    fb.add('  bucket = "prod-enterprise-audit-logs"')
    fb.add_target(
        '  acl    = "private"',
        "NO_FLAG", "TERRAFORM", "L3_ADVANCED", "L3-TF-010",
        "Audit bucket protected by private ACL"
    )
    fb.add('}').add()
    fb.add('resource "aws_s3_bucket" "public_distribution" {')
    fb.add('  bucket = "prod-enterprise-public-dist"')
    fb.add_target(
        '  acl    = "public-read"',
        "FLAG", "TERRAFORM", "L3_ADVANCED", "L3-TF-011",
        "Public-read ACL configured on distribution bucket"
    )
    fb.add('}').add()
    fb.add('resource "aws_ebs_volume" "unencrypted_vol" {')
    fb.add('  availability_zone = "us-east-1a"')
    fb.add('  size              = 100')
    fb.add_target(
        '  encrypted         = false',
        "FLAG", "TERRAFORM", "L3_ADVANCED", "L3-TF-012",
        "Unencrypted EBS volume in production infrastructure"
    )
    fb.add('}').add()
    fb.add('resource "aws_ebs_volume" "encrypted_vol" {')
    fb.add('  availability_zone = "us-east-1a"')
    fb.add('  size              = 100')
    fb.add_target(
        '  encrypted         = true',
        "NO_FLAG", "TERRAFORM", "L3_ADVANCED", "L3-TF-013",
        "Encrypted EBS volume in production infrastructure"
    )
    fb.add('}').add()
    fb.add('resource "aws_s3_bucket_public_access_block" "audit_pab" {')
    fb.add('  bucket                  = aws_s3_bucket.audit_logs.id')
    fb.add_target(
        '  block_public_acls       = true',
        "NO_FLAG", "TERRAFORM", "L3_ADVANCED", "L3-TF-014",
        "Public ACL blocking activated"
    )
    fb.add_target(
        '  block_public_policy     = true',
        "NO_FLAG", "TERRAFORM", "L3_ADVANCED", "L3-TF-015",
        "Public policy blocking activated"
    )
    fb.add('}')
    fixtures.append(fb)

    # =============================================================
    # 7. Kubernetes Workload Manifest (YAML)
    # =============================================================
    fb = FixtureBuilder("l3_advanced/k8s_workload/deployment.yaml")
    fb.add('apiVersion: apps/v1')
    fb.add('kind: Deployment')
    fb.add('metadata:')
    fb.add('  name: order-processor')
    fb.add('  labels:')
    fb.add_target(
        '    app.kubernetes.io/name: "order-processor-latest"',
        "NO_FLAG", "K8S", "L3_ADVANCED", "L3-K8S-001",
        "Workload label name string containing latest lookalike"
    )
    fb.add('spec:')
    fb.add('  replicas: 3')
    fb.add('  selector:')
    fb.add('    matchLabels:')
    fb.add('      app: order-processor')
    fb.add('  template:')
    fb.add('    metadata:')
    fb.add('      labels:')
    fb.add('        app: order-processor')
    fb.add('    spec:')
    fb.add_target(
        '      hostNetwork: false',
        "NO_FLAG", "K8S", "L3_ADVANCED", "L3-K8S-002",
        "Host network sharing disabled on pod specification"
    )
    fb.add_target(
        '      hostPID: false',
        "NO_FLAG", "K8S", "L3_ADVANCED", "L3-K8S-003",
        "Host PID sharing disabled on pod specification"
    )
    fb.add('      containers:')
    fb.add('      - name: processor')
    fb.add_target(
        '        image: redis:latest',
        "FLAG", "K8S", "L3_ADVANCED", "L3-K8S-004",
        "Container image using mutable latest version tag"
    )
    fb.add('        securityContext:')
    fb.add_target(
        '          privileged: false',
        "NO_FLAG", "K8S", "L3_ADVANCED", "L3-K8S-005",
        "Privileged container mode explicitly disabled"
    )
    fb.add_target(
        '          runAsNonRoot: true',
        "NO_FLAG", "K8S", "L3_ADVANCED", "L3-K8S-006",
        "Enforcing non-root container user execution"
    )
    fb.add_target(
        '          runAsUser: 10001',
        "NO_FLAG", "K8S", "L3_ADVANCED", "L3-K8S-007",
        "Explicit non-root user UID assigned"
    )
    fb.add_target(
        '          allowPrivilegeEscalation: false',
        "NO_FLAG", "K8S", "L3_ADVANCED", "L3-K8S-008",
        "Privilege escalation prevented via security context"
    )
    fb.add('      - name: privileged-diagnostics')
    fb.add_target(
        '        image: alpine:3.18.4',
        "NO_FLAG", "K8S", "L3_ADVANCED", "L3-K8S-009",
        "Diagnostic container image pinned to semantic version"
    )
    fb.add('        securityContext:')
    fb.add_target(
        '          privileged: true',
        "FLAG", "K8S", "L3_ADVANCED", "L3-K8S-010",
        "Diagnostic container running with privileged root access"
    )
    fb.add('      volumes:')
    fb.add('      - name: host-root')
    fb.add('        hostPath:')
    fb.add_target(
        '          path: "/"',
        "FLAG", "K8S", "L3_ADVANCED", "L3-K8S-011",
        "Dangerous root filesystem hostPath mount"
    )
    fixtures.append(fb)

    # =============================================================
    # 8. Production Multi-Stage Dockerfile (Dockerfile)
    # =============================================================
    fb = FixtureBuilder("l3_advanced/docker_build/Dockerfile")
    fb.add('FROM golang:1.21-alpine AS builder')
    fb.add('WORKDIR /build')
    fb.add('USER root')
    fb.add_target(
        'ARG GITHUB_TOKEN=ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R',
        "FLAG", "DOCKER", "L3_ADVANCED", "L3-DOCKER-001",
        "Build argument hardcoding GitHub personal access token"
    )
    fb.add('COPY go.* ./')
    fb.add('RUN go mod download')
    fb.add('COPY . .')
    fb.add('RUN CGO_ENABLED=0 go build -o /app/server .').add()
    fb.add('FROM alpine:3.18.4 AS runtime')
    fb.add('WORKDIR /app')
    fb.add_target(
        'ENV NODE_ENV=production',
        "NO_FLAG", "DOCKER", "L3_ADVANCED", "L3-DOCKER-002",
        "Standard runtime mode environment designation"
    )
    fb.add_target(
        'ENV PASSWORD_FILE=/var/run/secrets/db_password',
        "NO_FLAG", "DOCKER", "L3_ADVANCED", "L3-DOCKER-003",
        "Filesystem secret mount path rather than credential"
    )
    fb.add('RUN addgroup -S appgroup && adduser -S appuser -G appgroup')
    fb.add('COPY --from=builder /app/server /usr/local/bin/server')
    fb.add_target(
        'USER 10001',
        "NO_FLAG", "DOCKER", "L3_ADVANCED", "L3-DOCKER-004",
        "Dedicated unprivileged non-root user in final container stage"
    )
    fb.add_target(
        'EXPOSE 22',
        "FLAG", "DOCKER", "L3_ADVANCED", "L3-DOCKER-005",
        "Insecure SSH port 22 exposed in production container"
    )
    fb.add_target(
        'EXPOSE 8080',
        "NO_FLAG", "DOCKER", "L3_ADVANCED", "L3-DOCKER-006",
        "Standard unprivileged application HTTP port"
    )
    fb.add('ENTRYPOINT ["/usr/local/bin/server"]')
    fixtures.append(fb)

    # =============================================================
    # 9. Docker Compose Stack (YAML)
    # =============================================================
    fb = FixtureBuilder("l3_advanced/compose_stack/docker-compose.yml")
    fb.add('services:')
    fb.add('  web:')
    fb.add('    image: nginx:1.25.3')
    fb.add('    ports:')
    fb.add_target(
        '    - "80:80"',
        "DEBATABLE", "DOCKER", "L3_ADVANCED", "L3-COMP-001",
        "Standard public web ingress port 80"
    )
    fb.add('  api:')
    fb.add('    image: node:20-alpine')
    fb.add_target(
        '    privileged: false',
        "NO_FLAG", "DOCKER", "L3_ADVANCED", "L3-COMP-002",
        "Privileged mode explicitly disabled on api service"
    )
    fb.add('  db:')
    fb.add('    image: postgres:15.4-alpine')
    fb.add('    ports:')
    fb.add_target(
        '    - "127.0.0.1:5432:5432"',
        "NO_FLAG", "DOCKER", "L3_ADVANCED", "L3-COMP-003",
        "Database port bound strictly to local loopback interface"
    )
    fb.add('    environment:')
    fb.add_target(
        '      POSTGRES_PASSWORD: "ProdSuperSecretPass123"',
        "FLAG", "DOCKER", "L3_ADVANCED", "L3-COMP-004",
        "Cleartext database password literal in environment"
    )
    fb.add('  metrics-agent:')
    fb.add('    image: alpine:3.18.4')
    fb.add('    volumes:')
    fb.add_target(
        '    - "/var/run/docker.sock:/var/run/docker.sock"',
        "FLAG", "DOCKER", "L3_ADVANCED", "L3-COMP-005",
        "Host Docker socket mounted into container filesystem"
    )
    fixtures.append(fb)

    # =============================================================
    # 10. GitHub Actions Release Pipeline (YAML)
    # =============================================================
    fb = FixtureBuilder("l3_advanced/github_ci/release.yml")
    fb.add('name: Production Release')
    fb.add('on:')
    fb.add('  push:')
    fb.add('    branches: [main]')
    fb.add('permissions:')
    fb.add_target(
        '  contents: read',
        "NO_FLAG", "CI", "L3_ADVANCED", "L3-CI-001",
        "Restricted read-only repository permissions"
    )
    fb.add('jobs:')
    fb.add('  deploy:')
    fb.add('    runs-on: ubuntu-latest')
    fb.add('    steps:')
    fb.add_target(
        '    - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11',
        "NO_FLAG", "CI", "L3_ADVANCED", "L3-CI-002",
        "Checkout action pinned by immutable commit SHA"
    )
    fb.add('    - name: Inject PR Title Unsafe')
    fb.add_target(
        '      run: echo "${{ github.event.pull_request.title }}"',
        "FLAG", "CI", "L3_ADVANCED", "L3-CI-003",
        "Direct script injection via pull request title"
    )
    fb.add('    - name: Safe Environment Usage')
    fb.add('      env:')
    fb.add_target(
        '        PR_TITLE: "${{ github.event.pull_request.title }}"',
        "NO_FLAG", "CI", "L3_ADVANCED", "L3-CI-004",
        "Safe environment variable parameterization"
    )
    fb.add_target(
        '      run: echo "$PR_TITLE"',
        "NO_FLAG", "CI", "L3_ADVANCED", "L3-CI-005",
        "Quoted shell variable reference"
    )
    fb.add('    - name: Configure Production Credentials')
    fb.add('      env:')
    fb.add_target(
        '        DEPLOY_TOKEN: "ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R"',
        "FLAG", "CI", "L3_ADVANCED", "L3-CI-006",
        "Hardcoded deployment personal access token in CI step"
    )
    fb.add_target(
        '      run: echo "::add-mask::$DEPLOY_TOKEN"',
        "NO_FLAG", "CI", "L3_ADVANCED", "L3-CI-007",
        "Workflow command instructing engine to mask sensitive token"
    )
    fixtures.append(fb)

    # =============================================================
    # 11. Bash Deployment Script (Shell)
    # =============================================================
    fb = FixtureBuilder("l3_advanced/deploy_script/deploy.sh")
    fb.add('#!/usr/bin/env bash')
    fb.add('set -euo pipefail').add()
    fb.add('TARGET_DIR="/opt/app"')
    fb.add('LOG_FILE="/var/log/deploy.log"').add()
    fb.add('echo "Starting deployment sequence..."').add()
    fb.add('cleanup_cache() {')
    fb.add_target(
        '    chmod 0755 "$TARGET_DIR/bin"',
        "NO_FLAG", "SAST", "L3_ADVANCED", "L3-SH-001",
        "Standard restricted binary permissions"
    )
    fb.add_target(
        '    chmod 777 "$TARGET_DIR/cache"',
        "FLAG", "SAST", "L3_ADVANCED", "L3-SH-002",
        "World-writable directory permissions granted to cache directory"
    )
    fb.add('}').add()
    fb.add('execute_dynamic() {')
    fb.add('    local cmd_input="$1"')
    fb.add_target(
        '    eval "$cmd_input"',
        "FLAG", "SAST", "L3_ADVANCED", "L3-SH-003",
        "Dynamic shell evaluation on variable function parameter"
    )
    fb.add('}').add()
    fb.add('initialize_ssh() {')
    fb.add_target(
        '    eval "$(ssh-agent -s)"',
        "DEBATABLE", "SAST", "L3_ADVANCED", "L3-SH-004",
        "Standard evaluation of ssh-agent daemon output"
    )
    fb.add('}').add()
    fb.add('fetch_packages() {')
    fb.add_target(
        '    curl -fsSL -o /tmp/pkg.tar.gz "https://releases.internal/pkg.tar.gz"',
        "NO_FLAG", "SAST", "L3_ADVANCED", "L3-SH-005",
        "Secure curl invocation with certificate verification"
    )
    fb.add('}').add()
    fb.add('cleanup_cache')
    fb.add('echo "Deployment completed successfully."')
    fixtures.append(fb)

    # =============================================================
    # 12. Environment Variable Configuration (.env)
    # =============================================================
    fb = FixtureBuilder("l3_advanced/env_config/.env")
    fb.add('# Production Runtime Environment Variables')
    fb.add('APP_ENV=production')
    fb.add('PORT=8080')
    fb.add_target(
        'AWS_ACCESS_KEY_ID=AKIA2Y8Z4W9V3X7R1T5M',
        "FLAG", "SECRETS", "L3_ADVANCED", "L3-ENV-001",
        "Valid AWS Access Key ID assigned in environment configuration"
    )
    fb.add_target(
        'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYz8947KlMnP',
        "FLAG", "SECRETS", "L3_ADVANCED", "L3-ENV-002",
        "Hardcoded 40-character AWS Secret Access Key in environment"
    )
    fb.add_target(
        'SLACK_BOT_TOKEN=xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx',
        "FLAG", "SECRETS", "L3_ADVANCED", "L3-ENV-003",
        "Production Slack bot API token"
    )
    fb.add_target(
        'DATABASE_URL=postgres://${DB_USER}:${DB_PASS}@db.internal:5432/app',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-ENV-004",
        "Parameterized database connection URI with variable expansion"
    )
    fb.add_target(
        'API_KEY=YOUR_API_KEY_HERE',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-ENV-005",
        "Documentation template placeholder token"
    )
    fb.add_target(
        'SECRET_NAME=production/app/secrets',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-ENV-006",
        "Cloud Secrets Manager path identifier"
    )
    fb.add_target(
        'PASSWORD_FILE=/var/run/secrets/db_password',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-ENV-007",
        "Local container path pointing to mounted secret file"
    )
    fb.add_target(
        'GIT_COMMIT_SHA=b8a6f43e2d1c9b8a6f43e2d1c9b8a6f43e2d1c9b',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-ENV-008",
        "Git commit SHA digest string"
    )
    fixtures.append(fb)

    # =============================================================
    # 13. Application Configuration (YAML)
    # =============================================================
    fb = FixtureBuilder("l3_advanced/app_config/config.yaml")
    fb.add('server:')
    fb.add('  host: 0.0.0.0')
    fb.add('  port: 8080')
    fb.add('database:')
    fb.add_target(
        '  url: "postgres://admin:S3cr3tP4ss@db.internal:5432/app"',
        "FLAG", "SECRETS", "L3_ADVANCED", "L3-YAML-001",
        "Cleartext database credentials embedded in connection URL"
    )
    fb.add_target(
        '  secretName: "aws/secretsmanager/auth-keys"',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-YAML-002",
        "Resource identifier for secrets vault entry"
    )
    fb.add('security:')
    fb.add_target(
        '  apiKey: "AIzaSyBv9x1d4E8f2G6h0J3k5L7m9N1p3Q5r7S"',
        "FLAG", "SECRETS", "L3_ADVANCED", "L3-YAML-003",
        "Hardcoded Google AIza API credential in configuration"
    )
    fb.add_target(
        '  placeholderKey: "${API_KEY}"',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-YAML-004",
        "Environment template interpolation variable"
    )
    fb.add_target(
        '  passwordPolicy: "min_length: 14"',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-YAML-005",
        "Password complexity rule specification"
    )
    fixtures.append(fb)

    # =============================================================
    # 14. Node Package Definition (JSON)
    # =============================================================
    fb = FixtureBuilder("l3_advanced/node_pkg/package.json")
    fb.add('{')
    fb.add_target(
        '  "name": "passwordless-tokenizer-service",',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-NPM-001",
        "Package name containing passwordless and tokenizer substrings"
    )
    fb.add('  "version": "1.0.0",')
    fb.add('  "description": "Tokenizer utility for keyboard inputs",')
    fb.add('  "scripts": {')
    fb.add('    "test": "jest",')
    fb.add_target(
        '    "publish-pkg": "export NPM_TOKEN=ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R && npm publish"',
        "FLAG", "SECRETS", "L3_ADVANCED", "L3-NPM-002",
        "Hardcoded GitHub token embedded directly into npm script command"
    )
    fb.add('  },')
    fb.add('  "dependencies": {')
    fb.add('    "express": "^4.19.2"')
    fb.add('  }')
    fb.add('}')
    fixtures.append(fb)

    # =============================================================
    # 15. Documentation README (Markdown)
    # =============================================================
    fb = FixtureBuilder("l3_advanced/docs_readme/README.md")
    fb.add('# Developer Onboarding and API Documentation')
    fb.add('Welcome to the microservice development portal.')
    fb.add('To authenticate with the service in development:')
    fb.add('```bash')
    fb.add_target(
        'curl -H "Authorization: Bearer YOUR_API_KEY_HERE" https://api.service.internal/v1',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-DOC-001",
        "Documentation code fence demonstrating placeholder authorization token"
    )
    fb.add_target(
        'export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
        "DEBATABLE", "SECRETS", "L3_ADVANCED", "L3-DOC-002",
        "Documentation code block containing AWS documentation example key"
    )
    fb.add_target(
        'curl -H "Authorization: Bearer sk-proj-abcde12345ABCDE12345abcde12345ABCDE12345abcde12" https://api.openai.com/v1',
        "FLAG", "SECRETS", "L3_ADVANCED", "L3-DOC-003",
        "Actual OpenAI secret key format accidentally committed in documentation"
    )
    fb.add('```')
    fixtures.append(fb)

    # =============================================================
    # 16. PHP Portal Backend (PHP)
    # =============================================================
    fb = FixtureBuilder("l3_advanced/php_portal/index.php")
    fb.add('<?php')
    fb.add('$host = "127.0.0.1";')
    fb.add('$db   = "portal_db";')
    fb.add_target(
        '$form_field_type = "password";',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-PHP-001",
        "HTML input element type variable"
    )
    fb.add_target(
        '$api_token = getenv("PORTAL_API_TOKEN");',
        "NO_FLAG", "SECRETS", "L3_ADVANCED", "L3-PHP-002",
        "Secure dynamic environment lookup for API token"
    )
    fb.add('if (isset($_GET["user_id"])) {')
    fb.add('    $id = $_GET["user_id"];')
    fb.add_target(
        '    $query = "SELECT * FROM users WHERE id = " . $id;',
        "FLAG", "SAST", "L3_ADVANCED", "L3-PHP-003",
        "SQL injection via string concatenation in PHP query construction"
    )
    fb.add('}')
    fb.add('if (isset($_POST["calc_expression"])) {')
    fb.add_target(
        '    $result = eval("return " . $_POST["calc_expression"] . ";");',
        "FLAG", "SAST", "L3_ADVANCED", "L3-PHP-004",
        "Arbitrary code execution via PHP eval on untrusted user POST parameter"
    )
    fb.add('}')
    fb.add('?>')
    fixtures.append(fb)

    return fixtures
