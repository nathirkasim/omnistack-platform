"""
SAST Test Fixture: SQL Injection (Python)
Covers paired True Positives and False Positives.
"""
import sqlite3
from sqlalchemy import text
from sqlalchemy.orm import Session

# ==============================================================================
# TP-SAST-001: Genuine SQL Injection via raw string concatenation
# CWE-89 | High Severity
# ==============================================================================
def get_user_profile_vulnerable(db_connection: sqlite3.Connection, user_input_id: str):
    cursor = db_connection.cursor()
    # Intentionally vulnerable: user input concatenated directly into query
    query = "SELECT id, username, email FROM users WHERE id = '" + user_input_id + "'"
    cursor.execute(query)
    return cursor.fetchone()


# ==============================================================================
# FP-SAST-001: Safe Parameterized SQL Query
# Expected: No finding / False Positive if flagged
# ==============================================================================
def get_user_profile_safe(db_connection: sqlite3.Connection, user_input_id: str):
    cursor = db_connection.cursor()
    # Safe: Prepared statement with positional parameter binding
    query = "SELECT id, username, email FROM users WHERE id = ?"
    cursor.execute(query, (user_input_id,))
    return cursor.fetchone()


# ==============================================================================
# FP-SAST-002: String concatenation containing user input NOT used in query
# Resembles a SQL injection query construction, but value is purely logged/cached.
# ==============================================================================
def log_and_query_safe(db_connection: sqlite3.Connection, user_input_id: str):
    cursor = db_connection.cursor()
    # String construction resembles query building, but used solely for audit logs
    audit_log = f"AUDIT: Access requested for user_id='{user_input_id}' at timestamp"
    print(audit_log)

    # Actual database query uses static query with parameterized binding
    cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_input_id,))
    return cursor.fetchone()


# ==============================================================================
# FP-SAST-003: Fixed, trusted constant query with string formatting
# Value is a compile-time constant, not tainted by user input.
# ==============================================================================
SYSTEM_DEFAULT_ROLE = "ANALYST"

def get_system_analysts(db_connection: sqlite3.Connection):
    cursor = db_connection.cursor()
    # Safe: Value is hardcoded constant, no taint source exists
    query = f"SELECT id, username FROM users WHERE role = '{SYSTEM_DEFAULT_ROLE}'"
    cursor.execute(query)
    return cursor.fetchall()


# ==============================================================================
# TP-SAST-002: ORM Raw Query API used insecurely
# CWE-89 | High Severity
# ==============================================================================
def get_user_by_name_orm_vulnerable(session: Session, user_input_name: str):
    # Intentionally vulnerable: SQLAlchemy text() called with interpolated string
    raw_query = text(f"SELECT * FROM users WHERE name = '{user_input_name}'")
    return session.execute(raw_query).fetchall()


# ==============================================================================
# FP-SAST-004: ORM Raw Query API used securely with bindparams
# Expected: Safe / No detection
# ==============================================================================
def get_user_by_name_orm_safe(session: Session, user_input_name: str):
    # Safe: SQLAlchemy text() with bound parameter
    raw_query = text("SELECT * FROM users WHERE name = :name")
    return session.execute(raw_query, {"name": user_input_name}).fetchall()


# ==============================================================================
# FN-SAST-001: SQL Injection via multi-step alias/dictionary data flow
# Expected detection, but frequently missed by simple pattern matchers
# ==============================================================================
def get_records_indirect_vulnerable(db_connection: sqlite3.Connection, payload: dict):
    cursor = db_connection.cursor()
    filters = {}
    for k, v in payload.items():
        filters[k] = v
    # Indirect extraction through alias
    clause = "status = '" + str(filters.get("status", "active")) + "'"
    cursor.execute("SELECT * FROM items WHERE " + clause)
    return cursor.fetchall()
