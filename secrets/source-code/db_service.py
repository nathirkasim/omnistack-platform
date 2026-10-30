# VULNERABLE: Hardcoded Database Connection String with embedded plaintext password
DATABASE_URL = "postgres://dbadmin:SuperSecretPass2026!@postgres.internal.corp:5432/production"

def get_connection():
    import psycopg2
    return psycopg2.connect(DATABASE_URL)
