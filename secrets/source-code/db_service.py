# VULNERABLE: Hardcoded Database Connection String with embedded plaintext password
DATABASE_URL = "postgres://app_production_usr:mK9%23vL2$xQ5!zR8*mP4@db-prod-cluster.internal.corp:5432/platform_master"

def get_connection():
    import psycopg2
    return psycopg2.connect(DATABASE_URL)
