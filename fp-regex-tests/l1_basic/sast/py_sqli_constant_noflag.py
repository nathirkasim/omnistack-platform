def get_active_users(cursor):
    cursor.execute("SELECT id, name FROM users WHERE active = 1")
    return cursor.fetchall()
