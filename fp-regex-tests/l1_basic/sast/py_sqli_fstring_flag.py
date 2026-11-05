def fetch_item(cursor, item_id):
    cursor.execute(f"SELECT * FROM items WHERE id = {item_id}")
    return cursor.fetchall()
