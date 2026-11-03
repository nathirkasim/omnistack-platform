"""
Data Access and Repository Layer for Deep Taint Analysis
"""

import sqlite3

class OrderRepository:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:")

    def execute_raw_sql(self, order_filter: str):
        cursor = self.conn.cursor()
        # GT: id=TAINT-PY-001 type=TP cwe=CWE-89 rule=deep-taint-sqli
        cursor.execute(f"SELECT * FROM orders WHERE status = '{order_filter}'")
        return cursor.fetchall()

    def execute_parameterized(self, order_id: str):
        cursor = self.conn.cursor()
        # GT: id=TAINT-PY-011 type=FP reason=multi-hop-parameterized-query
        cursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
        return cursor.fetchall()

    def execute_second_order(self, cached_tag: str):
        cursor = self.conn.cursor()
        # GT: id=TAINT-PY-005 type=TP cwe=CWE-89 rule=second-order-sqli
        cursor.execute(f"SELECT * FROM audit_logs WHERE tag = '{cached_tag}'")
        return cursor.fetchall()

    def constant_query(self, _unused_filter: str):
        cursor = self.conn.cursor()
        # GT: id=TAINT-PY-019 type=FP reason=constant-query-sink
        cursor.execute("SELECT 1 FROM status_catalog LIMIT 1")
        return cursor.fetchall()

    def update_account_balance(self, target_account_id: str, amount: float):
        cursor = self.conn.cursor()
        # GT: id=TAINT-PY-010 type=TP cwe=CWE-639 rule=idor-unauthorized-update
        cursor.execute("UPDATE accounts SET balance = balance + ? WHERE account_id = ?", (amount, target_account_id))
        self.conn.commit()

