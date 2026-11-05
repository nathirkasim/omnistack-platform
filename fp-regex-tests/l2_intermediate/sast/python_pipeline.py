import ast
import hashlib
import os
import random
import subprocess
import yaml

class ReportGenerator:
    def __init__(self, db_conn):
        self.conn = db_conn
        self.eval_mode = False

    def run_query(self, report_id, tag):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM reports WHERE id = %s", (report_id,))
        cursor.execute("SELECT * FROM logs WHERE tag = '%s'" % tag)
        return cursor.fetchall()

    def load_spec(self, raw_yaml):
        return yaml.safe_load(raw_yaml)

    def load_untrusted_spec(self, raw_yaml):
        return yaml.load(raw_yaml)

    def parse_number_literal(self, val):
        return ast.literal_eval(val)

    def compute_sha(self, content):
        return hashlib.sha256(content.encode()).hexdigest()

    def archive_output(self, folder):
        subprocess.run(["tar", "-czf", "report.tar.gz", folder], check=True)
