from typing import List
from .base import FixtureBuilder, TargetLine

def generate_sast_cases() -> List[FixtureBuilder]:
    fixtures: List[FixtureBuilder] = []

    # -------------------------------------------------------------
    # L1 BASIC: SAST
    # -------------------------------------------------------------

    # 1. Python SQL Injection via String Modulo (FLAG)
    fb = FixtureBuilder("l1_basic/sast/py_sqli_modulo_flag.py")
    fb.add("def fetch_user(cursor, user_id):")
    fb.add_target(
        '    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)',
        "FLAG", "SAST", "L1_BASIC", "SAST-001",
        "SQL query constructed using Python string formatting modulo operator"
    )
    fb.add("    return cursor.fetchone()")
    fixtures.append(fb)

    # 2. Python Parameterized Query with Tuple (NO_FLAG)
    fb = FixtureBuilder("l1_basic/sast/py_sqli_param_noflag.py")
    fb.add("def fetch_user(cursor, user_id):")
    fb.add_target(
        '    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        "NO_FLAG", "SAST", "L1_BASIC", "SAST-002",
        "Safe parameterized query passing tuple parameters to database driver"
    )
    fb.add("    return cursor.fetchone()")
    fixtures.append(fb)

    # 3. Python SQL Injection via f-string (FLAG)
    fb = FixtureBuilder("l1_basic/sast/py_sqli_fstring_flag.py")
    fb.add("def fetch_item(cursor, item_id):")
    fb.add_target(
        '    cursor.execute(f"SELECT * FROM items WHERE id = {item_id}")',
        "FLAG", "SAST", "L1_BASIC", "SAST-003",
        "SQL query constructed using Python formatted string interpolation"
    )
    fb.add("    return cursor.fetchall()")
    fixtures.append(fb)

    # 4. Python Static Query Constant (NO_FLAG)
    fb = FixtureBuilder("l1_basic/sast/py_sqli_constant_noflag.py")
    fb.add("def get_active_users(cursor):")
    fb.add_target(
        '    cursor.execute("SELECT id, name FROM users WHERE active = 1")',
        "NO_FLAG", "SAST", "L1_BASIC", "SAST-004",
        "Static string literal query with no variable interpolation"
    )
    fb.add("    return cursor.fetchall()")
    fixtures.append(fb)

    # 5. Python Command Injection via os.system (FLAG)
    fb = FixtureBuilder("l1_basic/sast/py_os_system_flag.py")
    fb.add("import os")
    fb.add("def list_user_dir(username):")
    fb.add_target(
        '    os.system("ls -la /home/" + username)',
        "FLAG", "SAST", "L1_BASIC", "SAST-005",
        "Direct shell command execution with concatenated user input"
    )
    fixtures.append(fb)

    # 6. Python os.system with Constant Argument (NO_FLAG)
    fb = FixtureBuilder("l1_basic/sast/py_os_system_constant_noflag.py")
    fb.add("import os")
    fb.add("def clear_terminal():")
    fb.add_target(
        '    os.system("clear")',
        "NO_FLAG", "SAST", "L1_BASIC", "SAST-006",
        "Hardcoded static command string invocation without parameterization"
    )
    fixtures.append(fb)

    # 7. Python subprocess with shell=True and Concat (FLAG)
    fb = FixtureBuilder("l1_basic/sast/py_subprocess_flag.py")
    fb.add("import subprocess")
    fb.add("def ping_target(host):")
    fb.add_target(
        '    subprocess.run("ping -c 1 " + host, shell=True, check=True)',
        "FLAG", "SAST", "L1_BASIC", "SAST-007",
        "Subprocess execution with shell=True and unescaped input string"
    )
    fixtures.append(fb)

    # 8. Python subprocess with Argument List (NO_FLAG)
    fb = FixtureBuilder("l1_basic/sast/py_subprocess_noflag.py")
    fb.add("import subprocess")
    fb.add("def ping_target(host):")
    fb.add_target(
        '    subprocess.run(["ping", "-c", "1", host], check=True)',
        "NO_FLAG", "SAST", "L1_BASIC", "SAST-008",
        "Subprocess execution using argument array without shell interpreter"
    )
    fixtures.append(fb)

    # 9. Python eval on Dynamic Input (FLAG)
    fb = FixtureBuilder("l1_basic/sast/py_eval_flag.py")
    fb.add("def process_expression(expr):")
    fb.add_target(
        '    result = eval(expr)',
        "FLAG", "SAST", "L1_BASIC", "SAST-009",
        "Arbitrary Python code execution via dynamic eval call"
    )
    fb.add("    return result")
    fixtures.append(fb)

    # 10. Python ast.literal_eval (NO_FLAG)
    fb = FixtureBuilder("l1_basic/sast/py_ast_literal_eval_noflag.py")
    fb.add("import ast")
    fb.add("def parse_config(data):")
    fb.add_target(
        '    return ast.literal_eval(data)',
        "NO_FLAG", "SAST", "L1_BASIC", "SAST-010",
        "Safe AST evaluation restricted solely to literal expressions"
    )
    fixtures.append(fb)

    # 11. Python Model.eval() Lookalike (NO_FLAG)
    fb = FixtureBuilder("l1_basic/sast/py_model_eval_noflag.py")
    fb.add("class Predictor:")
    fb.add("    def eval(self): pass")
    fb.add("model = Predictor()")
    fb.add_target(
        'model.eval()',
        "NO_FLAG", "SAST", "L1_BASIC", "SAST-011",
        "Machine learning model evaluation mode toggle method invocation"
    )
    fixtures.append(fb)

    # 12. Python yaml.load Without Loader (FLAG)
    fb = FixtureBuilder("l1_basic/sast/py_yaml_load_flag.py")
    fb.add("import yaml")
    fb.add("def parse_spec(doc):")
    fb.add_target(
        '    return yaml.load(doc)',
        "FLAG", "SAST", "L1_BASIC", "SAST-012",
        "Unsafe YAML loading allowing arbitrary object deserialization"
    )
    fixtures.append(fb)

    # 13. Python yaml.safe_load (NO_FLAG)
    fb = FixtureBuilder("l1_basic/sast/py_yaml_safe_load_noflag.py")
    fb.add("import yaml")
    fb.add("def parse_spec(doc):")
    fb.add_target(
        '    return yaml.safe_load(doc)',
        "NO_FLAG", "SAST", "L1_BASIC", "SAST-013",
        "Safe YAML parser restricted to standard declarative data types"
    )
    fixtures.append(fb)

    # 14. Python MD5 for Password Hashing (FLAG)
    fb = FixtureBuilder("l1_basic/sast/py_md5_flag.py")
    fb.add("import hashlib")
    fb.add("def store_password(password):")
    fb.add_target(
        '    return hashlib.md5(password.encode()).hexdigest()',
        "FLAG", "SAST", "L1_BASIC", "SAST-014",
        "Cryptographically broken MD5 hash algorithm used on sensitive data"
    )
    fixtures.append(fb)

    # 15. Python SHA256 Hash (NO_FLAG)
    fb = FixtureBuilder("l1_basic/sast/py_sha256_noflag.py")
    fb.add("import hashlib")
    fb.add("def hash_payload(data):")
    fb.add_target(
        '    return hashlib.sha256(data.encode()).hexdigest()',
        "NO_FLAG", "SAST", "L1_BASIC", "SAST-015",
        "Strong cryptographic SHA-256 hash digest function"
    )
    fixtures.append(fb)

    # 16. Python MD5 Non-Security Cache Key (DEBATABLE)
    fb = FixtureBuilder("l1_basic/sast/py_md5_debatable.py")
    fb.add("import hashlib")
    fb.add("def generate_cache_key(url):")
    fb.add_target(
        '    return hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()',
        "DEBATABLE", "SAST", "L1_BASIC", "SAST-016",
        "Explicit usedforsecurity=False flag specifying non-cryptographic purpose"
    )
    fixtures.append(fb)

    # 17. Python Weak Pseudo-Random for Secret (FLAG)
    fb = FixtureBuilder("l1_basic/sast/py_random_flag.py")
    fb.add("import random")
    fb.add("def generate_session_token():")
    fb.add_target(
        '    return str(random.random())',
        "FLAG", "SAST", "L1_BASIC", "SAST-017",
        "Weak Mersenne Twister PRNG utilized for authentication token generation"
    )
    fixtures.append(fb)

    # 18. Python Random Choice for UI (NO_FLAG)
    fb = FixtureBuilder("l1_basic/sast/py_random_noflag.py")
    fb.add("import random")
    fb.add("def pick_avatar_color():")
    fb.add_target(
        '    return random.choice(["blue", "green", "amber", "teal"])',
        "NO_FLAG", "SAST", "L1_BASIC", "SAST-018",
        "Random selection for non-security cosmetic UI theme color"
    )
    fixtures.append(fb)

    # 19. Python Flask Debug Run on 0.0.0.0 (FLAG)
    fb = FixtureBuilder("l1_basic/sast/py_flask_debug_flag.py")
    fb.add("from flask import Flask")
    fb.add("app = Flask(__name__)")
    fb.add_target(
        'app.run(host="0.0.0.0", debug=True)',
        "FLAG", "SAST", "L1_BASIC", "SAST-019",
        "Flask development server running in debug mode bound to all network interfaces"
    )
    fixtures.append(fb)

    # 20. JS SQL Injection via String Concat (FLAG)
    fb = FixtureBuilder("l1_basic/sast/js_sqli_flag.js")
    fb.add("function getUser(db, userId) {")
    fb.add_target(
        '  return db.query("SELECT * FROM users WHERE id = " + userId);',
        "FLAG", "SAST", "L1_BASIC", "SAST-020",
        "Concatenated dynamic user input directly into SQL statement"
    )
    fb.add("}")
    fixtures.append(fb)

    # 21. JS Parameterized Query (NO_FLAG)
    fb = FixtureBuilder("l1_basic/sast/js_sqli_param_noflag.js")
    fb.add("function getUser(db, userId) {")
    fb.add_target(
        '  return db.query("SELECT * FROM users WHERE id = $1", [userId]);',
        "NO_FLAG", "SAST", "L1_BASIC", "SAST-021",
        "Parameterized positional argument query preventing injection"
    )
    fb.add("}")
    fixtures.append(fb)

    # 22. JS innerHTML XSS (FLAG)
    fb = FixtureBuilder("l1_basic/sast/js_xss_innerhtml_flag.js")
    fb.add("function renderUserComment(element, comment) {")
    fb.add_target(
        '  element.innerHTML = comment;',
        "FLAG", "SAST", "L1_BASIC", "SAST-022",
        "Raw untrusted content assignment to DOM innerHTML property"
    )
    fb.add("}")
    fixtures.append(fb)

    # 23. JS innerHTML Constant (NO_FLAG)
    fb = FixtureBuilder("l1_basic/sast/js_xss_innerhtml_const_noflag.js")
    fb.add("function renderLoader(element) {")
    fb.add_target(
        '  element.innerHTML = "<div class=\'loading\'>Please wait</div>";',
        "NO_FLAG", "SAST", "L1_BASIC", "SAST-023",
        "Hardcoded benign static HTML string assigned to innerHTML"
    )
    fb.add("}")
    fixtures.append(fb)

    # 24. JS textContent Safe DOM (NO_FLAG)
    fb = FixtureBuilder("l1_basic/sast/js_xss_textcontent_noflag.js")
    fb.add("function renderUserName(element, name) {")
    fb.add_target(
        '  element.textContent = name;',
        "NO_FLAG", "SAST", "L1_BASIC", "SAST-024",
        "Safe textContent assignment escaping any embedded markup entities"
    )
    fb.add("}")
    fixtures.append(fb)

    # 25. JS setTimeout String Code (FLAG) vs Arrow Function (NO_FLAG)
    fb = FixtureBuilder("l1_basic/sast/js_settimeout_variants.js")
    fb.add("function tick() { console.log('heartbeat'); }")
    fb.add_target(
        'setTimeout("tick()", 1000);',
        "FLAG", "SAST", "L1_BASIC", "SAST-025",
        "String argument in setTimeout evaluated as dynamic code"
    )
    fb.add_target(
        'setTimeout(() => tick(), 1000);',
        "NO_FLAG", "SAST", "L1_BASIC", "SAST-026",
        "Standard callback function reference passed to setTimeout"
    )
    fixtures.append(fb)

    # 26. JS Regex exec Lookalike (NO_FLAG)
    fb = FixtureBuilder("l1_basic/sast/js_regex_exec_noflag.js")
    fb.add("function validatePattern(str) {")
    fb.add_target(
        '  return /^user_[0-9]+$/.exec(str);',
        "NO_FLAG", "SAST", "L1_BASIC", "SAST-027",
        "Regular expression match method call rather than process execution"
    )
    fb.add("}")
    fixtures.append(fb)

    # 27. Go Command Execution with Shell vs Direct Array
    fb = FixtureBuilder("l1_basic/sast/go_exec_command_variants.go")
    fb.add("package main").add('import "os/exec"').add()
    fb.add("func runShell(input string) {")
    fb.add_target(
        '	_ = exec.Command("sh", "-c", input).Run()',
        "FLAG", "SAST", "L1_BASIC", "SAST-028",
        "Execution of arbitrary shell script string using system shell interpreter"
    )
    fb.add("}")
    fb.add("func runDirect(arg string) {")
    fb.add_target(
        '	_ = exec.Command("ls", "-l", arg).Run()',
        "NO_FLAG", "SAST", "L1_BASIC", "SAST-029",
        "Direct binary execution without intervening shell parser"
    )
    fb.add("}")
    fb.add("func main() {}")
    fixtures.append(fb)

    # 28. Go InsecureSkipVerify (FLAG)
    fb = FixtureBuilder("l1_basic/sast/go_insecure_tls_flag.go")
    fb.add("package main").add('import "crypto/tls"').add()
    fb.add("func createConfig() *tls.Config {")
    fb.add("	return &tls.Config{")
    fb.add_target(
        '		InsecureSkipVerify: true,',
        "FLAG", "SAST", "L1_BASIC", "SAST-030",
        "TLS certificate verification disabled allowing MITM vulnerability"
    )
    fb.add("	}")
    fb.add("}")
    fb.add("func main() {}")
    fixtures.append(fb)

    # 29. Bash eval on Untrusted Input (FLAG)
    fb = FixtureBuilder("l1_basic/sast/bash_eval_flag.sh")
    fb.add("#!/usr/bin/env bash")
    fb.add("read -r user_command")
    fb.add_target(
        'eval "$user_command"',
        "FLAG", "SAST", "L1_BASIC", "SAST-031",
        "Shell eval called directly on unvalidated user terminal input"
    )
    fixtures.append(fb)

    # 30. Bash eval on ssh-agent (DEBATABLE)
    fb = FixtureBuilder("l1_basic/sast/bash_eval_debatable.sh")
    fb.add("#!/usr/bin/env bash")
    fb.add_target(
        'eval "$(ssh-agent -s)"',
        "DEBATABLE", "SAST", "L1_BASIC", "SAST-032",
        "Idiomatic environment setup via ssh-agent process command evaluation"
    )
    fixtures.append(fb)

    # 31. Bash Permissive Permissions (FLAG) vs Restricted (NO_FLAG)
    fb = FixtureBuilder("l1_basic/sast/bash_chmod_variants.sh")
    fb.add("#!/usr/bin/env bash")
    fb.add_target(
        'chmod 777 /var/data/shared_cache',
        "FLAG", "SAST", "L1_BASIC", "SAST-033",
        "World-writable directory permissions granting unrestricted local access"
    )
    fb.add_target(
        'chmod 0755 /var/data/app_bin',
        "NO_FLAG", "SAST", "L1_BASIC", "SAST-034",
        "Standard restricted executable permissions preserving security boundaries"
    )
    fixtures.append(fb)

    # 32. Insecure HTTP Lookalike in SVG Namespace (NO_FLAG)
    fb = FixtureBuilder("l1_basic/sast/http_svg_namespace_noflag.xml")
    fb.add('<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">')
    fb.add_target(
        '  <circle cx="50" cy="50" r="40" stroke="green" stroke-width="4" fill="yellow" />',
        "NO_FLAG", "SAST", "L1_BASIC", "SAST-035",
        "W3C XML namespace URL specification rather than network transport"
    )
    fb.add('</svg>')
    fixtures.append(fb)

    # -------------------------------------------------------------
    # L2 INTERMEDIATE: SAST
    # -------------------------------------------------------------

    # L2-1: Python Data Processing Pipeline
    fb = FixtureBuilder("l2_intermediate/sast/python_pipeline.py")
    fb.add("import ast")
    fb.add("import hashlib")
    fb.add("import os")
    fb.add("import random")
    fb.add("import subprocess")
    fb.add("import yaml").add()
    fb.add("class ReportGenerator:")
    fb.add("    def __init__(self, db_conn):")
    fb.add("        self.conn = db_conn")
    fb.add("        self.eval_mode = False").add()
    fb.add("    def run_query(self, report_id, tag):")
    fb.add("        cursor = self.conn.cursor()")
    fb.add_target(
        '        cursor.execute("SELECT * FROM reports WHERE id = %s", (report_id,))',
        "NO_FLAG", "SAST", "L2_INTERMEDIATE", "SAST-L2-001",
        "Parameterized SQL query protecting database query execution"
    )
    fb.add_target(
        '        cursor.execute("SELECT * FROM logs WHERE tag = \'%s\'" % tag)',
        "FLAG", "SAST", "L2_INTERMEDIATE", "SAST-L2-002",
        "Unsanitized string interpolation directly into secondary SQL query"
    )
    fb.add("        return cursor.fetchall()").add()
    fb.add("    def load_spec(self, raw_yaml):")
    fb.add_target(
        '        return yaml.safe_load(raw_yaml)',
        "NO_FLAG", "SAST", "L2_INTERMEDIATE", "SAST-L2-003",
        "Safe YAML deserializer preventing arbitrary type instantiation"
    )
    fb.add().add("    def load_untrusted_spec(self, raw_yaml):")
    fb.add_target(
        '        return yaml.load(raw_yaml)',
        "FLAG", "SAST", "L2_INTERMEDIATE", "SAST-L2-004",
        "Insecure yaml.load function permitting arbitrary Python execution"
    )
    fb.add().add("    def parse_number_literal(self, val):")
    fb.add_target(
        '        return ast.literal_eval(val)',
        "NO_FLAG", "SAST", "L2_INTERMEDIATE", "SAST-L2-005",
        "Safe AST evaluation restricted to static data literals"
    )
    fb.add().add("    def compute_sha(self, content):")
    fb.add_target(
        '        return hashlib.sha256(content.encode()).hexdigest()',
        "NO_FLAG", "SAST", "L2_INTERMEDIATE", "SAST-L2-006",
        "Standard cryptographic SHA-256 integrity digest"
    )
    fb.add().add("    def archive_output(self, folder):")
    fb.add_target(
        '        subprocess.run(["tar", "-czf", "report.tar.gz", folder], check=True)',
        "NO_FLAG", "SAST", "L2_INTERMEDIATE", "SAST-L2-007",
        "Safe array-based command execution without shell wrapping"
    )
    fixtures.append(fb)

    # L2-2: Node Service Utilities
    fb = FixtureBuilder("l2_intermediate/sast/node_service.js")
    fb.add("const child_process = require('child_process');")
    fb.add("const crypto = require('crypto');").add()
    fb.add("class ServiceEngine {")
    fb.add("  constructor(db) { this.db = db; }").add()
    fb.add("  findUser(id) {")
    fb.add_target(
        '    return this.db.query("SELECT * FROM users WHERE id = $1", [id]);',
        "NO_FLAG", "SAST", "L2_INTERMEDIATE", "SAST-L2-008",
        "Parameterized query argument protecting against SQL injection"
    )
    fb.add("  }").add()
    fb.add("  findUserRaw(id) {")
    fb.add_target(
        '    return this.db.query("SELECT * FROM users WHERE id = " + id);',
        "FLAG", "SAST", "L2_INTERMEDIATE", "SAST-L2-009",
        "SQL query concatenation exposing endpoint to database injection"
    )
    fb.add("  }").add()
    fb.add("  renderStatus(container, msg) {")
    fb.add_target(
        '    container.textContent = msg;',
        "NO_FLAG", "SAST", "L2_INTERMEDIATE", "SAST-L2-010",
        "Safe DOM textContent node update"
    )
    fb.add_target(
        '    container.innerHTML = "<b>Status: Ready</b>";',
        "NO_FLAG", "SAST", "L2_INTERMEDIATE", "SAST-L2-011",
        "Constant benign markup assignment to innerHTML"
    )
    fb.add("  }").add()
    fb.add("  executeDynamic(scriptText) {")
    fb.add_target(
        '    return eval(scriptText);',
        "FLAG", "SAST", "L2_INTERMEDIATE", "SAST-L2-012",
        "Dynamic JavaScript code execution via global eval function"
    )
    fb.add("  }").add()
    fb.add("  inspectTime() {")
    fb.add_target(
        '    return child_process.execFile("/bin/date", ["-u"]);',
        "NO_FLAG", "SAST", "L2_INTERMEDIATE", "SAST-L2-013",
        "Direct binary invocation without shell parsing via execFile"
    )
    fb.add("  }")
    fb.add("}")
    fixtures.append(fb)

    return fixtures
