"""
SAST Test Fixture: Path Traversal and File Access (Python)
Covers paired True Positives and False Positives.
"""
import os
import pathlib

BASE_UPLOAD_DIR = "/var/app/data/uploads"

# ==============================================================================
# TP-SAST-007: Path Traversal via Unvalidated os.path.join
# CWE-22 | High Severity
# ==============================================================================
def read_user_file_vulnerable(filename_input: str) -> bytes:
    # Vulnerable: If filename_input is '../../etc/passwd', join traverses upward
    target_path = os.path.join(BASE_UPLOAD_DIR, filename_input)
    with open(target_path, "rb") as f:
        return f.read()


# ==============================================================================
# FP-SAST-011: Safe Path Canonicalization and Directory Containment Check
# Expected: Safe / No detection
# ==============================================================================
def read_user_file_safe_canonical(filename_input: str) -> bytes:
    # Resolve real absolute path of target and base directory
    base_dir = os.path.realpath(BASE_UPLOAD_DIR)
    target_path = os.path.realpath(os.path.join(base_dir, filename_input))

    # Safe: Verify that the resolved target path starts with the base directory
    if os.path.commonpath([base_dir]) != os.path.commonpath([base_dir, target_path]):
        raise PermissionError("Access denied: path traversal detected")

    with open(target_path, "rb") as f:
        return f.read()


# ==============================================================================
# FP-SAST-012: Safe pathlib.Path resolution with containment check
# Expected: Safe
# ==============================================================================
def read_user_file_safe_pathlib(filename_input: str) -> bytes:
    base = pathlib.Path(BASE_UPLOAD_DIR).resolve()
    target = (base / filename_input).resolve()
    # Safe: pathlib.Path.is_relative_to guarantees target is strictly inside base
    if not target.is_relative_to(base):
        raise ValueError("Invalid file location")
    return target.read_bytes()


# ==============================================================================
# FP-SAST-013: Benign '../' string used in Unit Test / Fixture path
# Should NOT be flagged as an exploit vector in test context
# ==============================================================================
def load_test_fixture():
    # Benign: Test helper navigating to fixture directory relative to test script
    test_fixture_path = os.path.join(os.path.dirname(__file__), "../../../fixtures/sample.json")
    return os.path.normpath(test_fixture_path)
