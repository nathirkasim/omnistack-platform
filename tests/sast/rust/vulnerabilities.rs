//! SAST Test Fixture: Command Injection, Path Traversal, and Unsafe Blocks (Rust)
//! Covers paired True Positives and False Positives.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

// =============================================================================
// TP-SAST-038: Command Injection via sh -c (Rust)
// CWE-78 | Critical Severity
// =============================================================================
pub fn run_shell_command_vulnerable(user_input: &str) -> std::io::Result<Output> {
    // Vulnerable: Invokes system shell with user-interpolated string
    Command::new("sh")
        .arg("-c")
        .arg(format!("echo {}", user_input))
        .output()
}

// =============================================================================
// FP-SAST-048: Safe Process Execution without Shell (Rust)
// Expected: Safe / No Shell
// =============================================================================
pub fn run_shell_command_safe(user_input: &str) -> std::io::Result<Output> {
    // Safe: Command arguments passed as direct argv without shell interpretation
    Command::new("echo")
        .arg(user_input)
        .output()
}

// =============================================================================
// TP-SAST-039: Path Traversal via Unvalidated Path Construction (Rust)
// CWE-22 | High Severity
// =============================================================================
pub fn read_file_vulnerable(base_dir: &str, user_path: &str) -> std::io::Result<Vec<u8>> {
    // Vulnerable: PathBuf::join with relative traversal vectors "../"
    let path = PathBuf::from(base_dir).join(user_path);
    fs::read(path)
}

// =============================================================================
// FP-SAST-049: Safe Path Traversal Guard with Canonicalize (Rust)
// Expected: Safe / Guarded
// =============================================================================
pub fn read_file_safe(base_dir: &str, user_path: &str) -> std::io::Result<Vec<u8>> {
    let base = Path::new(base_dir).canonicalize()?;
    let target = base.join(user_path).canonicalize()?;

    // Safe: Validates canonical path prefix
    if !target.starts_with(&base) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Path traversal detected",
        ));
    }
    fs::read(target)
}

// =============================================================================
// TP-SAST-040: Unchecked Raw Pointer Dereference in Unsafe Block (Rust)
// CWE-119 / CWE-476 | Medium Severity
// =============================================================================
pub unsafe fn dereference_raw_pointer_vulnerable(ptr: *const u32, offset: isize) -> u32 {
    // Vulnerable: Unbounded pointer arithmetic dereference without null or boundary checks
    *ptr.offset(offset)
}

// =============================================================================
// FP-SAST-050: Safe Rust Slice Indexing with Bounds Check
// Expected: Safe (Idiomatic Rust safety)
// =============================================================================
pub fn get_slice_element_safe(slice: &[u32], index: usize) -> Option<u32> {
    // Safe: Checked slice indexing returns Option without undefined behavior
    slice.get(index).copied()
}
