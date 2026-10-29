# frozen_string_literal: true

# SAST Test Fixture: SQL Injection, Command Injection, and Deserialization (Ruby / Rails)
# Covers paired True Positives and False Positives.

class VulnerabilitiesRuby
  # ============================================================================
  # TP-SAST-029: SQL Injection via ActiveRecord String Interpolation
  # CWE-89 | High Severity
  # ============================================================================
  def find_user_vulnerable(user_input_name)
    # Vulnerable: Interpolating untrusted string into where clause
    User.where("username = '#{user_input_name}'")
  end

  # ============================================================================
  # FP-SAST-038: Safe Parameterized ActiveRecord Query
  # Expected: Safe / Parameterized
  # ============================================================================
  def find_user_safe(user_input_name)
    # Safe: Positional placeholder or hash parameter binding
    User.where("username = ?", user_input_name)
  end

  # ============================================================================
  # TP-SAST-030: Command Injection via system string
  # CWE-78 | Critical Severity
  # ============================================================================
  def compress_archive_vulnerable(filename)
    # Vulnerable: Single string argument invokes shell
    system("gzip -f #{filename}")
  end

  # ============================================================================
  # FP-SAST-039: Safe Subprocess Execution with Multi-Argument Array
  # Expected: Safe / No Shell
  # ============================================================================
  def compress_archive_safe(filename)
    # Safe: Passing command and args as distinct arguments bypasses the shell
    system("gzip", "-f", filename)
  end

  # ============================================================================
  # TP-SAST-031: Insecure Deserialization via Marshal.load
  # CWE-502 | Critical Severity
  # ============================================================================
  def load_cache_vulnerable(raw_bytes)
    # Vulnerable: Native Ruby Marshal deserialization can instantiate arbitrary objects
    Marshal.load(raw_bytes)
  end

  # ============================================================================
  # FP-SAST-040: Safe JSON Deserialization
  # Expected: Safe
  # ============================================================================
  def load_cache_safe(json_string)
    require 'json'
    JSON.parse(json_string)
  end
end
