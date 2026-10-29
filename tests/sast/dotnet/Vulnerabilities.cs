using System;
using System.Data;
using Microsoft.Data.SqlClient;
using System.Diagnostics;
using System.IO;

namespace SecurityTest.Sast
{
    public class VulnerabilitiesDotNet
    {
        // =====================================================================
        // TP-SAST-035: SQL Injection via SqlCommand Concatenation (C#)
        // CWE-89 | High Severity
        // =====================================================================
        public void FindUserVulnerable(SqlConnection conn, string userInputId)
        {
            // Vulnerable: Query formed using string concatenation
            string query = "SELECT Id, Name FROM Accounts WHERE Id = '" + userInputId + "'";
            using var cmd = new SqlCommand(query, conn);
            using var reader = cmd.ExecuteReader();
        }

        // =====================================================================
        // FP-SAST-045: Safe Parameterized SqlCommand (C#)
        // Expected: Safe / Parameterized
        // =====================================================================
        public void FindUserSafe(SqlConnection conn, string userInputId)
        {
            string query = "SELECT Id, Name FROM Accounts WHERE Id = @Id";
            using var cmd = new SqlCommand(query, conn);
            // Safe: Strongly-typed SqlParameter binding
            cmd.Parameters.Add("@Id", SqlDbType.VarChar).Value = userInputId;
            using var reader = cmd.ExecuteReader();
        }

        // =====================================================================
        // TP-SAST-036: Command Injection via cmd.exe Shell Invocation (C#)
        // CWE-78 | Critical Severity
        // =====================================================================
        public void RunScriptVulnerable(string userParam)
        {
            // Vulnerable: Command shell execution with user input
            Process.Start("cmd.exe", "/c process_report.bat " + userParam);
        }

        // =====================================================================
        // FP-SAST-046: Safe Process Execution without Shell (C#)
        // Expected: Safe / No Shell
        // =====================================================================
        public void RunScriptSafe(string userParam)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "process_report.exe",
                Arguments = userParam,
                UseShellExecute = false
            };
            Process.Start(startInfo);
        }

        // =====================================================================
        // TP-SAST-037: Path Traversal via Path.Combine (C#)
        // CWE-22 | High Severity
        // =====================================================================
        public string ReadUserDocumentVulnerable(string baseDir, string userFile)
        {
            // Vulnerable: Path.Combine does not prevent "../" directory escape
            string fullPath = Path.Combine(baseDir, userFile);
            return File.ReadAllText(fullPath);
        }

        // =====================================================================
        // FP-SAST-047: Safe Path Canonicalization Guard (C#)
        // Expected: Safe / Guarded
        // =====================================================================
        public string ReadUserDocumentSafe(string baseDir, string userFile)
        {
            string safeRoot = Path.GetFullPath(baseDir);
            string fullPath = Path.GetFullPath(Path.Combine(safeRoot, userFile));

            // Safe: Enforces directory containment
            if (!fullPath.StartsWith(safeRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            {
                throw new UnauthorizedAccessException("Path traversal detected");
            }
            return File.ReadAllText(fullPath);
        }
    }
}
