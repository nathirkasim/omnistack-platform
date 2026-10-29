package com.security.test.sast;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

/**
 * SAST Test Fixture: Command Injection, Path Traversal, and Deserialization (Java)
 * Covers paired True Positives and False Positives.
 */
public class SecurityVulnerabilitiesJava {

    // =========================================================================
    // TP-SAST-022: Command Injection via Runtime.exec string
    // CWE-78 | Critical Severity
    // =========================================================================
    public Process runSystemDiagnosticVulnerable(String userParam) throws IOException {
        // Vulnerable: Shell string concatenation in Runtime.exec
        return Runtime.getRuntime().exec("sh -c /usr/bin/traceroute " + userParam);
    }

    // =========================================================================
    // FP-SAST-032: Safe Process Execution via ProcessBuilder Array
    // Expected: Safe / No Shell
    // =========================================================================
    public Process runSystemDiagnosticSafe(String userParam) throws IOException {
        // Safe: ProcessBuilder with separate command array arguments
        ProcessBuilder pb = new ProcessBuilder("/usr/bin/traceroute", userParam);
        return pb.start();
    }

    // =========================================================================
    // TP-SAST-023: Path Traversal via Unvalidated File Construction
    // CWE-22 | High Severity
    // =========================================================================
    public File getDocumentFileVulnerable(String filename) {
        File baseDir = new File("/var/storage/docs");
        // Vulnerable: filename can be "../../etc/passwd"
        return new File(baseDir, filename);
    }

    // =========================================================================
    // FP-SAST-033: Safe Path Traversal Canonical Path Guard
    // Expected: Safe / Canonicalization Guard
    // =========================================================================
    public File getDocumentFileSafe(String filename) throws IOException, SecurityException {
        File baseDir = new File("/var/storage/docs").getCanonicalFile();
        File targetFile = new File(baseDir, filename).getCanonicalFile();

        // Safe: Validates canonical path boundary
        if (!targetFile.getPath().startsWith(baseDir.getPath() + File.separator)) {
            throw new SecurityException("Illegal directory traversal attempt");
        }
        return targetFile;
    }

    // =========================================================================
    // TP-SAST-024: Insecure Deserialization via ObjectInputStream
    // CWE-502 | Critical Severity
    // =========================================================================
    public Object deserializePayloadVulnerable(FileInputStream fis) throws IOException, ClassNotFoundException {
        // Vulnerable: Unfiltered Java native deserialization allows arbitrary code execution (gadget chains)
        ObjectInputStream ois = new ObjectInputStream(fis);
        return ois.readObject();
    }
}
