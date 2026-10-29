/**
 * SAST Test Fixture: Cross-Site Scripting (XSS) in React / JSX
 * Covers paired True Positives and False Positives.
 */
import React from 'react';
import DOMPurify from 'dompurify';

interface UserBioProps {
    rawBio: string;
}

// ==============================================================================
// TP-SAST-017: Stored / DOM XSS via unescaped dangerouslySetInnerHTML
// CWE-79 | High Severity
// ==============================================================================
export function UserBioVulnerable({ rawBio }: UserBioProps) {
    // Vulnerable: Passing untrusted prop directly into innerHTML bypasses React escaping
    return <div dangerouslySetInnerHTML={{ __html: rawBio }} />;
}

// ==============================================================================
// FP-SAST-023: Standard React JSX String Interpolation
// Expected: Safe (React escapes HTML characters by default)
// ==============================================================================
export function UserBioSafeDefault({ rawBio }: UserBioProps) {
    // Safe: Rendered as standard text node; HTML tags are escaped
    return <div className="user-bio">{rawBio}</div>;
}

// ==============================================================================
// FP-SAST-024: DOMPurify Sanitized HTML in dangerouslySetInnerHTML
// Expected: Safe (Sanitized before DOM insertion)
// ==============================================================================
export function UserBioSafeSanitized({ rawBio }: UserBioProps) {
    // Safe: Sanitized via trusted library before rendering
    const cleanHtml = DOMPurify.sanitize(rawBio);
    return <div dangerouslySetInnerHTML={{ __html: cleanHtml }} />;
}

// ==============================================================================
// FP-SAST-025: Fixed Static Constant in dangerouslySetInnerHTML
// Expected: Safe (Zero user taint)
// ==============================================================================
export function FooterDisclaimerSafe() {
    const STATIC_DISCLAIMER = '<span>&copy; 2026 <strong>Acme Corp</strong>. All rights reserved.</span>';
    return <footer dangerouslySetInnerHTML={{ __html: STATIC_DISCLAIMER }} />;
}
