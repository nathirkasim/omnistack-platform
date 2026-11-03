package main

import (
	"html"
	"path/filepath"
	"regexp"
	"strings"
)

func noopSanitize(in string) string {
	return in
}

func wrongContextSanitize(in string) string {
	return html.EscapeString(in)
}

func bypassableBlocklist(in string) string {
	return strings.ReplaceAll(in, "../", "")
}

func strictAlphaNumeric(in string) bool {
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_\-]+$`, in)
	return matched
}

func isSafeCanonicalPath(baseDir, filename string) bool {
	cleanBase := filepath.Clean(baseDir)
	target := filepath.Clean(filepath.Join(baseDir, filename))
	return strings.HasPrefix(target, cleanBase+string(filepath.Separator))
}
