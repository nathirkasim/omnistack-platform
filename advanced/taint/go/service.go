package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
)

type StatefulTaskService struct {
	pendingCmd     string
	sanitizedField string
}

func (s *StatefulTaskService) StageCommand(cmd string) {
	s.pendingCmd = cmd
}

func (s *StatefulTaskService) StageSafeField(field string) {
	if strictAlphaNumeric(field) {
		s.sanitizedField = field
	} else {
		s.sanitizedField = "safe_default"
	}
}

func (s *StatefulTaskService) DispatchPending() ([]byte, error) {
	// GT: id=TAINT-GO-003 type=TP cwe=CWE-78 rule=struct-field-taint-exec
	return exec.Command("sh", "-c", s.pendingCmd).Output()
}

func (s *StatefulTaskService) DispatchSafe() ([]byte, error) {
	// GT: id=TAINT-GO-013 type=FP reason=sanitized-struct-field-exec
	return exec.Command("echo", s.sanitizedField).Output()
}

type OrderService struct {
	repo *OrderRepository
}

func (s *OrderService) ProcessOrderFilter(rawFilter string) error {
	return s.stepOne(rawFilter)
}

func (s *OrderService) stepOne(f string) error {
	return s.stepTwo(f)
}

func (s *OrderService) stepTwo(f string) error {
	return s.repo.ExecuteRawSQL(f)
}

func (s *OrderService) ProcessSafeOrder(rawID string) error {
	return s.repo.ExecuteParameterized(rawID)
}

func (s *OrderService) FetchWithNoop(rawURL string) (*http.Response, error) {
	cleaned := noopSanitize(rawURL)
	// GT: id=TAINT-GO-006 type=TP cwe=CWE-918 rule=noop-sanitizer-ssrf
	return http.Get(cleaned)
}

func (s *OrderService) FetchWithAllowlist(rawURL string) (*http.Response, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "https") || parsed.Host != "api.internal.service" {
		return nil, fmt.Errorf("forbidden")
	}
	// GT: id=TAINT-GO-017 type=FP reason=strict-url-host-allowlist
	return http.Get(rawURL)
}

func (s *OrderService) QueryWithWrongSanitizer(userStr string) error {
	escaped := wrongContextSanitize(userStr)
	// GT: id=TAINT-GO-007 type=TP cwe=CWE-89 rule=wrong-context-sanitizer-sqli
	return s.repo.ExecuteRawSQL(escaped)
}

func (s *OrderService) ReadWithBypassableBlocklist(baseDir, filename string) ([]byte, error) {
	cleaned := bypassableBlocklist(filename)
	// GT: id=TAINT-GO-009 type=TP cwe=CWE-22 rule=bypassable-blocklist-traversal
	return os.ReadFile(baseDir + "/" + cleaned)
}

func (s *OrderService) ReadWithCanonicalCheck(baseDir, filename string) ([]byte, error) {
	if !isSafeCanonicalPath(baseDir, filename) {
		return nil, fmt.Errorf("forbidden")
	}
	// GT: id=TAINT-GO-018 type=FP reason=canonical-validator-path-traversal
	return os.ReadFile(baseDir + "/" + filename)
}
