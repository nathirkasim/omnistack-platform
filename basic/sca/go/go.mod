module codesec-benchmark/basic/sca/go

go 1.20

require (

	// GT: id=SCA-GO-004 type=TP cwe=CVE-2021-20206 rule=cve-cni-iptables-injection
	github.com/containernetworking/cni v0.8.0

	// --- False Positive Traps ---

	// GT: id=SCA-GO-009 type=FP reason=already-patched-version
	github.com/gin-contrib/sse v0.1.0
	// GT: id=SCA-GO-001 type=TP cwe=CVE-2020-28483 rule=cve-gin-crlf-injection
	github.com/gin-gonic/gin v1.6.0

	// GT: id=SCA-GO-005 type=TP cwe=CVE-2020-27847 rule=cve-jwt-key-confusion
	github.com/golang-jwt/jwt v3.2.1+incompatible

	// GT: id=SCA-GO-011 type=FP reason=already-patched-version
	github.com/golang-jwt/jwt/v5 v5.0.0

	// GT: id=SCA-GO-016 type=FP reason=safe-utility-no-cve
	github.com/google/uuid v1.4.0

	// GT: id=SCA-GO-008 type=TP cwe=CVE-2020-35380 rule=cve-xml-roundtrip-bypass
	github.com/mattermost/xml-roundtrip-validator v0.1.0

	// GT: id=SCA-GO-003 type=TP cwe=CVE-2021-30465 rule=cve-runc-mount-escape
	github.com/opencontainers/runc v1.0.0-rc92

	// GT: id=SCA-GO-010 type=FP reason=test-assertion-library-only
	github.com/stretchr/testify v1.8.4

	// GT: id=SCA-GO-007 type=TP cwe=CVE-2021-42248 rule=cve-gjson-dos
	github.com/tidwall/gjson v1.9.3

	// GT: id=SCA-GO-014 type=FP reason=already-patched-version
	github.com/tidwall/match v1.1.1

	// GT: id=SCA-GO-012 type=FP reason=already-patched-version
	github.com/valyala/bytebufferpool v1.0.0

	// GT: id=SCA-GO-006 type=TP cwe=CVE-2022-21221 rule=cve-fasthttp-header-overflow
	github.com/valyala/fasthttp v1.33.0

	// GT: id=SCA-GO-002 type=TP cwe=CVE-2020-29652 rule=cve-golang-crypto-panic
	golang.org/x/crypto v0.0.0-20220112180741-5e0467b6c7ce

	// GT: id=SCA-GO-015 type=FP reason=already-patched-version
	golang.org/x/sys v0.13.0

	// GT: id=SCA-GO-013 type=FP reason=dev-tooling-only
	golang.org/x/tools v0.14.0
)

require github.com/tidwall/pretty v1.2.0 // indirect
