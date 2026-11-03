module codesec-benchmark/advanced/sca/go

go 1.20

require (
	// GT: id=SCA-GO-1001 type=TP cwe=CVE-2022-21221 rule=cve-fasthttp-transitive technique=transitive-dep-depth-2
	github.com/valyala/fasthttp v1.33.0

	// GT: id=SCA-GO-1002 type=TP cwe=CVE-2020-29652 rule=cve-golang-crypto-diamond technique=diamond-dependency
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad

	// GT: id=SCA-GO-1003 type=TP cwe=CVE-2020-28483 rule=cve-gin-version-range technique=version-range-inequality
	github.com/gin-gonic/gin v1.6.0

	// GT: id=SCA-GO-1004 type=TP cwe=CVE-2020-27847 rule=cve-jwt-vulnerable-call technique=vulnerable-function-called
	github.com/golang-jwt/jwt v3.2.1+incompatible

	// GT: id=SCA-GO-1005 type=TP cwe=CVE-2021-30465 rule=cve-runc-replace-directive technique=go-mod-replace-vulnerable
	github.com/opencontainers/runc v1.0.0-rc92

	// GT: id=SCA-GO-1006 type=TP cwe=CVE-2021-39139 rule=cve-dependency-confusion technique=internal-pkg-name-hijack
	fakecorp.internal/cloud-auth v0.0.1

	// GT: id=SCA-GO-1007 type=TP cwe=CVE-2020-28483 rule=cve-typosquatting technique=typosquat-package
	github.com/ginn-gonic/gin v1.6.0

	// GT: id=SCA-GO-1008 type=TP cwe=CVE-2021-42248 rule=cve-gjson-transitive technique=transitive-dep-depth-3
	github.com/tidwall/gjson v1.9.2

	// --- False Positives ---

	// GT: id=SCA-GO-1009 type=FP reason=vulnerable-function-never-called technique=unreachable-api-surface
	github.com/tidwall/match v1.1.1

	// GT: id=SCA-GO-1010 type=FP reason=test-only-dependency technique=dev-test-scope
	github.com/stretchr/testify v1.8.4

	// GT: id=SCA-GO-1011 type=FP reason=already-patched-version technique=pinned-patched-version
	github.com/gin-contrib/sse v0.1.0

	// GT: id=SCA-GO-1012 type=FP reason=outside-advisory-version-range technique=safe-version-branch
	github.com/golang-jwt/jwt/v5 v5.2.0

	// GT: id=SCA-GO-1013 type=FP reason=monorepo-internal-subpackage technique=monorepo-local-subproject
	github.com/example/benchmark/internal-subpkg v1.0.0

	// GT: id=SCA-GO-1014 type=FP reason=vendored-ignored-directory technique=vendored-code
	github.com/example/vendored/pkg v1.0.0

	// GT: id=SCA-GO-1015 type=FP reason=different-ecosystem-package-name technique=cross-ecosystem-homonym
	github.com/fake/django-go v0.1.0

	// GT: id=SCA-GO-1016 type=FP reason=replace-directive-fixed technique=lockfile-resolutions-override
	golang.org/x/sys v0.13.0
)
