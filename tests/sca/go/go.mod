module github.com/security/test/go-fixture

go 1.20

require (
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad // CVE-2021-43565
	golang.org/x/net v0.7.0 // CVE-2023-25577
)

require golang.org/x/sys v0.5.0 // indirect
