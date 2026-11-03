# Advanced Security Cases Coverage Report

**Total Advanced TPs**: 194 | **Detected**: 103 | **Coverage**: 53.09%

**Missed TPs**: 91 | **Flagged FPs**: 20

**Twin Evasion Delta**: +44.72% (Plain: 66.7% vs Evasion: 22.0%)


## Section Breakdown

| Section | Detected | Total | Coverage |
| :--- | :---: | :---: | :---: |
| deep-taint | 21 | 40 | 52.5% |
| evasion | 37 | 83 | 44.6% |
| mutants | 8 | 12 | 66.7% |
| rendered-iac | 6 | 12 | 50.0% |
| secrets-history | 9 | 15 | 60.0% |
| transitive-sca | 22 | 32 | 68.8% |

## Detected TPs

| ID | Section | Language | Technique | Difficulty | File:Line |
| :--- | :--- | :--- | :--- | :--- | :--- |
| EVASION-GO-001 | evasion | go | plain | medium | `advanced/evasion/go/twins.go:21` |
| EVASION-GO-003 | evasion | go | plain | medium | `advanced/evasion/go/twins.go:34` |
| EVASION-GO-009 | evasion | go | plain | medium | `advanced/evasion/go/twins.go:79` |
| EVASION-GO-010 | evasion | go | io-writestring-split-buffers | medium | `advanced/evasion/go/twins.go:84` |
| EVASION-GO-013 | evasion | go | plain | medium | `advanced/evasion/go/twins.go:104` |
| EVASION-GO-014 | evasion | go | hasher-stream-write | medium | `advanced/evasion/go/twins.go:109` |
| EVASION-JAVA-003 | evasion | java | plain | medium | `advanced/evasion/java/Twins.java:35` |
| EVASION-JAVA-004 | evasion | java | string-join-concat | medium | `advanced/evasion/java/Twins.java:42` |
| EVASION-JAVA-005 | evasion | java | plain | medium | `advanced/evasion/java/Twins.java:50` |
| EVASION-JAVA-006 | evasion | java | split-variable-concatenation | medium | `advanced/evasion/java/Twins.java:56` |
| EVASION-JAVA-007 | evasion | java | plain | medium | `advanced/evasion/java/Twins.java:65` |
| EVASION-JAVA-009 | evasion | java | plain | medium | `advanced/evasion/java/Twins.java:76` |
| EVASION-JAVA-010 | evasion | java | string-format-builder | medium | `advanced/evasion/java/Twins.java:81` |
| EVASION-JAVA-011 | evasion | java | plain | medium | `advanced/evasion/java/Twins.java:88` |
| EVASION-JAVA-013 | evasion | java | plain | medium | `advanced/evasion/java/Twins.java:101` |
| EVASION-JAVA-014 | evasion | java | concatenated-algorithm-string | medium | `advanced/evasion/java/Twins.java:106` |
| EVASION-JAVA-015 | evasion | java | plain | medium | `advanced/evasion/java/Twins.java:113` |
| EVASION-NODE-001 | evasion | node | plain | medium | `advanced/evasion/node/twins.js:17` |
| EVASION-NODE-005 | evasion | node | plain | medium | `advanced/evasion/node/twins.js:42` |
| EVASION-NODE-007 | evasion | node | plain | medium | `advanced/evasion/node/twins.js:54` |
| EVASION-NODE-009 | evasion | node | plain | medium | `advanced/evasion/node/twins.js:66` |
| EVASION-PY-001 | evasion | python | plain | medium | `advanced/evasion/python/twins.py:17` |
| EVASION-PY-003 | evasion | python | plain | medium | `advanced/evasion/python/twins.py:29` |
| EVASION-PY-005 | evasion | python | plain | medium | `advanced/evasion/python/twins.py:41` |
| EVASION-PY-007 | evasion | python | plain | medium | `advanced/evasion/python/twins.py:52` |
| EVASION-PY-013 | evasion | python | plain | medium | `advanced/evasion/python/twins.py:92` |
| EVASION-PY-015 | evasion | python | plain | medium | `advanced/evasion/python/twins.py:103` |
| EVASION-SEC-002 | evasion | python | base64-encoded-secret | medium | `advanced/evasion/secrets/secrets_twins.py:14` |
| EVASION-SEC-003 | evasion | python | plain | medium | `advanced/evasion/secrets/secrets_twins.py:19` |
| EVASION-SEC-005 | evasion | python | plain | medium | `advanced/evasion/secrets/secrets_twins.py:27` |
| EVASION-SEC-007 | evasion | yaml | plain | medium | `advanced/evasion/secrets/stripe.yaml:4` |
| EVASION-SEC-013 | evasion | python | plain | medium | `advanced/evasion/secrets/secrets_twins.py:45` |
| EVASION-SEC-014 | evasion | python | single-line-escaped-pem | medium | `advanced/evasion/secrets/secrets_twins.py:50` |
| EVASION-SEC-015 | evasion | node | plain | medium | `advanced/evasion/secrets/minified_bundle.js:4` |
| EVASION-SEC-017 | evasion | python | plain | medium | `advanced/evasion/secrets/secrets_twins.py:55` |
| EVASION-SEC-018 | evasion | python | unicode-escaped-string | medium | `advanced/evasion/secrets/secrets_twins.py:58` |
| EVASION-SEC-019 | evasion | python | plain | medium | `advanced/evasion/secrets/secrets_twins.py:63` |
| HIST-SEC-012 | secrets-history | generic | npmrc-auth-token | medium | `advanced/secrets-history/.npmrc:4` |
| HIST-SEC-013 | secrets-history | generic | pypirc-committed-api-token | medium | `advanced/secrets-history/.pypirc:7` |
| IAC-KUST-0001 | rendered-iac | kubernetes | kustomize-overlay-resolution | medium | `advanced/iac/kustomize/overlays/prod/patch.yaml:14` |
| IAC-KUST-0002 | rendered-iac | kubernetes | kustomize-overlay-resolution | medium | `advanced/iac/kustomize/overlays/prod/patch.yaml:9` |
| IAC-TF-1001 | rendered-iac | terraform | resolved-local-variable | medium | `advanced/iac/terraform/main.tf:26` |
| IAC-TF-1002 | rendered-iac | terraform | dynamic-block-resolution | medium | `advanced/iac/terraform/main.tf:45` |
| IAC-TF-1005 | rendered-iac | terraform | count-block-conditional | medium | `advanced/iac/terraform/main.tf:94` |
| IAC-TF-1006 | rendered-iac | terraform | dynamic-block-iam | medium | `advanced/iac/terraform/main.tf:108` |
| MUTANT-GO-002 | mutants | go | command-injection | medium | `advanced/mutants/mutants.go:16` |
| MUTANT-JAVA-001 | mutants | java | sql-injection | medium | `advanced/mutants/Mutants.java:8` |
| MUTANT-JAVA-002 | mutants | java | sql-injection | medium | `advanced/mutants/Mutants.java:16` |
| MUTANT-NODE-001 | mutants | node | command-injection | medium | `advanced/mutants/mutants.js:8` |
| MUTANT-NODE-002 | mutants | node | code-injection-eval | medium | `advanced/mutants/mutants.js:13` |
| MUTANT-NODE-003 | mutants | node | command-injection | medium | `advanced/mutants/mutants.js:19` |
| MUTANT-PY-002 | mutants | python | sql-injection | medium | `advanced/mutants/mutants.py:21` |
| MUTANT-PY-003 | mutants | python | command-injection | medium | `advanced/mutants/mutants.py:26` |
| SCA-GO-1001 | transitive-sca | go | transitive-dep-depth-2 | medium | `advanced/sca/go/go.mod:7` |
| SCA-GO-1002 | transitive-sca | go | diamond-dependency | medium | `advanced/sca/go/go.mod:10` |
| SCA-GO-1003 | transitive-sca | go | version-range-inequality | medium | `advanced/sca/go/go.mod:13` |
| SCA-GO-1004 | transitive-sca | go | vulnerable-function-called | medium | `advanced/sca/go/go.mod:16` |
| SCA-GO-1005 | transitive-sca | go | go-mod-replace-vulnerable | medium | `advanced/sca/go/go.mod:19` |
| SCA-GO-1008 | transitive-sca | go | transitive-dep-depth-3 | medium | `advanced/sca/go/go.mod:28` |
| SCA-JAVA-1001 | transitive-sca | java | transitive-dep-depth-2 | medium | `advanced/sca/java/pom.xml:12` |
| SCA-JAVA-1002 | transitive-sca | java | diamond-dependency | medium | `advanced/sca/java/pom.xml:19` |
| SCA-JAVA-1003 | transitive-sca | java | version-range-inequality | medium | `advanced/sca/java/pom.xml:26` |
| SCA-JAVA-1004 | transitive-sca | java | vulnerable-function-called | medium | `advanced/sca/java/pom.xml:33` |
| SCA-JAVA-1005 | transitive-sca | java | shaded-fat-jar | medium | `advanced/sca/java/pom.xml:40` |
| SCA-JAVA-1007 | transitive-sca | java | typosquat-package | medium | `advanced/sca/java/pom.xml:54` |
| SCA-JAVA-1008 | transitive-sca | java | transitive-dep-depth-4 | medium | `advanced/sca/java/pom.xml:61` |
| SCA-NODE-1001 | transitive-sca | node | transitive-dep-depth-2 | medium | `advanced/sca/node/package.json:7` |
| SCA-NODE-1004 | transitive-sca | node | vulnerable-function-called | medium | `advanced/sca/node/package.json:13` |
| SCA-NODE-1007 | transitive-sca | node | typosquat-package | medium | `advanced/sca/node/package.json:19` |
| SCA-PY-1001 | transitive-sca | python | transitive-dep-depth-2 | medium | `advanced/sca/python/requirements.txt:4` |
| SCA-PY-1002 | transitive-sca | python | diamond-dependency | medium | `advanced/sca/python/requirements.txt:7` |
| SCA-PY-1003 | transitive-sca | python | version-range-inequality | medium | `advanced/sca/python/requirements.txt:10` |
| SCA-PY-1004 | transitive-sca | python | vulnerable-function-called | medium | `advanced/sca/python/requirements.txt:13` |
| SCA-PY-1005 | transitive-sca | python | manifest-lockfile-mismatch | medium | `advanced/sca/python/requirements.txt:16` |
| SCA-PY-1008 | transitive-sca | python | transitive-dep-depth-3 | medium | `advanced/sca/python/requirements.txt:25` |
| SEC-HIST-002 | secrets-history | python | git-history-deleted-branch-secret | medium | `advanced/secrets-history/history_fixtures.py:10` |
| SEC-HIST-004 | secrets-history | python | git-history-secret-moved-files | medium | `advanced/secrets-history/history_fixtures.py:16` |
| SEC-HIST-005 | secrets-history | yaml | github-actions-hardcoded-secret | medium | `advanced/secrets-history/github-workflow.yml:11` |
| SEC-HIST-007 | secrets-history | generic | jenkins-hardcoded-api-key | medium | `advanced/secrets-history/Jenkinsfile:8` |
| SEC-HIST-008 | secrets-history | dockerfile | dockerfile-arg-npm-token | medium | `advanced/secrets-history/Dockerfile:4` |
| SEC-HIST-010 | secrets-history | yaml | helm-values-plaintext-secret | medium | `advanced/secrets-history/values.yaml:5` |
| SEC-HIST-011 | secrets-history | kubernetes | k8s-secret-base64-token | medium | `advanced/secrets-history/k8s-secret.yaml:8` |
| TAINT-GO-001 | deep-taint | go | deep-taint-sqli | hard | `advanced/taint/go/repository.go:14` |
| TAINT-GO-002 | deep-taint | go | goroutine-channel-exec | hard | `advanced/taint/go/main.go:21` |
| TAINT-GO-003 | deep-taint | go | struct-field-taint-exec | medium | `advanced/taint/go/service.go:30` |
| TAINT-GO-004 | deep-taint | go | closure-function-pointer-exec | hard | `advanced/taint/go/main.go:59` |
| TAINT-GO-005 | deep-taint | go | second-order-sqli | medium | `advanced/taint/go/repository.go:26` |
| TAINT-GO-008 | deep-taint | go | framework-template-html-bypass | hard | `advanced/taint/go/main.go:80` |
| TAINT-JAVA-001 | deep-taint | java | deep-taint-sqli | hard | `advanced/taint/java/OrderRepository.java:17` |
| TAINT-JAVA-005 | deep-taint | java | second-order-sqli | medium | `advanced/taint/java/OrderRepository.java:32` |
| TAINT-JAVA-006 | deep-taint | java | noop-sanitizer-ssrf | medium | `advanced/taint/java/OrderService.java:76` |
| TAINT-JAVA-008 | deep-taint | java | framework-query-string-concat | hard | `advanced/taint/java/DeepTaintController.java:66` |
| TAINT-JAVA-009 | deep-taint | java | bypassable-blocklist-traversal | medium | `advanced/taint/java/OrderService.java:103` |
| TAINT-NODE-003 | deep-taint | node | higher-order-callback-exec | medium | `advanced/taint/node/app.js:33` |
| TAINT-NODE-004 | deep-taint | node | async-event-emitter-exec | hard | `advanced/taint/node/app.js:18` |
| TAINT-NODE-006 | deep-taint | node | noop-sanitizer-ssrf | medium | `advanced/taint/node/service.js:67` |
| TAINT-NODE-009 | deep-taint | node | bypassable-blocklist-traversal | medium | `advanced/taint/node/service.js:88` |
| TAINT-PY-001 | deep-taint | python | deep-taint-sqli | hard | `advanced/taint/python/repository.py:14` |
| TAINT-PY-002 | deep-taint | python | class-field-taint-exec | hard | `advanced/taint/python/service.py:30` |
| TAINT-PY-003 | deep-taint | python | closure-callback-command-injection | medium | `advanced/taint/python/service.py:45` |
| TAINT-PY-005 | deep-taint | python | second-order-sqli | medium | `advanced/taint/python/repository.py:26` |
| TAINT-PY-008 | deep-taint | python | framework-mark-safe-xss | hard | `advanced/taint/python/controller.py:96` |
| TAINT-PY-009 | deep-taint | python | bypassable-blocklist-traversal | medium | `advanced/taint/python/service.py:90` |

## Missed TPs (Blind Spots)

| ID | Section | Language | Technique | Difficulty | Reason | File:Line |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| EVASION-GO-002 | evasion | go | function-pointer-slice-unpack | medium | exploitable-command-injection | `advanced/evasion/go/twins.go:26` |
| EVASION-GO-004 | evasion | go | strings-join-concatenation | medium | exploitable-sql-injection | `advanced/evasion/go/twins.go:40` |
| EVASION-GO-005 | evasion | go | plain | medium | exploitable-path-traversal | `advanced/evasion/go/twins.go:48` |
| EVASION-GO-006 | evasion | go | string-builder-join | medium | exploitable-path-traversal | `advanced/evasion/go/twins.go:53` |
| EVASION-GO-007 | evasion | go | plain | medium | exploitable-ssrf | `advanced/evasion/go/twins.go:63` |
| EVASION-GO-008 | evasion | go | custom-client-do-request | medium | exploitable-ssrf | `advanced/evasion/go/twins.go:68` |
| EVASION-GO-011 | evasion | go | plain | medium | exploitable-open-redirect | `advanced/evasion/go/twins.go:92` |
| EVASION-GO-012 | evasion | go | manual-header-status-code | medium | exploitable-open-redirect | `advanced/evasion/go/twins.go:97` |
| EVASION-GO-015 | evasion | go | plain | medium | exploitable-insecure-randomness | `advanced/evasion/go/twins.go:117` |
| EVASION-GO-016 | evasion | go | custom-math-rand-source | medium | exploitable-insecure-randomness | `advanced/evasion/go/twins.go:122` |
| EVASION-JAVA-001 | evasion | java | plain | medium | exploitable-command-injection | `advanced/evasion/java/Twins.java:21` |
| EVASION-JAVA-002 | evasion | java | process-builder-reflection | medium | exploitable-command-injection | `advanced/evasion/java/Twins.java:26` |
| EVASION-JAVA-008 | evasion | java | uri-to-url-delegation | medium | exploitable-ssrf | `advanced/evasion/java/Twins.java:70` |
| EVASION-JAVA-012 | evasion | java | reflection-constructor-instantiation | medium | exploitable-insecure-deserialization | `advanced/evasion/java/Twins.java:93` |
| EVASION-JAVA-016 | evasion | java | split-variable-response-header | medium | exploitable-open-redirect | `advanced/evasion/java/Twins.java:118` |
| EVASION-NODE-002 | evasion | node | computed-property-require | medium | exploitable-command-injection | `advanced/evasion/node/twins.js:22` |
| EVASION-NODE-003 | evasion | node | plain | medium | exploitable-sql-injection | `advanced/evasion/node/twins.js:30` |
| EVASION-NODE-004 | evasion | node | array-join-string-concat | medium | exploitable-sql-injection | `advanced/evasion/node/twins.js:35` |
| EVASION-NODE-006 | evasion | node | global-scope-computed-access | medium | exploitable-code-injection-eval | `advanced/evasion/node/twins.js:47` |
| EVASION-NODE-008 | evasion | node | object-property-dynamic-read | medium | exploitable-path-traversal | `advanced/evasion/node/twins.js:59` |
| EVASION-NODE-010 | evasion | node | dynamic-http-module-dispatch | medium | exploitable-ssrf | `advanced/evasion/node/twins.js:71` |
| EVASION-NODE-011 | evasion | node | plain | medium | exploitable-reflected-xss | `advanced/evasion/node/twins.js:79` |
| EVASION-NODE-012 | evasion | node | template-array-join | medium | exploitable-reflected-xss | `advanced/evasion/node/twins.js:84` |
| EVASION-NODE-013 | evasion | node | plain | medium | exploitable-weak-crypto-hash | `advanced/evasion/node/twins.js:91` |
| EVASION-NODE-014 | evasion | node | computed-algorithm-identifier | medium | exploitable-weak-crypto-hash | `advanced/evasion/node/twins.js:96` |
| EVASION-NODE-015 | evasion | node | plain | medium | exploitable-open-redirect | `advanced/evasion/node/twins.js:103` |
| EVASION-NODE-016 | evasion | node | computed-header-name-set | medium | exploitable-open-redirect | `advanced/evasion/node/twins.js:109` |
| EVASION-PY-002 | evasion | python | getattr-dynamic-import | medium | exploitable-command-injection | `advanced/evasion/python/twins.py:21` |
| EVASION-PY-004 | evasion | python | join-concatenation | medium | exploitable-sql-injection | `advanced/evasion/python/twins.py:34` |
| EVASION-PY-006 | evasion | python | function-aliasing | medium | exploitable-code-injection-eval | `advanced/evasion/python/twins.py:45` |
| EVASION-PY-008 | evasion | python | split-variable-concatenation | medium | exploitable-path-traversal | `advanced/evasion/python/twins.py:57` |
| EVASION-PY-009 | evasion | python | plain | medium | exploitable-ssrf | `advanced/evasion/python/twins.py:67` |
| EVASION-PY-010 | evasion | python | dynamic-module-attribute | medium | exploitable-ssrf | `advanced/evasion/python/twins.py:71` |
| EVASION-PY-011 | evasion | python | plain | medium | exploitable-reflected-xss | `advanced/evasion/python/twins.py:79` |
| EVASION-PY-012 | evasion | python | multiline-f-string | medium | exploitable-reflected-xss | `advanced/evasion/python/twins.py:83` |
| EVASION-PY-014 | evasion | python | dictionary-function-pointer | medium | exploitable-insecure-deserialization | `advanced/evasion/python/twins.py:96` |
| EVASION-PY-016 | evasion | python | dynamic-hash-lookup | medium | exploitable-weak-crypto-hash | `advanced/evasion/python/twins.py:107` |
| EVASION-SEC-001 | evasion | python | plain | medium | exploitable-aws-secret-access-key | `advanced/evasion/secrets/secrets_twins.py:11` |
| EVASION-SEC-004 | evasion | python | hex-encoded-token | medium | exploitable-github-personal-access-token | `advanced/evasion/secrets/secrets_twins.py:22` |
| EVASION-SEC-006 | evasion | python | split-variable-concatenation | medium | exploitable-slack-bot-token | `advanced/evasion/secrets/secrets_twins.py:30` |
| EVASION-SEC-008 | evasion | yaml | nested-yaml-property | medium | exploitable-stripe-secret-key | `advanced/evasion/secrets/stripe.yaml:9` |
| EVASION-SEC-009 | evasion | generic | plain | medium | exploitable-google-api-key | `advanced/evasion/secrets/google_keys.xml:4` |
| EVASION-SEC-010 | evasion | generic | xml-cdata-block | medium | exploitable-google-api-key | `advanced/evasion/secrets/google_keys.xml:7` |
| EVASION-SEC-011 | evasion | python | plain | medium | exploitable-db-password-in-uri | `advanced/evasion/secrets/secrets_twins.py:37` |
| EVASION-SEC-012 | evasion | python | low-entropy-password | medium | exploitable-db-password-in-uri | `advanced/evasion/secrets/secrets_twins.py:40` |
| EVASION-SEC-016 | evasion | node | minified-js-comment | medium | exploitable-jwt-secret-in-code | `advanced/evasion/secrets/minified_bundle.js:7` |
| HIST-SEC-006 | secrets-history | yaml | gitlab-ci-hardcoded-secret | medium | exploitable-gitlab-ci-hardcoded-secret | `advanced/secrets-history/.gitlab-ci.yml:8` |
| IAC-HELM-0001 | rendered-iac | yaml | helm-render-resolution | medium | exploitable-helm-template-privileged-enabled | `advanced/iac/helm/templates/deployment.yaml:15` |
| IAC-HELM-0002 | rendered-iac | yaml | helm-render-resolution | medium | exploitable-helm-template-docker-socket | `advanced/iac/helm/templates/deployment.yaml:24` |
| IAC-HELM-0003 | rendered-iac | yaml | helm-render-resolution | medium | exploitable-helm-template-ingress-tls-disabled | `advanced/iac/helm/templates/deployment.yaml:46` |
| IAC-KUST-0003 | rendered-iac | kubernetes | kustomize-overlay-resolution | medium | exploitable-kustomize-overlay-sensitive-hostpath | `advanced/iac/kustomize/overlays/prod/patch.yaml:19` |
| IAC-TF-1003 | rendered-iac | terraform | module-parameter-resolution | medium | exploitable-module-call-storage-unencrypted | `advanced/iac/terraform/main.tf:127` |
| IAC-TF-1004 | rendered-iac | terraform | cross-resource-correlation | medium | exploitable-cross-resource-public-instance-exposed | `advanced/iac/terraform/main.tf:69` |
| MUTANT-GO-001 | mutants | go | sql-injection | medium | exploitable-sql-injection | `advanced/mutants/mutants.go:10` |
| MUTANT-JAVA-003 | mutants | java | command-injection | medium | exploitable-command-injection | `advanced/mutants/Mutants.java:22` |
| MUTANT-PY-001 | mutants | python | sql-injection | medium | exploitable-sql-injection | `advanced/mutants/mutants.py:9` |
| MUTANT-PY-004 | mutants | python | reflected-xss | medium | exploitable-reflected-xss | `advanced/mutants/mutants.py:32` |
| SCA-GO-1006 | transitive-sca | go | internal-pkg-name-hijack | medium | exploitable-cve-dependency-confusion | `advanced/sca/go/go.mod:22` |
| SCA-GO-1007 | transitive-sca | go | typosquat-package | medium | exploitable-cve-typosquatting | `advanced/sca/go/go.mod:25` |
| SCA-JAVA-1006 | transitive-sca | java | internal-pkg-name-hijack | medium | exploitable-cve-dependency-confusion | `advanced/sca/java/pom.xml:47` |
| SCA-NODE-1002 | transitive-sca | node | diamond-dependency | medium | exploitable-cve-minimist-diamond | `advanced/sca/node/package.json:9` |
| SCA-NODE-1003 | transitive-sca | node | version-range-inequality | medium | exploitable-cve-lodash-range-resolution | `advanced/sca/node/package.json:11` |
| SCA-NODE-1005 | transitive-sca | node | package-json-overrides-vulnerable | medium | exploitable-cve-axios-overrides | `advanced/sca/node/package.json:15` |
| SCA-NODE-1006 | transitive-sca | node | internal-pkg-name-hijack | medium | exploitable-cve-dependency-confusion | `advanced/sca/node/package.json:17` |
| SCA-NODE-1008 | transitive-sca | node | transitive-dep-depth-3 | medium | exploitable-cve-node-fetch-transitive | `advanced/sca/node/package.json:21` |
| SCA-PY-1006 | transitive-sca | python | internal-pkg-name-hijack | medium | exploitable-cve-dependency-confusion | `advanced/sca/python/requirements.txt:19` |
| SCA-PY-1007 | transitive-sca | python | typosquat-package | medium | exploitable-cve-typosquatting-lookalike | `advanced/sca/python/requirements.txt:22` |
| SEC-HIST-001 | secrets-history | python | git-history-committed-then-deleted | medium | exploitable-git-history-committed-then-deleted | `advanced/secrets-history/history_fixtures.py:7` |
| SEC-HIST-003 | secrets-history | python | git-history-rotated-stale-secret | medium | exploitable-git-history-rotated-stale-secret | `advanced/secrets-history/history_fixtures.py:13` |
| SEC-HIST-009 | secrets-history | generic | tfvars-committed-password | medium | exploitable-tfvars-committed-password | `advanced/secrets-history/terraform.tfvars:4` |
| SEC-HIST-014 | secrets-history | generic | maven-settings-plaintext-password | medium | exploitable-maven-settings-plaintext-password | `advanced/secrets-history/settings.xml:7` |
| SEC-HIST-015 | secrets-history | yaml | openapi-example-hardcoded-api-key | medium | exploitable-openapi-example-hardcoded-api-key | `advanced/secrets-history/openapi-spec.yaml:15` |
| TAINT-GO-006 | deep-taint | go | noop-sanitizer-ssrf | medium | exploitable-noop-sanitizer-ssrf | `advanced/taint/go/service.go:61` |
| TAINT-GO-007 | deep-taint | go | wrong-context-sanitizer-sqli | medium | exploitable-wrong-context-sanitizer-sqli | `advanced/taint/go/service.go:76` |
| TAINT-GO-009 | deep-taint | go | bypassable-blocklist-traversal | medium | exploitable-bypassable-blocklist-traversal | `advanced/taint/go/service.go:82` |
| TAINT-GO-010 | deep-taint | go | idor-unauthorized-update | medium | exploitable-idor-unauthorized-update | `advanced/taint/go/repository.go:38` |
| TAINT-JAVA-002 | deep-taint | java | class-field-taint-exec | hard | exploitable-class-field-taint-exec | `advanced/taint/java/OrderService.java:45` |
| TAINT-JAVA-003 | deep-taint | java | stream-lambda-command-injection | medium | exploitable-stream-lambda-command-injection | `advanced/taint/java/OrderService.java:57` |
| TAINT-JAVA-004 | deep-taint | java | unsafe-reflection-invocation | hard | exploitable-unsafe-reflection-invocation | `advanced/taint/java/DeepTaintController.java:52` |
| TAINT-JAVA-007 | deep-taint | java | wrong-context-sanitizer-sqli | medium | exploitable-wrong-context-sanitizer-sqli | `advanced/taint/java/OrderService.java:97` |
| TAINT-JAVA-010 | deep-taint | java | idor-unauthorized-update | medium | exploitable-idor-unauthorized-update | `advanced/taint/java/OrderRepository.java:45` |
| TAINT-NODE-001 | deep-taint | node | deep-taint-sqli | hard | exploitable-deep-taint-sqli | `advanced/taint/node/repository.js:12` |
| TAINT-NODE-002 | deep-taint | node | class-field-taint-exec | hard | exploitable-class-field-taint-exec | `advanced/taint/node/service.js:34` |
| TAINT-NODE-005 | deep-taint | node | second-order-sqli | medium | exploitable-second-order-sqli | `advanced/taint/node/repository.js:22` |
| TAINT-NODE-007 | deep-taint | node | wrong-context-sanitizer-sqli | medium | exploitable-wrong-context-sanitizer-sqli | `advanced/taint/node/service.js:82` |
| TAINT-NODE-008 | deep-taint | node | framework-unescaped-send-xss | hard | exploitable-framework-unescaped-send-xss | `advanced/taint/node/app.js:58` |
| TAINT-NODE-010 | deep-taint | node | idor-unauthorized-update | medium | exploitable-idor-unauthorized-update | `advanced/taint/node/repository.js:32` |
| TAINT-PY-004 | deep-taint | python | async-generator-open-redirect | hard | exploitable-async-generator-open-redirect | `advanced/taint/python/controller.py:78` |
| TAINT-PY-006 | deep-taint | python | noop-sanitizer-ssrf | medium | exploitable-noop-sanitizer-ssrf | `advanced/taint/python/service.py:74` |
| TAINT-PY-007 | deep-taint | python | wrong-context-sanitizer-sqli | medium | exploitable-wrong-context-sanitizer-sqli | `advanced/taint/python/service.py:85` |
| TAINT-PY-010 | deep-taint | python | idor-unauthorized-update | medium | exploitable-idor-unauthorized-update | `advanced/taint/python/repository.py:38` |

## Flagged False Positives

| ID | Section | Language | Reason Safe | File:Line |
| :--- | :--- | :--- | :--- | :--- |
| IAC-KUST-0004 | rendered-iac | kubernetes | unsafe-base-fixed-by-safe-overlay | `advanced/iac/kustomize/overlays/dev/patch.yaml:12` |
| IAC-TF-1007 | rendered-iac | terraform | dev-environment-resolves-private-acl | `advanced/iac/terraform/main.tf:32` |
| IAC-TF-1012 | rendered-iac | terraform | count-zero-resource-not-created | `advanced/iac/terraform/main.tf:101` |
| SCA-GO-1012 | transitive-sca | go | outside-advisory-version-range | `advanced/sca/go/go.mod:42` |
| SCA-GO-1015 | transitive-sca | go | different-ecosystem-package-name | `advanced/sca/go/go.mod:51` |
| SCA-JAVA-1012 | transitive-sca | java | outside-advisory-version-range | `advanced/sca/java/pom.xml:92` |
| SCA-NODE-1009 | transitive-sca | node | vulnerable-function-never-called | `advanced/sca/node/package.json:23` |
| SCA-NODE-1012 | transitive-sca | node | outside-advisory-version-range | `advanced/sca/node/package.json:27` |
| SCA-PY-1011 | transitive-sca | python | already-patched-version | `advanced/sca/python/requirements.txt:36` |
| SCA-PY-1012 | transitive-sca | python | outside-advisory-version-range | `advanced/sca/python/requirements.txt:39` |
| SEC-HIST-019 | secrets-history | dockerfile | dockerfile-arg-standard-env-placeholder | `advanced/secrets-history/Dockerfile:7` |
| TAINT-GO-016 | deep-taint | go | correct-html-escape | `advanced/taint/go/main.go:87` |
| TAINT-GO-020 | deep-taint | go | role-based-auth-guard | `advanced/taint/go/main.go:107` |
| TAINT-JAVA-016 | deep-taint | java | correct-html-escape | `advanced/taint/java/DeepTaintController.java:73` |
| TAINT-JAVA-018 | deep-taint | java | canonical-validator-path-traversal | `advanced/taint/java/OrderService.java:112` |
| TAINT-JAVA-019 | deep-taint | java | constant-query-sink | `advanced/taint/java/OrderRepository.java:39` |
| TAINT-NODE-017 | deep-taint | node | strict-url-host-allowlist | `advanced/taint/node/service.js:76` |
| TAINT-NODE-018 | deep-taint | node | canonical-validator-path-traversal | `advanced/taint/node/service.js:96` |
| TAINT-PY-016 | deep-taint | python | correct-markup-escape | `advanced/taint/python/controller.py:104` |
| TAINT-PY-018 | deep-taint | python | canonical-validator-path-traversal | `advanced/taint/python/service.py:97` |