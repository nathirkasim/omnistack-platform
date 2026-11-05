"""Helm and Kustomize test cases for IaC security benchmark."""

HELM_KUSTOMIZE_CASES = [
    # ---------------------------------------------------------
    # Helm Charts
    # ---------------------------------------------------------
    {
        "id": "HELM-001",
        "iac_type": "helm",
        "category": "helm-kustomize",
        "label": "TRUE_POSITIVE",
        "description": "Helm chart with values.yaml defaults configuring privileged: true and hostNetwork: true",
        "why_scanner_may_fail": "Baseline Helm template evaluation test case.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_K8S_16",
                "cwe": "CWE-250",
                "cis": "CIS Kubernetes 1.6 - 5.2.1",
                "nist": "AC-6",
                "resource": "Deployment.release-name-insecure-app",
                "file": "templates/deployment.yaml",
                "line": 16,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.2.1", "nist_800_53": "AC-6", "pci_dss": "2.2.4", "soc2": "CC6.3"},
        "source_refs": ["https://helm.sh/docs/chart_best_practices/templates/"],
        "undeliverable_static": False,
        "files": {
            "Chart.yaml": """apiVersion: v2
name: insecure-app
description: Standard Helm chart with insecure defaults
type: application
version: 0.1.0
appVersion: "1.0"
""",
            "values.yaml": """privileged: true
hostNetwork: true
image: nginx:latest
""",
            "templates/deployment.yaml": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-insecure-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      hostNetwork: {{ .Values.hostNetwork }}
      containers:
        - name: app
          image: {{ .Values.image }}
          securityContext:
            privileged: {{ .Values.privileged }}
"""
        }
    },
    {
        "id": "HELM-002",
        "iac_type": "helm",
        "category": "helm-kustomize",
        "label": "EVASIVE_MISCONFIG",
        "description": "Helm template conditionally injects hostPath mount and SYS_ADMIN capability under {{- if .Values.debug.enabled }}",
        "why_scanner_may_fail": "Scanners that do not render Helm templates or only inspect raw template files miss vulnerabilities embedded inside Go template conditionals.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_K8S_16",
                "cwe": "CWE-250",
                "cis": "CIS Kubernetes 1.6 - 5.2.1",
                "nist": "AC-6",
                "resource": "Deployment.release-name-cond-app",
                "file": "templates/deployment.yaml",
                "line": 18,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.2.1", "nist_800_53": "AC-6", "pci_dss": "2.2.4", "soc2": "CC6.3"},
        "source_refs": ["https://helm.sh/docs/chart_template_guide/control_structures/"],
        "undeliverable_static": False,
        "files": {
            "Chart.yaml": """apiVersion: v2
name: cond-app
description: Conditionally insecure Helm chart
type: application
version: 0.1.0
""",
            "values.yaml": """debug:
  enabled: true
image: app:1.0.0
""",
            "templates/deployment.yaml": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-cond-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      containers:
        - name: app
          image: {{ .Values.image }}
          {{- if .Values.debug.enabled }}
          securityContext:
            privileged: true
          volumeMounts:
            - mountPath: /var/run/docker.sock
              name: dockersock
          {{- end }}
      {{- if .Values.debug.enabled }}
      volumes:
        - name: dockersock
          hostPath:
            path: /var/run/docker.sock
      {{- end }}
"""
        }
    },
    {
        "id": "HELM-003",
        "iac_type": "helm",
        "category": "helm-kustomize",
        "label": "SAFE_LOOKALIKE",
        "description": "Helm chart delegates container securityContext to a shared named template helper in _helpers.tpl that enforces full hardening",
        "why_scanner_may_fail": "Scanners that do not evaluate {{ include '...' . }} helpers see an empty securityContext in deployment.yaml and trigger False Positives.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_K8S_16", "CKV_K8S_20", "CKV_K8S_21"],
        "compliance": {"cis": "5.2.6", "nist_800_53": "AC-6", "pci_dss": "2.2.4", "soc2": "CC6.3"},
        "source_refs": ["https://helm.sh/docs/chart_template_guide/named_templates/"],
        "undeliverable_static": False,
        "files": {
            "Chart.yaml": """apiVersion: v2
name: secure-app
description: Helm chart utilizing hardened helper templates
type: application
version: 0.1.0
""",
            "values.yaml": """image: secure-worker:2.0.0
""",
            "templates/_helpers.tpl": """{{/*
Common hardened security context
*/}}
{{- define "secure-app.hardenedSecurityContext" -}}
runAsNonRoot: true
runAsUser: 10001
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop:
    - ALL
{{- end }}
""",
            "templates/deployment.yaml": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-secure-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      containers:
        - name: app
          image: {{ .Values.image }}
          securityContext:
            {{- include "secure-app.hardenedSecurityContext" . | nindent 12 }}
"""
        }
    },

    # ---------------------------------------------------------
    # Kustomize Overlays
    # ---------------------------------------------------------
    {
        "id": "KUST-001",
        "iac_type": "kustomize",
        "category": "helm-kustomize",
        "label": "TRUE_POSITIVE",
        "description": "Kustomize production overlay introduces hostNetwork: true and privileged: true via strategic merge patch",
        "why_scanner_may_fail": "Baseline Kustomize overlay evaluation test case.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_K8S_16",
                "cwe": "CWE-250",
                "cis": "CIS Kubernetes 1.6 - 5.2.1",
                "nist": "AC-6",
                "resource": "Deployment.production.workload",
                "file": "patch.yaml",
                "line": 6,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.2.1", "nist_800_53": "AC-6", "pci_dss": "2.2.4", "soc2": "CC6.3"},
        "source_refs": ["https://kubectl.docs.kubernetes.io/references/kustomize/kustomization/patches/"],
        "undeliverable_static": False,
        "files": {
            "base/kustomization.yaml": """apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml
""",
            "base/deployment.yaml": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: workload
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      containers:
        - name: app
          image: app:1.0.0
""",
            "kustomization.yaml": """apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - base/
patchesStrategicMerge:
  - patch.yaml
""",
            "patch.yaml": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: workload
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: app
          securityContext:
            privileged: true
"""
        }
    },
    {
        "id": "KUST-002",
        "iac_type": "kustomize",
        "category": "helm-kustomize",
        "label": "EVASIVE_MISCONFIG",
        "description": "Kustomize overlay strips out security control runAsNonRoot via RFC 6902 JSON patch (op: remove)",
        "why_scanner_may_fail": "Scanners that only understand strategic merge patches fail to interpret RFC 6902 JSON patches (op: remove, path: /spec/template/spec/containers/0/securityContext/runAsNonRoot), missing the removal of protection.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_K8S_20",
                "cwe": "CWE-250",
                "cis": "CIS Kubernetes 1.6 - 5.2.6",
                "nist": "AC-6",
                "resource": "Deployment.default.hardened-workload",
                "file": "kustomization.yaml",
                "line": 10,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.2.6", "nist_800_53": "AC-6", "pci_dss": "2.2.4", "soc2": "CC6.3"},
        "source_refs": ["https://kubectl.docs.kubernetes.io/references/kustomize/kustomization/patchesjson6902/"],
        "undeliverable_static": False,
        "files": {
            "base/deployment.yaml": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: hardened-workload
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      containers:
        - name: app
          image: app:1.0.0
          securityContext:
            runAsNonRoot: true
""",
            "kustomization.yaml": """apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - base/deployment.yaml
patches:
  - target:
      kind: Deployment
      name: hardened-workload
    patch: |-
      - op: remove
        path: /spec/template/spec/containers/0/securityContext/runAsNonRoot
"""
        }
    },
    {
        "id": "KUST-003",
        "iac_type": "kustomize",
        "category": "helm-kustomize",
        "label": "SAFE_LOOKALIKE",
        "description": "Base deployment is missing securityContext, but dev overlay strategic merge patch injects complete hardening",
        "why_scanner_may_fail": "Scanning base manifest in isolation produces a False Positive because the rendered overlay applies the fix.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_K8S_16", "CKV_K8S_20", "CKV_K8S_21"],
        "compliance": {"cis": "5.2.6", "nist_800_53": "AC-6", "pci_dss": "2.2.4", "soc2": "CC6.3"},
        "source_refs": ["https://kubectl.docs.kubernetes.io/references/kustomize/kustomization/patches/"],
        "undeliverable_static": False,
        "files": {
            "base/deployment.yaml": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: workload
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      containers:
        - name: app
          image: app:1.0.0
""",
            "kustomization.yaml": """apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - base/deployment.yaml
patchesStrategicMerge:
  - patch.yaml
""",
            "patch.yaml": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: workload
spec:
  template:
    spec:
      containers:
        - name: app
          securityContext:
            runAsNonRoot: true
            runAsUser: 10001
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
"""
        }
    }
]
