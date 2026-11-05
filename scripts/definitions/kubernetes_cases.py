"""Kubernetes manifest test cases for IaC security benchmark."""

KUBERNETES_CASES = [
    # ---------------------------------------------------------
    # Workload Security (Containers, Pods, Privileged, Host Access)
    # ---------------------------------------------------------
    {
        "id": "K8S-SEC-001",
        "iac_type": "kubernetes",
        "category": "kubernetes-security",
        "label": "TRUE_POSITIVE",
        "description": "Deployment with privileged: true, hostNetwork: true, and hostPath mount to /var/run/docker.sock",
        "why_scanner_may_fail": "Baseline Kubernetes misconfiguration; must be detected by all K8s security scanners.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_K8S_16",
                "cwe": "CWE-250",
                "cis": "CIS Kubernetes 1.6 - 5.2.1",
                "nist": "AC-3, AC-6",
                "resource": "Deployment.production.critical-backend",
                "file": "deployment.yaml",
                "line": 15,
                "severity": "CRITICAL"
            },
            {
                "rule": "CKV_K8S_19",
                "cwe": "CWE-284",
                "cis": "CIS Kubernetes 1.6 - 5.2.4",
                "nist": "SC-7",
                "resource": "Deployment.production.critical-backend",
                "file": "deployment.yaml",
                "line": 12,
                "severity": "HIGH"
            },
            {
                "rule": "CKV_K8S_27",
                "cwe": "CWE-284",
                "cis": "CIS Kubernetes 1.6 - 5.2.7",
                "nist": "AC-3",
                "resource": "Deployment.production.critical-backend",
                "file": "deployment.yaml",
                "line": 28,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.2.1", "nist_800_53": "AC-6", "pci_dss": "2.2.4", "soc2": "CC6.3"},
        "source_refs": ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
        "undeliverable_static": False,
        "files": {
            "deployment.yaml": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: critical-backend
  namespace: production
spec:
  replicas: 1
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
    spec:
      hostNetwork: true
      containers:
        - name: app
          image: backend-service:1.2.0
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
            runAsNonRoot: false
          volumeMounts:
            - mountPath: /var/run/docker.sock
              name: dockersock
      volumes:
        - name: dockersock
          hostPath:
            path: /var/run/docker.sock
"""
        }
    },
    {
        "id": "K8S-SEC-002",
        "iac_type": "kubernetes",
        "category": "kubernetes-security",
        "label": "EVASIVE_MISCONFIG",
        "description": "CronJob where primary application container is hardened, but an initContainer runs privileged with hostPath mount to /etc",
        "why_scanner_may_fail": "Scanners that only inspect Deployment kind or only traverse spec.template.spec.containers fail to examine initContainers in batch CronJobs.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_K8S_16",
                "cwe": "CWE-250",
                "cis": "CIS Kubernetes 1.6 - 5.2.1",
                "nist": "AC-6",
                "resource": "CronJob.maintenance.database-backup",
                "file": "cronjob.yaml",
                "line": 18,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.2.1", "nist_800_53": "AC-6", "pci_dss": "2.2.4", "soc2": "CC6.3"},
        "source_refs": ["https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/"],
        "undeliverable_static": False,
        "files": {
            "cronjob.yaml": """apiVersion: batch/v1
kind: CronJob
metadata:
  name: database-backup
  namespace: maintenance
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          initContainers:
            - name: system-prep
              image: alpine:3.19
              securityContext:
                privileged: true
              volumeMounts:
                - name: host-etc
                  mountPath: /host/etc
          containers:
            - name: backup-worker
              image: backup-worker:1.0.0
              securityContext:
                readOnlyRootFilesystem: true
                runAsNonRoot: true
                runAsUser: 10001
          volumes:
            - name: host-etc
              hostPath:
                path: /etc
"""
        }
    },
    {
        "id": "K8S-SEC-003",
        "iac_type": "kubernetes",
        "category": "kubernetes-security",
        "label": "SAFE_LOOKALIKE",
        "description": "Fully hardened Pod with readOnlyRootFilesystem, dropped capabilities, no privilege escalation, and non-root execution",
        "why_scanner_may_fail": "Ideal hardened pod baseline. No security findings should be triggered.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_K8S_16", "CKV_K8S_20", "CKV_K8S_21", "CKV_K8S_22", "CKV_K8S_37"],
        "compliance": {"cis": "5.2.6", "nist_800_53": "AC-6", "pci_dss": "2.2.4", "soc2": "CC6.3"},
        "source_refs": ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
        "undeliverable_static": False,
        "files": {
            "pod.yaml": """apiVersion: v1
kind: Pod
metadata:
  name: secure-worker
  namespace: restricted-zone
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: worker
      image: registry.example.com/worker:v1.2.3@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      resources:
        limits:
          cpu: "500m"
          memory: "512Mi"
        requests:
          cpu: "100m"
          memory: "128Mi"
"""
        }
    },
    {
        "id": "K8S-SEC-004",
        "iac_type": "kubernetes",
        "category": "kubernetes-security",
        "label": "EVASIVE_MISCONFIG",
        "description": "Multi-document YAML file where Doc 1 is a benign ConfigMap, Doc 2 is a secure frontend, and Doc 3 is an unconfined privileged DaemonSet",
        "why_scanner_may_fail": "Scanners with incomplete YAML multi-document parsers only scan the first document (---) in a stream and miss subsequent vulnerable documents.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_K8S_16",
                "cwe": "CWE-250",
                "cis": "CIS Kubernetes 1.6 - 5.2.1",
                "nist": "AC-6",
                "resource": "DaemonSet.kube-system.node-debugger",
                "file": "multi-workload.yaml",
                "line": 45,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.2.1", "nist_800_53": "AC-6", "pci_dss": "2.2.4", "soc2": "CC6.3"},
        "source_refs": ["https://yaml.org/spec/1.2/spec.html#id2760395"],
        "undeliverable_static": False,
        "files": {
            "multi-workload.yaml": """apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: production
data:
  ENVIRONMENT: "production"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-frontend
  namespace: production
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: nginx:1.25.3
          securityContext:
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 101
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-debugger
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: node-debugger
  template:
    metadata:
      labels:
        app: node-debugger
    spec:
      hostPID: true
      hostNetwork: true
      containers:
        - name: debugger
          image: busybox:1.36
          securityContext:
            privileged: true
"""
        }
    },
    {
        "id": "K8S-SEC-005",
        "iac_type": "kubernetes",
        "category": "kubernetes-security",
        "label": "EVASIVE_MISCONFIG",
        "description": "YAML anchor definition (&base_sec) has safe settings but subsequent key override sets privileged: true after the alias",
        "why_scanner_may_fail": "Scanners that parse YAML anchors with simple shallow replacement may only inspect the anchor definition and miss the overridden property.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_K8S_16",
                "cwe": "CWE-250",
                "cis": "CIS Kubernetes 1.6 - 5.2.1",
                "nist": "AC-6",
                "resource": "Deployment.default.anchor-override",
                "file": "deployment.yaml",
                "line": 18,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.2.1", "nist_800_53": "AC-6", "pci_dss": "2.2.4", "soc2": "CC6.3"},
        "source_refs": ["https://yaml.org/spec/1.2/spec.html#id2765865"],
        "undeliverable_static": False,
        "files": {
            "deployment.yaml": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: anchor-override
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: worker
  template:
    metadata:
      labels:
        app: worker
    spec:
      containers:
        - name: app
          image: worker:1.0.0
          securityContext: &base_sec
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            privileged: false
            # Override anchor property below
            privileged: true
"""
        }
    },

    # ---------------------------------------------------------
    # RBAC & Cluster Permissions
    # ---------------------------------------------------------
    {
        "id": "K8S-RBAC-001",
        "iac_type": "kubernetes",
        "category": "kubernetes-security",
        "label": "TRUE_POSITIVE",
        "description": "ClusterRole granting wildcard verbs ['*'] on all resources ['*'] bound to default ServiceAccount",
        "why_scanner_may_fail": "Baseline Kubernetes RBAC misconfiguration; unrestricted cluster-admin equivalent.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_K8S_49",
                "cwe": "CWE-250",
                "cis": "CIS Kubernetes 1.6 - 5.1.3",
                "nist": "AC-6",
                "resource": "ClusterRole.wildcard-admin",
                "file": "rbac.yaml",
                "line": 1,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.1.3", "nist_800_53": "AC-6", "pci_dss": "7.1.2", "soc2": "CC6.3"},
        "source_refs": ["https://kubernetes.io/docs/reference/access-authn-authz/rbac/"],
        "undeliverable_static": False,
        "files": {
            "rbac.yaml": """apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wildcard-admin
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: default-sa-admin
subjects:
  - kind: ServiceAccount
    name: default
    namespace: default
roleRef:
  kind: ClusterRole
  name: wildcard-admin
  apiGroup: rbac.authorization.k8s.io
"""
        }
    },
    {
        "id": "K8S-RBAC-002",
        "iac_type": "kubernetes",
        "category": "kubernetes-security",
        "label": "EVASIVE_MISCONFIG",
        "description": "ClusterRole disguised as monitoring agent granting create on pods/exec and get/list on secrets (stealthy privilege escalation)",
        "why_scanner_may_fail": "Scanners searching exclusively for wildcard verbs ['*'] miss specific high-risk RBAC capabilities like pods/exec and secrets extraction.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_K8S_155",
                "cwe": "CWE-250",
                "cis": "CIS Kubernetes 1.6 - 5.1.3",
                "nist": "AC-6",
                "resource": "ClusterRole.monitoring-agent-role",
                "file": "rbac.yaml",
                "line": 1,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.1.3", "nist_800_53": "AC-6", "pci_dss": "7.1.2", "soc2": "CC6.3"},
        "source_refs": ["https://cyberark.com/resources/threat-research-blog/kubernetes-privilege-escalation"],
        "undeliverable_static": False,
        "files": {
            "rbac.yaml": """apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitoring-agent-role
rules:
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
"""
        }
    },
    {
        "id": "K8S-RBAC-003",
        "iac_type": "kubernetes",
        "category": "kubernetes-security",
        "label": "SAFE_LOOKALIKE",
        "description": "ClusterRole with strictly read-only non-sensitive metrics access",
        "why_scanner_may_fail": "Scanners with broad RBAC rules flagging any ClusterRole definition trigger False Positives on legitimate read-only monitoring roles.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_K8S_49", "CKV_K8S_155"],
        "compliance": {"cis": "5.1.3", "nist_800_53": "AC-6", "pci_dss": "7.1.2", "soc2": "CC6.3"},
        "source_refs": ["https://kubernetes.io/docs/reference/access-authn-authz/rbac/"],
        "undeliverable_static": False,
        "files": {
            "rbac.yaml": """apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: prometheus-metrics-reader
rules:
  - apiGroups: ["metrics.k8s.io"]
    resources: ["pods", "nodes"]
    verbs: ["get", "list", "watch"]
"""
        }
    }
]
