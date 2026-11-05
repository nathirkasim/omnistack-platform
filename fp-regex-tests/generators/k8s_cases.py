from typing import List
from .base import FixtureBuilder, TargetLine

def generate_k8s_cases() -> List[FixtureBuilder]:
    fixtures: List[FixtureBuilder] = []

    # -------------------------------------------------------------
    # L1 BASIC: KUBERNETES
    # -------------------------------------------------------------

    # 1. Privileged Container (FLAG)
    fb = FixtureBuilder("l1_basic/k8s/k8s_privileged_flag.yaml")
    fb.add("apiVersion: v1").add("kind: Pod").add("metadata:")
    fb.add("  name: debug-pod").add("spec:")
    fb.add("  containers:")
    fb.add("  - name: busybox")
    fb.add("    image: busybox:1.36.1")
    fb.add("    securityContext:")
    fb.add_target(
        "      privileged: true",
        "FLAG", "K8S", "L1_BASIC", "K8S-001",
        "Privileged container flag granting host root capabilities"
    )
    fixtures.append(fb)

    # 2. Unprivileged Container Explicit False (NO_FLAG)
    fb = FixtureBuilder("l1_basic/k8s/k8s_privileged_noflag.yaml")
    fb.add("apiVersion: v1").add("kind: Pod").add("metadata:")
    fb.add("  name: worker-pod").add("spec:")
    fb.add("  containers:")
    fb.add("  - name: worker")
    fb.add("    image: busybox:1.36.1")
    fb.add("    securityContext:")
    fb.add_target(
        "      privileged: false",
        "NO_FLAG", "K8S", "L1_BASIC", "K8S-002",
        "Privileged container explicitly set to false"
    )
    fixtures.append(fb)

    # 3. Host Network Enabled (FLAG)
    fb = FixtureBuilder("l1_basic/k8s/k8s_hostnetwork_flag.yaml")
    fb.add("apiVersion: v1").add("kind: Pod").add("metadata:")
    fb.add("  name: hostnet-pod").add("spec:")
    fb.add_target(
        "  hostNetwork: true",
        "FLAG", "K8S", "L1_BASIC", "K8S-003",
        "Host network namespace shared with pod"
    )
    fb.add("  containers:")
    fb.add("  - name: agent")
    fb.add("    image: alpine:3.18.4")
    fixtures.append(fb)

    # 4. Host Network Disabled (NO_FLAG)
    fb = FixtureBuilder("l1_basic/k8s/k8s_hostnetwork_noflag.yaml")
    fb.add("apiVersion: v1").add("kind: Pod").add("metadata:")
    fb.add("  name: isolated-pod").add("spec:")
    fb.add_target(
        "  hostNetwork: false",
        "NO_FLAG", "K8S", "L1_BASIC", "K8S-004",
        "Host network sharing explicitly deactivated"
    )
    fb.add("  containers:")
    fb.add("  - name: agent")
    fb.add("    image: alpine:3.18.4")
    fixtures.append(fb)

    # 5. Host PID Enabled (FLAG)
    fb = FixtureBuilder("l1_basic/k8s/k8s_hostpid_flag.yaml")
    fb.add("apiVersion: v1").add("kind: Pod").add("metadata:")
    fb.add("  name: monitor-pod").add("spec:")
    fb.add_target(
        "  hostPID: true",
        "FLAG", "K8S", "L1_BASIC", "K8S-005",
        "Host PID namespace shared with pod"
    )
    fb.add("  containers:")
    fb.add("  - name: monitor")
    fb.add("    image: alpine:3.18.4")
    fixtures.append(fb)

    # 6. HostPath Mount at Root (FLAG)
    fb = FixtureBuilder("l1_basic/k8s/k8s_hostpath_root_flag.yaml")
    fb.add("apiVersion: v1").add("kind: Pod").add("metadata:")
    fb.add("  name: storage-pod").add("spec:")
    fb.add("  volumes:")
    fb.add("  - name: host-root")
    fb.add("    hostPath:")
    fb.add_target(
        '      path: "/"',
        "FLAG", "K8S", "L1_BASIC", "K8S-006",
        "Host root filesystem mounted into container volume"
    )
    fb.add("  containers:")
    fb.add("  - name: app")
    fb.add("    image: alpine:3.18.4")
    fixtures.append(fb)

    # 7. EmptyDir Volume (NO_FLAG)
    fb = FixtureBuilder("l1_basic/k8s/k8s_emptydir_noflag.yaml")
    fb.add("apiVersion: v1").add("kind: Pod").add("metadata:")
    fb.add("  name: scratch-pod").add("spec:")
    fb.add("  volumes:")
    fb.add("  - name: temp-storage")
    fb.add_target(
        "    emptyDir: {}",
        "NO_FLAG", "K8S", "L1_BASIC", "K8S-007",
        "Ephemeral emptyDir volume isolated to pod lifecycle"
    )
    fb.add("  containers:")
    fb.add("  - name: app")
    fb.add("    image: alpine:3.18.4")
    fixtures.append(fb)

    # 8. Run As Root User (FLAG)
    fb = FixtureBuilder("l1_basic/k8s/k8s_runasroot_flag.yaml")
    fb.add("apiVersion: v1").add("kind: Pod").add("metadata:")
    fb.add("  name: root-pod").add("spec:")
    fb.add("  containers:")
    fb.add("  - name: service")
    fb.add("    image: alpine:3.18.4")
    fb.add("    securityContext:")
    fb.add_target(
        "      runAsUser: 0",
        "FLAG", "K8S", "L1_BASIC", "K8S-008",
        "Container explicitly configured to run as root UID 0"
    )
    fixtures.append(fb)

    # 9. Run As Non-Root User (NO_FLAG)
    fb = FixtureBuilder("l1_basic/k8s/k8s_runasnonroot_noflag.yaml")
    fb.add("apiVersion: v1").add("kind: Pod").add("metadata:")
    fb.add("  name: nonroot-pod").add("spec:")
    fb.add("  containers:")
    fb.add("  - name: service")
    fb.add("    image: alpine:3.18.4")
    fb.add("    securityContext:")
    fb.add_target(
        "      runAsNonRoot: true",
        "NO_FLAG", "K8S", "L1_BASIC", "K8S-009",
        "Pod security context requiring non-root execution"
    )
    fb.add_target(
        "      runAsUser: 10001",
        "NO_FLAG", "K8S", "L1_BASIC", "K8S-010",
        "Unprivileged UID assigned to container process"
    )
    fixtures.append(fb)

    # 10. Allow Privilege Escalation True (FLAG)
    fb = FixtureBuilder("l1_basic/k8s/k8s_escalation_flag.yaml")
    fb.add("apiVersion: v1").add("kind: Pod").add("metadata:")
    fb.add("  name: escalation-pod").add("spec:")
    fb.add("  containers:")
    fb.add("  - name: service")
    fb.add("    image: alpine:3.18.4")
    fb.add("    securityContext:")
    fb.add_target(
        "      allowPrivilegeEscalation: true",
        "FLAG", "K8S", "L1_BASIC", "K8S-011",
        "Privilege escalation enabled allowing setuid execution"
    )
    fixtures.append(fb)

    # 11. Allow Privilege Escalation False (NO_FLAG)
    fb = FixtureBuilder("l1_basic/k8s/k8s_escalation_noflag.yaml")
    fb.add("apiVersion: v1").add("kind: Pod").add("metadata:")
    fb.add("  name: safe-escalation-pod").add("spec:")
    fb.add("  containers:")
    fb.add("  - name: service")
    fb.add("    image: alpine:3.18.4")
    fb.add("    securityContext:")
    fb.add_target(
        "      allowPrivilegeEscalation: false",
        "NO_FLAG", "K8S", "L1_BASIC", "K8S-012",
        "Privilege escalation prevented via security context"
    )
    fixtures.append(fb)

    # 12. Capabilities Add SYS_ADMIN (FLAG)
    fb = FixtureBuilder("l1_basic/k8s/k8s_caps_flag.yaml")
    fb.add("apiVersion: v1").add("kind: Pod").add("metadata:")
    fb.add("  name: cap-pod").add("spec:")
    fb.add("  containers:")
    fb.add("  - name: service")
    fb.add("    image: alpine:3.18.4")
    fb.add("    securityContext:")
    fb.add("      capabilities:")
    fb.add("        add:")
    fb.add_target(
        '        - "SYS_ADMIN"',
        "FLAG", "K8S", "L1_BASIC", "K8S-013",
        "High-privilege CAP_SYS_ADMIN Linux capability added to container"
    )
    fixtures.append(fb)

    # 13. Capabilities Drop ALL (NO_FLAG)
    fb = FixtureBuilder("l1_basic/k8s/k8s_caps_drop_noflag.yaml")
    fb.add("apiVersion: v1").add("kind: Pod").add("metadata:")
    fb.add("  name: hard-cap-pod").add("spec:")
    fb.add("  containers:")
    fb.add("  - name: service")
    fb.add("    image: alpine:3.18.4")
    fb.add("    securityContext:")
    fb.add("      capabilities:")
    fb.add("        drop:")
    fb.add_target(
        '        - "ALL"',
        "NO_FLAG", "K8S", "L1_BASIC", "K8S-014",
        "All default Linux kernel capabilities explicitly dropped"
    )
    fixtures.append(fb)

    # 14. Image Tag Latest (FLAG)
    fb = FixtureBuilder("l1_basic/k8s/k8s_image_latest_flag.yaml")
    fb.add("apiVersion: v1").add("kind: Pod").add("metadata:")
    fb.add("  name: latest-pod").add("spec:")
    fb.add("  containers:")
    fb.add("  - name: web")
    fb.add_target(
        "    image: nginx:latest",
        "FLAG", "K8S", "L1_BASIC", "K8S-015",
        "Mutable :latest container image tag reference"
    )
    fixtures.append(fb)

    # 15. Image Without Tag (FLAG)
    fb = FixtureBuilder("l1_basic/k8s/k8s_image_notag_flag.yaml")
    fb.add("apiVersion: v1").add("kind: Pod").add("metadata:")
    fb.add("  name: notag-pod").add("spec:")
    fb.add("  containers:")
    fb.add("  - name: web")
    fb.add_target(
        "    image: nginx",
        "FLAG", "K8S", "L1_BASIC", "K8S-016",
        "Implicit latest image tag due to omitted version specification"
    )
    fixtures.append(fb)

    # 16. Pinned Image Tag (NO_FLAG)
    fb = FixtureBuilder("l1_basic/k8s/k8s_image_pinned_noflag.yaml")
    fb.add("apiVersion: v1").add("kind: Pod").add("metadata:")
    fb.add("  name: pinned-pod").add("spec:")
    fb.add("  containers:")
    fb.add("  - name: web")
    fb.add_target(
        "    image: nginx:1.25.3",
        "NO_FLAG", "K8S", "L1_BASIC", "K8S-017",
        "Immutably pinned semantic version container image tag"
    )
    fixtures.append(fb)

    # 17. Image Registry Name Containing Latest Lookalike (NO_FLAG)
    fb = FixtureBuilder("l1_basic/k8s/k8s_image_name_lookalike_noflag.yaml")
    fb.add("apiVersion: v1").add("kind: Pod").add("metadata:")
    fb.add("  name: reg-pod").add("spec:")
    fb.add("  containers:")
    fb.add("  - name: tool")
    fb.add_target(
        "    image: internal-registry.local/app-latest-tools:2.1.0",
        "NO_FLAG", "K8S", "L1_BASIC", "K8S-018",
        "Image name containing latest sub-token but explicitly pinned to version 2.1.0"
    )
    fixtures.append(fb)

    # 18. Literal Password in Env (FLAG)
    fb = FixtureBuilder("l1_basic/k8s/k8s_secret_env_flag.yaml")
    fb.add("apiVersion: v1").add("kind: Pod").add("metadata:")
    fb.add("  name: db-pod").add("spec:")
    fb.add("  containers:")
    fb.add("  - name: db")
    fb.add("    image: postgres:15.4-alpine")
    fb.add("    env:")
    fb.add("    - name: DB_PASSWORD")
    fb.add_target(
        '      value: "Hunter2SecretPassword"',
        "FLAG", "K8S", "L1_BASIC", "K8S-019",
        "Cleartext password defined inline within pod environment variable"
    )
    fixtures.append(fb)

    # 19. Secret Reference via SecretKeyRef (NO_FLAG)
    fb = FixtureBuilder("l1_basic/k8s/k8s_secret_ref_noflag.yaml")
    fb.add("apiVersion: v1").add("kind: Pod").add("metadata:")
    fb.add("  name: db-pod").add("spec:")
    fb.add("  containers:")
    fb.add("  - name: db")
    fb.add("    image: postgres:15.4-alpine")
    fb.add("    env:")
    fb.add("    - name: DB_PASSWORD")
    fb.add("      valueFrom:")
    fb.add_target(
        "        secretKeyRef:",
        "NO_FLAG", "K8S", "L1_BASIC", "K8S-020",
        "Dynamic secret value loaded from Kubernetes Secret resource"
    )
    fb.add("          name: app-db-credentials")
    fb.add("          key: password")
    fixtures.append(fb)

    # 20. RBAC Wildcard Privileges (FLAG)
    fb = FixtureBuilder("l1_basic/k8s/k8s_rbac_wildcard_flag.yaml")
    fb.add("apiVersion: rbac.authorization.k8s.io/v1")
    fb.add("kind: ClusterRole")
    fb.add("metadata:")
    fb.add("  name: super-admin")
    fb.add("rules:")
    fb.add("- apiGroups:")
    fb.add_target(
        '  - "*"',
        "FLAG", "K8S", "L1_BASIC", "K8S-021",
        "All API groups granted in RBAC rule"
    )
    fb.add("  resources:")
    fb.add_target(
        '  - "*"',
        "FLAG", "K8S", "L1_BASIC", "K8S-022",
        "All resources granted in RBAC rule"
    )
    fb.add("  verbs:")
    fb.add_target(
        '  - "*"',
        "FLAG", "K8S", "L1_BASIC", "K8S-023",
        "All actions granted in RBAC rule"
    )
    fixtures.append(fb)

    # -------------------------------------------------------------
    # L2 INTERMEDIATE: KUBERNETES
    # -------------------------------------------------------------

    # L2-1: Pod Security Matrix
    fb = FixtureBuilder("l2_intermediate/k8s/pod_security_matrix.yaml")
    fb.add("apiVersion: apps/v1")
    fb.add("kind: Deployment")
    fb.add("metadata:")
    fb.add("  name: workload-processor")
    fb.add("  labels:")
    fb.add_target(
        '    app.kubernetes.io/name: "privileged-broker"',
        "NO_FLAG", "K8S", "L2_INTERMEDIATE", "K8S-L2-001",
        "Metadata label containing privileged substring"
    )
    fb.add("spec:")
    fb.add("  replicas: 2")
    fb.add("  selector:")
    fb.add("    matchLabels:")
    fb.add("      app: processor")
    fb.add("  template:")
    fb.add("    metadata:")
    fb.add("      labels:")
    fb.add("        app: processor")
    fb.add("    spec:")
    fb.add_target(
        "      hostNetwork: false",
        "NO_FLAG", "K8S", "L2_INTERMEDIATE", "K8S-L2-002",
        "Host network sharing disabled on deployment pod spec"
    )
    fb.add_target(
        "      hostPID: false",
        "NO_FLAG", "K8S", "L2_INTERMEDIATE", "K8S-L2-003",
        "Host PID sharing disabled on deployment pod spec"
    )
    fb.add("      containers:")
    fb.add("      - name: processor")
    fb.add_target(
        "        image: redis:latest",
        "FLAG", "K8S", "L2_INTERMEDIATE", "K8S-L2-004",
        "Mutable latest tag on workload container"
    )
    fb.add("        securityContext:")
    fb.add_target(
        "          privileged: false",
        "NO_FLAG", "K8S", "L2_INTERMEDIATE", "K8S-L2-005",
        "Privileged container explicitly set to false"
    )
    fb.add_target(
        "          runAsNonRoot: true",
        "NO_FLAG", "K8S", "L2_INTERMEDIATE", "K8S-L2-006",
        "Enforce non-root execution in container"
    )
    fb.add_target(
        "          runAsUser: 10001",
        "NO_FLAG", "K8S", "L2_INTERMEDIATE", "K8S-L2-007",
        "Dedicated non-root UID 10001 assigned"
    )
    fb.add_target(
        "          readOnlyRootFilesystem: true",
        "NO_FLAG", "K8S", "L2_INTERMEDIATE", "K8S-L2-008",
        "Immutable root filesystem enforced"
    )
    fb.add_target(
        "          allowPrivilegeEscalation: true",
        "FLAG", "K8S", "L2_INTERMEDIATE", "K8S-L2-009",
        "Privilege escalation allowed on container process"
    )
    fixtures.append(fb)

    # L2-2: RBAC and Scoped Access
    fb = FixtureBuilder("l2_intermediate/k8s/rbac_and_access.yaml")
    fb.add("apiVersion: rbac.authorization.k8s.io/v1")
    fb.add("kind: Role")
    fb.add("metadata:")
    fb.add("  namespace: default")
    fb.add("  name: pod-reader")
    fb.add("rules:")
    fb.add("- apiGroups:")
    fb.add_target(
        '  - ""',
        "NO_FLAG", "K8S", "L2_INTERMEDIATE", "K8S-L2-010",
        "Core API group empty string"
    )
    fb.add("  resources:")
    fb.add_target(
        '  - "pods"',
        "NO_FLAG", "K8S", "L2_INTERMEDIATE", "K8S-L2-011",
        "Scoped pods resource"
    )
    fb.add("  verbs:")
    fb.add_target(
        '  - "get"',
        "NO_FLAG", "K8S", "L2_INTERMEDIATE", "K8S-L2-012",
        "Read-only get action"
    )
    fb.add_target(
        '  - "list"',
        "NO_FLAG", "K8S", "L2_INTERMEDIATE", "K8S-L2-013",
        "Read-only list action"
    )
    fb.add("---")
    fb.add("apiVersion: rbac.authorization.k8s.io/v1")
    fb.add("kind: ClusterRoleBinding")
    fb.add("metadata:")
    fb.add("  name: default-sa-admin")
    fb.add("subjects:")
    fb.add("- kind: ServiceAccount")
    fb.add_target(
        "  name: default",
        "FLAG", "K8S", "L2_INTERMEDIATE", "K8S-L2-014",
        "Default service account bound to administrative cluster role"
    )
    fb.add("  namespace: default")
    fb.add("roleRef:")
    fb.add("  kind: ClusterRole")
    fb.add_target(
        "  name: cluster-admin",
        "FLAG", "K8S", "L2_INTERMEDIATE", "K8S-L2-015",
        "Cluster-admin role reference"
    )
    fb.add("  apiGroup: rbac.authorization.k8s.io")
    fixtures.append(fb)

    return fixtures
