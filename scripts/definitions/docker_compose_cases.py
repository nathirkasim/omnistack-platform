"""Dockerfile and Docker Compose test cases for IaC benchmark."""

DOCKER_COMPOSE_CASES = [
    # ---------------------------------------------------------
    # Dockerfile
    # ---------------------------------------------------------
    {
        "id": "DOCKER-001",
        "iac_type": "dockerfile",
        "category": "container-images",
        "label": "TRUE_POSITIVE",
        "description": "Dockerfile running as root, using ADD for remote tarball, curl pipe to sh, and unpinned latest base image",
        "why_scanner_may_fail": "Baseline Dockerfile security test case.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_DOCKER_1",
                "cwe": "CWE-250",
                "cis": "CIS Docker 1.6 - 4.1",
                "nist": "AC-6",
                "resource": "Dockerfile.",
                "file": "Dockerfile",
                "line": 6,
                "severity": "HIGH"
            },
            {
                "rule": "CKV_DOCKER_7",
                "cwe": "CWE-829",
                "cis": "CIS Docker 1.6 - 4.7",
                "nist": "SA-11",
                "resource": "Dockerfile.",
                "file": "Dockerfile",
                "line": 1,
                "severity": "LOW"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "4.1", "nist_800_53": "AC-6", "pci_dss": "2.2.4", "soc2": "CC6.3"},
        "source_refs": ["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"],
        "undeliverable_static": False,
        "files": {
            "Dockerfile": """FROM ubuntu:latest

WORKDIR /app

RUN apt-get update && apt-get install -y curl tar
ADD https://example.com/binaries/agent.tar.gz /app/agent.tar.gz
RUN curl -sSL https://install.example.com/setup.sh | sh

USER root

ENTRYPOINT ["/app/agent"]
"""
        }
    },
    {
        "id": "DOCKER-002",
        "iac_type": "dockerfile",
        "category": "container-images",
        "label": "EVASIVE_MISCONFIG",
        "description": "Multi-stage Dockerfile where build secret token is passed via ARG in builder stage and accidentally copied into final image via .env file",
        "why_scanner_may_fail": "Scanners evaluating stages independently may dismiss ARG in the builder stage as ephemeral, failing to notice that artifacts containing the secret are copied into the runtime stage.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_DOCKER_8",
                "cwe": "CWE-798",
                "cis": "CIS Docker 1.6 - 4.1",
                "nist": "IA-2",
                "resource": "Dockerfile.",
                "file": "Dockerfile",
                "line": 4,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "4.1", "nist_800_53": "IA-2", "pci_dss": "8.2.1", "soc2": "CC6.1"},
        "source_refs": ["https://docs.docker.com/build/building/secrets/"],
        "undeliverable_static": False,
        "files": {
            "Dockerfile": """FROM golang:1.21-alpine AS builder

WORKDIR /src
ARG BUILD_SECRET_TOKEN=ghp_MockSecretTokenValueForTesting9988776655
RUN echo "API_TOKEN=${BUILD_SECRET_TOKEN}" > /src/app.env
COPY . .
RUN go build -o /bin/app

FROM alpine:3.19 AS runtime
WORKDIR /app
COPY --from=builder /src/app.env /app/app.env
COPY --from=builder /bin/app /app/app
USER 10001:10001

ENTRYPOINT ["/app/app"]
"""
        }
    },
    {
        "id": "DOCKER-003",
        "iac_type": "dockerfile",
        "category": "container-images",
        "label": "SAFE_LOOKALIKE",
        "description": "Fully hardened Dockerfile with pinned SHA256 digest, non-root user UID 65532, and COPY --chown",
        "why_scanner_may_fail": "Hardened Dockerfile baseline; no findings should be triggered.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_DOCKER_1", "CKV_DOCKER_2", "CKV_DOCKER_7"],
        "compliance": {"cis": "4.1", "nist_800_53": "AC-6", "pci_dss": "2.2.4", "soc2": "CC6.3"},
        "source_refs": ["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"],
        "undeliverable_static": False,
        "files": {
            "Dockerfile": """FROM cgr.dev/chainguard/static:latest@sha256:d8bb6aa16709a3dc5877f24032d84db8cc3bc5ab6ce6e5c8e235804aa3d56fcf

WORKDIR /app
COPY --chown=65532:65532 binary /app/binary

USER 65532:65532

ENTRYPOINT ["/app/binary"]
"""
        }
    },

    # ---------------------------------------------------------
    # Docker Compose
    # ---------------------------------------------------------
    {
        "id": "COMPOSE-001",
        "iac_type": "docker-compose",
        "category": "container-images",
        "label": "TRUE_POSITIVE",
        "description": "docker-compose service configured with privileged: true and docker socket mount",
        "why_scanner_may_fail": "Baseline docker-compose security test case.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_DOCKER_10",
                "cwe": "CWE-250",
                "cis": "CIS Docker 1.6 - 5.1",
                "nist": "AC-6",
                "resource": "services.agent",
                "file": "docker-compose.yml",
                "line": 4,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.1", "nist_800_53": "AC-6", "pci_dss": "2.2.4", "soc2": "CC6.3"},
        "source_refs": ["https://docs.docker.com/compose/compose-file/05-services/#privileged"],
        "undeliverable_static": False,
        "files": {
            "docker-compose.yml": """version: '3.8'

services:
  agent:
    image: cluster-agent:1.0.0
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""
        }
    },
    {
        "id": "COMPOSE-002",
        "iac_type": "docker-compose",
        "category": "container-images",
        "label": "EVASIVE_MISCONFIG",
        "description": "docker-compose service escapes isolation via network_mode: host and pid: host without using 'privileged: true'",
        "why_scanner_may_fail": "Scanners that look exclusively for privileged: true fail to detect host network and process namespace sharing.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_DOCKER_11",
                "cwe": "CWE-284",
                "cis": "CIS Docker 1.6 - 5.9",
                "nist": "SC-7",
                "resource": "services.sniffer",
                "file": "docker-compose.yml",
                "line": 4,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.9", "nist_800_53": "SC-7", "pci_dss": "1.2.1", "soc2": "CC6.6"},
        "source_refs": ["https://docs.docker.com/compose/compose-file/05-services/#network_mode"],
        "undeliverable_static": False,
        "files": {
            "docker-compose.yml": """version: '3.8'

services:
  sniffer:
    image: net-diagnostic:2.0.0
    network_mode: "host"
    pid: "host"
    restart: always
"""
        }
    },
    {
        "id": "COMPOSE-003",
        "iac_type": "docker-compose",
        "category": "container-images",
        "label": "SAFE_LOOKALIKE",
        "description": "Database service exposes port 5432 bound strictly to localhost 127.0.0.1 on isolated internal network",
        "why_scanner_may_fail": "Scanners parsing port bindings with naive regex (e.g. matching '5432:5432') without parsing the host IP address 127.0.0.1 trigger False Positives.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_DOCKER_10", "exposed-db-port"],
        "compliance": {"cis": "5.1", "nist_800_53": "AC-4", "pci_dss": "1.2.1", "soc2": "CC6.6"},
        "source_refs": ["https://docs.docker.com/compose/compose-file/05-services/#ports"],
        "undeliverable_static": False,
        "files": {
            "docker-compose.yml": """version: '3.8'

services:
  database:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: appdb
    ports:
      - "127.0.0.1:5432:5432"
    read_only: true
    cap_drop:
      - ALL
"""
        }
    }
]
