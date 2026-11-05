from typing import List
from .base import FixtureBuilder, TargetLine

def generate_docker_cases() -> List[FixtureBuilder]:
    fixtures: List[FixtureBuilder] = []

    # -------------------------------------------------------------
    # L1 BASIC: DOCKERFILE & COMPOSE
    # -------------------------------------------------------------

    # 1. Dockerfile Explicit USER root as Final (FLAG)
    fb = FixtureBuilder("l1_basic/docker/docker_user_root_flag.Dockerfile")
    fb.add("FROM alpine:3.18.4")
    fb.add("WORKDIR /app")
    fb.add_target(
        "USER root",
        "FLAG", "DOCKER", "L1_BASIC", "DOCKER-001",
        "Container explicitly configured to execute as root user in final stage"
    )
    fb.add('CMD ["sh"]')
    fixtures.append(fb)

    # 2. Dockerfile Dedicated Non-Root User (NO_FLAG)
    fb = FixtureBuilder("l1_basic/docker/docker_nonroot_user_noflag.Dockerfile")
    fb.add("FROM alpine:3.18.4")
    fb.add("RUN addgroup -S appgroup && adduser -S appuser -G appgroup")
    fb.add("WORKDIR /app")
    fb.add_target(
        "USER 10001",
        "NO_FLAG", "DOCKER", "L1_BASIC", "DOCKER-002",
        "Explicit unprivileged non-root user UID specified"
    )
    fb.add('CMD ["./run.sh"]')
    fixtures.append(fb)

    # 3. Dockerfile Multi-Stage: Builder Root, Final Non-Root (NO_FLAG)
    fb = FixtureBuilder("l1_basic/docker/docker_multistage_builder_root_noflag.Dockerfile")
    fb.add("FROM golang:1.21-alpine AS builder")
    fb.add("WORKDIR /src")
    fb.add("USER root")
    fb.add("RUN go build -o /app/server .")
    fb.add("FROM alpine:3.18.4")
    fb.add("COPY --from=builder /app/server /usr/local/bin/server")
    fb.add_target(
        "USER 10001",
        "NO_FLAG", "DOCKER", "L1_BASIC", "DOCKER-003",
        "Final container runtime stage strictly runs as non-root user"
    )
    fb.add('ENTRYPOINT ["server"]')
    fixtures.append(fb)

    # 4. Dockerfile Insecure curl piped to sh (FLAG)
    fb = FixtureBuilder("l1_basic/docker/docker_curl_sh_flag.Dockerfile")
    fb.add("FROM alpine:3.18.4")
    fb.add_target(
        "RUN curl -fsSL https://get.example.com/install.sh | sh",
        "FLAG", "DOCKER", "L1_BASIC", "DOCKER-004",
        "Piping remote untrusted script directly to shell interpreter"
    )
    fixtures.append(fb)

    # 5. Dockerfile curl with SHA256 Verification (NO_FLAG)
    fb = FixtureBuilder("l1_basic/docker/docker_curl_checksum_noflag.Dockerfile")
    fb.add("FROM alpine:3.18.4")
    fb.add_target(
        'RUN curl -fsSLo pkg.tar.gz https://vendor.com/pkg.tar.gz && echo "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  pkg.tar.gz" | sha256sum -c',
        "NO_FLAG", "DOCKER", "L1_BASIC", "DOCKER-005",
        "Remote binary download validated against cryptographic checksum"
    )
    fixtures.append(fb)

    # 6. Dockerfile Cleartext Secret in ENV (FLAG)
    fb = FixtureBuilder("l1_basic/docker/docker_env_secret_flag.Dockerfile")
    fb.add("FROM alpine:3.18.4")
    fb.add_target(
        "ENV APP_PASSWORD=Hunter2Hunter2",
        "FLAG", "DOCKER", "L1_BASIC", "DOCKER-006",
        "Cleartext secret hardcoded in container image metadata layer"
    )
    fixtures.append(fb)

    # 7. Dockerfile Secret in ARG (FLAG)
    fb = FixtureBuilder("l1_basic/docker/docker_arg_token_flag.Dockerfile")
    fb.add("FROM alpine:3.18.4")
    fb.add_target(
        "ARG GITHUB_TOKEN=ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R",
        "FLAG", "DOCKER", "L1_BASIC", "DOCKER-007",
        "Personal access token baked into build argument default"
    )
    fixtures.append(fb)

    # 8. Dockerfile Secret Path in ENV (NO_FLAG)
    fb = FixtureBuilder("l1_basic/docker/docker_env_file_noflag.Dockerfile")
    fb.add("FROM alpine:3.18.4")
    fb.add_target(
        "ENV PASSWORD_FILE=/run/secrets/db_password",
        "NO_FLAG", "DOCKER", "L1_BASIC", "DOCKER-008",
        "Filesystem path reference for runtime secret lookup"
    )
    fixtures.append(fb)

    # 9. Dockerfile EXPOSE Port 22 (FLAG)
    fb = FixtureBuilder("l1_basic/docker/docker_expose_22_flag.Dockerfile")
    fb.add("FROM alpine:3.18.4")
    fb.add_target(
        "EXPOSE 22",
        "FLAG", "DOCKER", "L1_BASIC", "DOCKER-009",
        "SSH port 22 exposed in container image"
    )
    fixtures.append(fb)

    # 10. Dockerfile EXPOSE Port 8080 (NO_FLAG)
    fb = FixtureBuilder("l1_basic/docker/docker_expose_8080_noflag.Dockerfile")
    fb.add("FROM alpine:3.18.4")
    fb.add_target(
        "EXPOSE 8080",
        "NO_FLAG", "DOCKER", "L1_BASIC", "DOCKER-010",
        "Standard unprivileged application HTTP port"
    )
    fixtures.append(fb)

    # 11. Compose Privileged Container (FLAG)
    fb = FixtureBuilder("l1_basic/docker/compose_privileged_flag.yml")
    fb.add("services:")
    fb.add("  debug:")
    fb.add("    image: alpine:3.18.4")
    fb.add_target(
        "    privileged: true",
        "FLAG", "DOCKER", "L1_BASIC", "DOCKER-011",
        "Container granted full system capabilities via compose privileged flag"
    )
    fixtures.append(fb)

    # 12. Compose Docker Socket Mount (FLAG)
    fb = FixtureBuilder("l1_basic/docker/compose_sock_flag.yml")
    fb.add("services:")
    fb.add("  runner:")
    fb.add("    image: docker:24-cli")
    fb.add("    volumes:")
    fb.add_target(
        '    - "/var/run/docker.sock:/var/run/docker.sock"',
        "FLAG", "DOCKER", "L1_BASIC", "DOCKER-012",
        "Host Docker daemon control socket exposed into container"
    )
    fixtures.append(fb)

    # 13. Compose Isolated Local Port Binding (NO_FLAG)
    fb = FixtureBuilder("l1_basic/docker/compose_local_port_noflag.yml")
    fb.add("services:")
    fb.add("  database:")
    fb.add("    image: postgres:15.4-alpine")
    fb.add("    ports:")
    fb.add_target(
        '    - "127.0.0.1:5432:5432"',
        "NO_FLAG", "DOCKER", "L1_BASIC", "DOCKER-013",
        "Service port bound solely to local host loopback interface"
    )
    fixtures.append(fb)

    # 14. Compose Database Credential Literal (FLAG)
    fb = FixtureBuilder("l1_basic/docker/compose_env_secret_flag.yml")
    fb.add("services:")
    fb.add("  database:")
    fb.add("    image: postgres:15.4-alpine")
    fb.add("    environment:")
    fb.add_target(
        '      POSTGRES_PASSWORD: "ProdSuperSecretPass123"',
        "FLAG", "DOCKER", "L1_BASIC", "DOCKER-014",
        "Plaintext password literal embedded in compose environment dictionary"
    )
    fixtures.append(fb)

    # -------------------------------------------------------------
    # L2 INTERMEDIATE: DOCKER & COMPOSE
    # -------------------------------------------------------------

    # L2-1: Backend Dockerfile
    fb = FixtureBuilder("l2_intermediate/docker/backend.Dockerfile")
    fb.add("FROM node:20-alpine AS builder")
    fb.add("WORKDIR /app")
    fb.add("USER root")
    fb.add_target(
        "ARG BUILD_TOKEN=ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R",
        "FLAG", "DOCKER", "L2_INTERMEDIATE", "DOCKER-L2-001",
        "GitHub token embedded inside build argument definition"
    )
    fb.add("COPY package*.json ./")
    fb.add("RUN npm ci")
    fb.add("COPY . .")
    fb.add("RUN npm run build")
    fb.add("FROM node:20-alpine AS runtime")
    fb.add("WORKDIR /app")
    fb.add_target(
        "ENV NODE_ENV=production",
        "NO_FLAG", "DOCKER", "L2_INTERMEDIATE", "DOCKER-L2-002",
        "Standard environment designation flag"
    )
    fb.add_target(
        "ENV PASSWORD_FILE=/var/run/secrets/db_password",
        "NO_FLAG", "DOCKER", "L2_INTERMEDIATE", "DOCKER-L2-003",
        "Filesystem secret pointer rather than credential value"
    )
    fb.add_target(
        'RUN echo "Preparing application user environment"',
        "NO_FLAG", "DOCKER", "L2_INTERMEDIATE", "DOCKER-L2-004",
        "Command log string containing user substring"
    )
    fb.add("RUN addgroup -S appgroup && adduser -S appuser -G appgroup")
    fb.add("COPY --from=builder --chown=appuser:appgroup /app/dist ./dist")
    fb.add_target(
        "USER 10001",
        "NO_FLAG", "DOCKER", "L2_INTERMEDIATE", "DOCKER-L2-005",
        "Unprivileged user UID enforced for execution"
    )
    fb.add_target(
        "EXPOSE 22",
        "FLAG", "DOCKER", "L2_INTERMEDIATE", "DOCKER-L2-006",
        "Insecure SSH daemon port exposed in production runtime container"
    )
    fb.add_target(
        "EXPOSE 8080",
        "NO_FLAG", "DOCKER", "L2_INTERMEDIATE", "DOCKER-L2-007",
        "Standard unprivileged application HTTP port"
    )
    fb.add('CMD ["node", "dist/server.js"]')
    fixtures.append(fb)

    # L2-2: Stack Compose
    fb = FixtureBuilder("l2_intermediate/docker/stack-compose.yml")
    fb.add("services:")
    fb.add("  api:")
    fb.add("    image: node:20-alpine")
    fb.add_target(
        "    privileged: false",
        "NO_FLAG", "DOCKER", "L2_INTERMEDIATE", "DOCKER-L2-008",
        "Privileged mode explicitly disabled on api container"
    )
    fb.add("    ports:")
    fb.add_target(
        '    - "80:8080"',
        "DEBATABLE", "DOCKER", "L2_INTERMEDIATE", "DOCKER-L2-009",
        "Public web ingress port 80"
    )
    fb.add("  database:")
    fb.add("    image: postgres:15.4-alpine")
    fb.add("    ports:")
    fb.add_target(
        '    - "127.0.0.1:5432:5432"',
        "NO_FLAG", "DOCKER", "L2_INTERMEDIATE", "DOCKER-L2-010",
        "Database port bound exclusively to localhost"
    )
    fb.add("    environment:")
    fb.add_target(
        '      POSTGRES_PASSWORD: "SuperSecretPassword123"',
        "FLAG", "DOCKER", "L2_INTERMEDIATE", "DOCKER-L2-011",
        "Hardcoded plaintext database administrative password"
    )
    fb.add("  debug-agent:")
    fb.add("    image: alpine:3.18.4")
    fb.add_target(
        "    privileged: true",
        "FLAG", "DOCKER", "L2_INTERMEDIATE", "DOCKER-L2-012",
        "Diagnostic agent executing with full root capabilities"
    )
    fixtures.append(fb)

    return fixtures
