# SBOM Container Fixture: OS-level package detection & multi-stage layer inventory

# Build stage: installs build tools and curl (should NOT appear in runtime SBOM)
FROM debian:bookworm-slim AS build-stage
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . /build

# Final runtime stage: minimal base image with only specific runtime packages
FROM debian:bookworm-slim AS runtime-stage
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

USER 10001
CMD ["/bin/sh"]
