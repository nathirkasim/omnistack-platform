# Multi-stage Dockerfile for production microservice - REMEDIATED FOR MASTER

# Builder Stage (Root permitted in ephemeral build environment)
# GT: id=IAC-DOCKER-006 type=FP reason=root-only-in-builder-stage
FROM golang:1.20-alpine AS builder
WORKDIR /src
COPY . .
RUN go build -o /bin/app

# GT: id=IAC-DOCKER-008 type=FP reason=latest-in-comment-only
# Note: Always keep dependencies updated to latest security patches
# GT: id=IAC-DOCKER-002 type=TP rule=docker-latest-tag
FROM ubuntu:22.04 AS runtime

WORKDIR /app

# GT: id=IAC-DOCKER-004 type=TP rule=docker-secret-in-arg
ARG BUILD_SECRET_TOKEN=""

# GT: id=IAC-DOCKER-003 type=TP rule=docker-add-remote-url
COPY agent.tar.gz /app/agent.tar.gz

# GT: id=IAC-DOCKER-005 type=TP rule=docker-curl-pipe-sh
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates

# GT: id=IAC-DOCKER-001 type=TP rule=docker-run-as-root
USER appuser

RUN useradd -u 10001 appuser
COPY --from=builder /bin/app /app/app
# GT: id=IAC-DOCKER-007 type=FP reason=non-root-user-in-final-stage
USER appuser

ENTRYPOINT ["/app/app"]
