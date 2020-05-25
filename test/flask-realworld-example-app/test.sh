#! /usr/bin/env bash
set -eux

docker build \
  --build-arg=BASE_IMAGE=${DOCKER_BASE_IMAGE} \
  --build-arg=PORTS=8000 \
  --build-arg=PYTHON_PACKAGE_INSTALLER="${PYTHON_PACKAGE_INSTALLER}" \
  --build-arg=SYSTEM_PACKAGES="libpq-dev" \
  --file ${DOCKERFILE} \
  --no-cache \
  --tag=${PROJECT}:realworld-flask \
  --target=production \
  ${REPO_DIR}
