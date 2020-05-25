#! /usr/bin/env bash
set -eux

docker build \
  --build-arg=BASE_IMAGE=${DOCKER_BASE_IMAGE} \
  --build-arg=PORTS=8000 \
  --build-arg=PYTHON_PACKAGE_INSTALLER="${PYTHON_PACKAGE_INSTALLER}" \
  --file ${DOCKERFILE} \
  --no-cache \
  --tag=stackuno-python:realworld-flask \
  --target=production \
  ${REPO_DIR}
