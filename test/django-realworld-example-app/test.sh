#! /bin/bash
set -eux

docker build \
  --file ${DOCKERFILE} \
  --build-arg=BASE_IMAGE=${DOCKER_BASE_IMAGE} \
  --build-arg=PORTS=8000 \
  --build-arg=PYTHON_PACKAGE_INSTALLER="${PYTHON_PACKAGE_INSTALLER}" \
  --tag=${DOCKER_IMAGE_NAME}:realworld-django \
  --target=production \
  ${REPO_DIR}
