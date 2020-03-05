# The following args have been provided default values but can be overriden
# from the CLI by specifying those variables with the override values or by
# declaring those variables in the project.mk file which is conditionally
# included after variable declaration in this Makefile.

# Path to the shippable part of your application
# The shippable part of your application should contain manifest files
# (requirements.txt in case of pip, pyproject.toml and poetry.lock in case of
# Poetry) and the actual source that you will want to run inside of your
# container.
APP_PATH ?= .

# Version of the application to be shipped
APP_VERSION ?= 0.1.0

# Name of the applicationn and resulting Docker image
APP_NAME ?= backend-python

# Python version for the base Docker image
# The notation of the version should match the semver notation for which there
# are official Docker images available, otherwise the BASE_IMAGE variable will
# have to be modified to pull the appropriate Docker base image.
PYTHON_VERSION ?= 3.8.0

# Base image (as FROM) for all project images
# Try to use official images as much as possible.
# https://docs.docker.com/docker-hub/official_images/
PYTHON_IMAGE ?= index.docker.io/python:${PYTHON_VERSION}-slim-buster

# Python dependency installation command
# The following example installation commands should work:
# -	for projects that use Pip: `pip install -r requirements.txt`
# - for projects that use Poetry: `poetry install --no-dev`
PYTHON_DEPS_INSTALL_COMMAND ?= poetry install --no-dev

# Host address for port mapping
# Don't use 0.0.0.0 as this opens up your machine,
HOST_ADDRESS ?= 127.0.0.1

# Port on host to be mapped into the container
HOST_PORT ?= 8121

# Version to use for tagging images
# By default the APP_VERSION and PYTHON_VERSION are factored into the VERSION
# variable such that PYTHON_VERSION is part of the pre-release clause. The
# reason the build metadata was not utilized in this case is because Docker
# does not allow for tags containing build metadata clauses since plus-signs
# (+) are technically not allowed in Docker tags.
# https://semver.org/
VERSION ?= ${APP_VERSION}-python-${PYTHON_VERSION}


# Docker container parameters

# Docker image to use as a source for development and production images
DOCKER_CONTAINER_BASE_IMAGE = ${PYTHON_IMAGE}

# Home path of the container in order to adequately mount .homedir
DOCKER_CONTAINER_HOME_PATH = /home/appuser

# Port of the container to which to map the host
DOCKER_CONTAINER_PORT = 8000


# Docker host parameters

# IP address or hostname of the host, defaults to the host loopback address
DOCKER_HOST_ADDRESS = ${HOST_ADDRESS}

# Port of the host, defaults to ${HOST_PORT}
DOCKER_HOST_PORT = ${HOST_PORT}

# Path of the project of interest, defaults to the current working directory
DOCKER_HOST_PROJECT_PATH = ${PWD}


# Docker image name
DOCKER_IMAGE_NAME = ${APP_NAME}

# Docker image tag
DOCKER_IMAGE_TAG = ${VERSION}

# Absolute path to Dockerfile
DOCKER_FILE = ${PWD}/Dockerfile

# Caching flag for Docker build process
# Disable caching to force the docker builder to always rebuild all layers and
# thus minimize the chances of cached layers providing a false sense of build
# validity. If a build is broken because some resource is no longer available
# from the registries, you would need to know this as soon as possible i.e.:
# before hitting production environments.
DOCKER_CACHE_FLAG ?= "--no-cache"

# Define the command line arguments to use in spawning Docker runs.
# - Defines environment variables (-e)
# - Defines port mappings (-p)
# - Sets the UID and GID to those of the host user (-u)
#   Ensures sensible ownership defaults on Linux hosts
# - Mounts volumes (-v)
# - Sets working directory (-w)
DOCKER_ARGS = \
	-e "PROJECT=${PROJECT}" \
	-e "HOME=${DOCKER_CONTAINER_HOME_PATH}" \
	-p ${DOCKER_HOST_ADDRESS}:${DOCKER_HOST_PORT}:${DOCKER_CONTAINER_PORT} \
	-u `id -u`:`id -g` \
	-v ${DOCKER_HOST_PROJECT_PATH}/.config:/etc/opt/${PROJECT} \
	-v ${DOCKER_HOST_PROJECT_PATH}/.homedir:${DOCKER_CONTAINER_HOME_PATH} \
	-v ${DOCKER_HOST_PROJECT_PATH}/.venv:/opt/venv \
	-v `realpath ${APP_PATH}`:/tmp/${PROJECT} \
	-w /tmp/${PROJECT}


# Include the project.mk file if it exists to override defined parameters
-include project.mk

# Remove temporary files
clean:
	@rm -rf .homedir/.cache .venv

# Spawn a Bash shell for the development image
bash:
	@mkdir -p .config .venv ${APP_PATH}
	@docker run \
		${DOCKER_ARGS} \
		--rm -it \
		${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}-dev bash

# Build production image
prod-image:
	@docker build \
		${DOCKER_CACHE_FLAG} \
		--build-arg=DOCKER_BASE_IMAGE="${DOCKER_CONTAINER_BASE_IMAGE}" \
		--build-arg=PROJECT="${PROJECT}" \
		--build-arg=PYTHON_DEPS_INSTALL_COMMAND="${PYTHON_DEPS_INSTALL_COMMAND}" \
		--file=${DOCKER_FILE} \
		--rm \
		--tag="${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}" \
		--target=prod-image \
		${APP_PATH}

# Build development image
dev-image:
	@docker build \
		${DOCKER_CACHE_FLAG} \
		--build-arg="DOCKER_BASE_IMAGE=${DOCKER_CONTAINER_BASE_IMAGE}" \
		--build-arg="PROJECT=${PROJECT}" \
		--build-arg="PYTHON_DEPS_INSTALL_COMMAND=${PYTHON_DEPS_INSTALL_COMMAND}" \
		--file=${DOCKER_FILE} \
		--rm \
		--tag="${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}-dev" \
		--target=dev-image \
		${APP_PATH}

.PHONY: prod-image dev-image bash clean
