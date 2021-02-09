SHELL = /bin/sh

DOCKER ?= docker
GIT ?= git
MKDIR ?= mkdir -p
RM ?= rm -f

# The following args have been provided default values but can be overriden
# from the CLI by specifying those variables with the override values or by
# declaring those variables in the project.mk file which is conditionally
# included after variable declarations in this Makefile.

# Path to the shippable part of your application
# The shippable part of your application should contain manifest files
# (requirements.txt in case of pip, pyproject.toml and poetry.lock in case of
# Poetry) and the actual source that you will want to run inside of your
# container.
srcdir ?= .

# Path to the working directory on the host
# The working directory will contain the home directory that is mounted into
# the Docker container, package caches and other artifacts that may be be used
# to aid in development.
workdir ?= .

# Absolute path to Dockerfile
Dockerfile ?= ./Dockerfile

# Docker stage to build in case of a multi-stage build
# Defaults to the build stage when undefined as it is fair to assume that
# manually invoking GNU Make rules is likelier to happen from a software
# developer's workstation as opposed to a production build environment and
# therefore the ability to spawn a working build/development environment with
# minimal manual effort renders this design choice sensible.
stage ?= build

# Prefix for Docker images
PROJECT_NAME ?= $(notdir $(realpath $(srcdir)))

# Version of the application to build
PROJECT_VERSION ?= $(shell $(GIT) describe --always --dirty)

SYSTEM_PACKAGES ?=

# Python version for the base Docker image
# The notation of the version should match the semver notation for which there
# are official Docker images available, otherwise the DOCKER_BASE_IMAGE
# variable will have to be modified to pull the appropriate Docker base image.
RUNTIME_VERSION ?= 3.10.0a3

# Python dependency installation command
# The following example installation commands should work:
# -	for projects that use Pip: `pip install -r requirements.txt`
# - for projects that use Poetry: `poetry install --no-dev`
PACKAGE_INSTALLER ?= poetry install --no-dev
PACKAGE_INSTALLER_VERSION ?= 1.1.4

# Version to use for tagging images
# By default the PROJECT_VERSION and RUNTIME_VERSION are factored into the
# VERSION variable such that RUNTIME_VERSION is part of the pre-release clause.
# The reason the build metadata was not utilized in this case is because Docker
# does not allow for tags containing build metadata clauses since plus-signs
# (+) are technically not allowed in Docker tags.
# https://semver.org/
VERSION ?= $(PROJECT_VERSION)-python-$(RUNTIME_VERSION)


# Docker image registry
DOCKER_REGISTRY ?= index.docker.io/

# Base image (as FROM) for all project images
# Try to use official images as much as possible.
# https://docs.docker.com/docker-hub/official_images/
# https://hub.docker.com/_/python/
DOCKER_BASE_IMAGE ?= python:$(RUNTIME_VERSION)-slim-buster

# Caching flag for Docker build process
# Disable caching to force the docker builder to always rebuild all layers and
# thus minimize the chances of cached layers providing a false sense of build
# validity. If a build is broken because some resource is no longer available
# from the registries, you would need to know this as soon as possible i.e.:
# before hitting production environments.
DOCKER_CACHE_FLAG ?= --no-cache

# Home path of the container in order to adequately mount .homedir
DOCKER_CONTAINER_HOME_PATH = /home/appuser

# Host address for port mapping, defaults to the host loopback address
# Don't use 0.0.0.0 as this opens up your machine,
DOCKER_HOST_ADDRESS = 127.0.0.1

# Ports of the container to expose
DOCKER_CONTAINER_EXPOSE_PORTS = 8000

# Ports of the container to map
DOCKER_CONTAINER_PORTS = 8000/tcp
DOCKER_CONTAINER_PORT_MAPPING = $(addprefix \
	$(DOCKER_HOST_ADDRESS):, \
	$(DOCKER_CONTAINER_PORTS))


# Docker image name
DOCKER_IMAGE_NAME = $(PROJECT_NAME)

# Docker image tag
DOCKER_IMAGE_TAG = $(VERSION)

# Arguments for Docker image builds
# - BASE_IMAGE defines the Docker image to use in the FROM instruction
# - PORTS defines the ports to expose on the production image
# - PROJECT defines the name of the project and name of the subdirectory of
#   /opt where to install the project
# - SYSTEM_PACKAGES defines the system packages to install
DOCKER_BUILD_ARGS = \
	--build-arg=BASE_IMAGE="$(DOCKER_REGISTRY)$(DOCKER_BASE_IMAGE)" \
	--build-arg=PORTS="$(DOCKER_CONTAINER_EXPOSE_PORTS)" \
	--build-arg=PROJECT="$(PROJECT_NAME)" \
	--build-arg=PACKAGE_INSTALLER="$(PACKAGE_INSTALLER)" \
	--build-arg=PACKAGE_INSTALLER_VERSION="$(PACKAGE_INSTALLER_VERSION)" \
	--build-arg=SYSTEM_PACKAGES="$(SYSTEM_PACKAGES)"

# Define the command line arguments to use in spawning Docker runs.
# - Defines environment variables (-e)
# - Defines port mappings (-p)
# - Sets the UID and GID to those of the host user (-u)
#   Ensures sensible ownership defaults on Linux hosts
# - Mounts volumes (-v)
# - Sets working directory (-w)
DOCKER_ARGS = \
	-e "PROJECT=$(PROJECT_NAME)" \
	-e "HOME=$(DOCKER_CONTAINER_HOME_PATH)" \
	-p $(DOCKER_CONTAINER_PORT_MAPPING) \
	-u $(shell id -u):$(shell id -g) \
	-v $(realpath $(workdir)/.config):/etc/opt/$(PROJECT_NAME) \
	-v $(realpath $(workdir)/.homedir):$(DOCKER_CONTAINER_HOME_PATH) \
	-v $(realpath $(workdir)/.venv):/opt/venv \
	-v $(realpath $(srcdir)):/tmp/$(PROJECT_NAME) \
	-w /tmp/$(PROJECT_NAME)

# Include the project.mk file if it exists to override defined parameters
-include project.mk

# Spawn a Bash shell
bash: $(srcdir) $(workdir)
	$(MKDIR) \
		$(workdir)/.config \
		$(workdir)/.homedir \
		$(workdir)/.venv
ifeq ($(strip $(stage)),production)
	$(DOCKER) run \
		$(DOCKER_ARGS) \
		--rm -it \
		--entrypoint=bash \
		$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)
else
	$(DOCKER) run \
		$(DOCKER_ARGS) \
		--rm -it \
		--entrypoint=bash \
		$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)-$(stage)
endif

# Clear local cache and venv directories
clean: $(workdir)
	$(RM) -rf \
		$(workdir)/.homedir/.cache \
		$(workdir)/.venv

# Build the Docker image
image: $(srcdir)
ifeq ($(strip $(stage)),production) # production stage
	$(DOCKER) build \
		$(DOCKER_BUILD_ARGS) \
		$(DOCKER_CACHE_FLAG) \
		--file=$(Dockerfile) \
		--rm \
		--tag=$(DOCKER_IMAGE_NAME) \
		--tag=$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG) \
		--target=production \
		$(srcdir)
else # build stage
	$(DOCKER) build \
		$(DOCKER_BUILD_ARGS) \
		$(DOCKER_CACHE_FLAG) \
		--file=$(Dockerfile) \
		--rm \
		--tag=$(DOCKER_IMAGE_NAME):$(stage) \
		--tag=$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)-$(stage) \
		--target=$(stage) \
		$(srcdir)
endif

.PHONY: bash clean image
