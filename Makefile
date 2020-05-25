SHELL = /bin/sh

DOCKER ?= docker
GIT ?= git
MKDIR ?= mkdir
RM ?= rm -f

# The following args have been provided default values but can be overriden
# from the CLI by specifying those variables with the override values or by
# declaring those variables in the project.mk file which is conditionally
# included after variable declaration in this Makefile.

# Path to the shippable part of your application
# The shippable part of your application should contain manifest files
# (requirements.txt in case of pip, pyproject.toml and poetry.lock in case of
# Poetry) and the actual source that you will want to run inside of your
# container.
srcdir = .

# Absolute path to Dockerfile
Dockerfile = ./Dockerfile

# Docker stage to build in case of a multi-stage build
# Defaults to the build stage when undefined as it is fair to assume that
# manually invoking GNU Make rules is likelier to happen from a software
# developer's workstation as opposed to a production build environment and
# therefore the ability to spawn a working build/development environment with
# minimal manual effort renders this design choice sensible.
stage =
# Override an empty stage to equal build
ifeq ($(strip $(stage)),)
stage = build
endif

# Prefix for Docker images
PROJECT ?=
# Override an empty PROJECT to equal the source directory name
ifeq ($(strip $(PROJECT)),)
PROJECT = $(notdir $(realpath $(srcdir)))
endif

# Version of the application to build
PROJECT_VERSION ?=
ifeq ($(strip $(PROJECT_VERSION)),)
PROJECT_VERSION = $(shell $(GIT) describe --always --dirty)
endif

# Ports of the application to expose
APP_PORTS ?= 8000/tcp

SYSTEM_PACKAGES ?=

# Python version for the base Docker image
# The notation of the version should match the semver notation for which there
# are official Docker images available, otherwise the DOCKER_BASE_IMAGE
# variable will have to be modified to pull the appropriate Docker base image.
PYTHON_VERSION ?= 3.8.0

# Python dependency installation command
# The following example installation commands should work:
# -	for projects that use Pip: `pip install -r requirements.txt`
# - for projects that use Poetry: `poetry install --no-dev`
PYTHON_PACKAGE_INSTALLER ?= poetry install --no-dev

# Host address for port mapping
# Don't use 0.0.0.0 as this opens up your machine,
HOST_ADDRESS ?= 127.0.0.1

# Port on host to be mapped into the container
HOST_PORT ?= 8000

# Version to use for tagging images
# By default the PROJECT_VERSION and PYTHON_VERSION are factored into the
# VERSION variable such that PYTHON_VERSION is part of the pre-release clause.
# The reason the build metadata was not utilized in this case is because Docker
# does not allow for tags containing build metadata clauses since plus-signs
# (+) are technically not allowed in Docker tags.
# https://semver.org/
VERSION ?= $(PROJECT_VERSION)-python-$(PYTHON_VERSION)


# Docker image registry
DOCKER_REGISTRY ?= index.docker.io/

# Base image (as FROM) for all project images
# Try to use official images as much as possible.
# https://docs.docker.com/docker-hub/official_images/
DOCKER_BASE_IMAGE ?= python:$(PYTHON_VERSION)-slim-buster

# Caching flag for Docker build process
# Disable caching to force the docker builder to always rebuild all layers and
# thus minimize the chances of cached layers providing a false sense of build
# validity. If a build is broken because some resource is no longer available
# from the registries, you would need to know this as soon as possible i.e.:
# before hitting production environments.
DOCKER_CACHE_FLAG ?= --no-cache

# Home path of the container in order to adequately mount .homedir
DOCKER_CONTAINER_HOME_PATH = /home/appuser

# Ports of the container to expose
DOCKER_CONTAINER_PORTS = $(APP_PORTS)

# IP address or hostname of the host, defaults to the host loopback address
DOCKER_HOST_ADDRESS = $(HOST_ADDRESS)

# Port of the host, defaults to $(PORT)
DOCKER_HOST_PORT = $(HOST_PORT)

# Path of the project of interest, defaults to the current working directory
DOCKER_HOST_PROJECT_PATH = $(srcdir)

# Docker image name
DOCKER_IMAGE_NAME = $(PROJECT)

# Docker image tag
DOCKER_IMAGE_TAG = $(VERSION)

# Arguments for Docker image builds
# - BASE_IMAGE defines the Docker image to use in the FROM instruction
# - PORTS defines the ports to expose on the production image
# - PROJECT defines the name of the project and name of the subdirectory of
#   /opt where to install the project
# - PYTHON_DEPS_INSTALL_COMMAND defines the command to install Python
#   dependencies
# - SYSTEM_PACKAGES defines the system packages to install
DOCKER_BUILD_ARGS = \
	--build-arg=BASE_IMAGE="$(DOCKER_REGISTRY)$(DOCKER_BASE_IMAGE)" \
	--build-arg=PORTS="$(DOCKER_CONTAINER_PORTS)" \
	--build-arg=PROJECT="$(PROJECT)" \
	--build-arg=PYTHON_PACKAGE_INSTALLER="$(PYTHON_PACKAGE_INSTALLER)" \
	--build-arg=SYSTEM_PACKAGES="$(SYSTEM_PACKAGES)"

# Define the command line arguments to use in spawning Docker runs.
# - Defines environment variables (-e)
# - Defines port mappings (-p)
# - Sets the UID and GID to those of the host user (-u)
#   Ensures sensible ownership defaults on Linux hosts
# - Mounts volumes (-v)
# - Sets working directory (-w)
DOCKER_ARGS = \
	-e "PROJECT=$(PROJECT)" \
	-e "HOME=$(DOCKER_CONTAINER_HOME_PATH)" \
	-p $(DOCKER_HOST_ADDRESS):$(DOCKER_HOST_PORT):$(DOCKER_CONTAINER_PORT) \
	-u `id -u`:`id -g` \
	-v $(DOCKER_HOST_PROJECT_PATH)/.config:/etc/opt/$(PROJECT) \
	-v $(DOCKER_HOST_PROJECT_PATH)/.homedir:$(DOCKER_CONTAINER_HOME_PATH) \
	-v $(DOCKER_HOST_PROJECT_PATH)/.venv:/opt/venv \
	-v `realpath $(srcdir)`:/tmp/$(PROJECT) \
	-w /tmp/$(PROJECT)

# Include the project.mk file if it exists to override defined parameters
-include project.mk

# Spawn a Bash shell
bash: $(srcdir)
	mkdir -p .config .venv $(srcdir)
ifeq ($(strip $(stage)),production)
	docker run \
		$(DOCKER_ARGS) \
		--rm -it \
		--entrypoint=bash \
		$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)
else
	docker run \
		$(DOCKER_ARGS) \
		--rm -it \
		--entrypoint=bash \
		$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)-$(stage)
endif

# Clear local cache and venv directories
clean:
	rm -rf .homedir/.cache .venv

# Build the Docker image
image: $(srcdir)
ifeq ($(strip $(stage)),production) # production stage
	docker build \
		$(DOCKER_BUILD_ARGS) \
		$(DOCKER_CACHE_FLAG) \
		--file=$(Dockerfile) \
		--rm \
		--tag=$(DOCKER_IMAGE_NAME) \
		--tag=$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG) \
		--target=production \
		$(srcdir)
else # build stage
	docker build \
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
