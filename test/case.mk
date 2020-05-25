SHELL = /bin/sh

GIT ?= git
RM ?= rm -f

PROJECT ?= stackuno-python

REPO_URL ?=
REPO_DIR ?= src
REPO_BRANCH_NAME ?= master

DOCKERFILE ?= ../../Dockerfile
PYTHON_PACKAGE_INSTALLER ?=
DOCKER_BASE_IMAGE ?= python:3.8.0-slim-buster

TEST_ARGS = \
	DOCKERFILE=${DOCKERFILE} \
	REPO_DIR=${REPO_DIR} \
	PYTHON_PACKAGE_INSTALLER="${PYTHON_PACKAGE_INSTALLER}" \
	DOCKER_BASE_IMAGE=${DOCKER_BASE_IMAGE} \
	PROJECT=${PROJECT}

all: src test.sh
	${TEST_ARGS} ./test.sh

${REPO_DIR}:
	${GIT} clone -b ${REPO_BRANCH_NAME} --depth 1 ${REPO_URL} ${REPO_DIR}

clean:
	${RM} -r ${REPO_DIR}

.PHONY:
	all clean
