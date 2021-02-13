SHELL = /bin/sh

GIT ?= git
RM ?= rm -f

REPO_URL ?= example.com
REPO_BRANCH_NAME ?= master

PYTHON_PACKAGE_INSTALLER ?=
DOCKER_BASE_IMAGE ?= python:3.8.0-slim-buster

TEST_ARGS = \
	PYTHON_PACKAGE_INSTALLER="${PYTHON_PACKAGE_INSTALLER}" \
	DOCKER_BASE_IMAGE=${DOCKER_BASE_IMAGE}

src:
	${GIT} clone -b ${REPO_BRANCH_NAME} --depth 1 ${REPO_URL} src

.PHONY: test
test: src
	${TEST_ARGS} ./test.sh

.PHONY: clean
clean:
	${RM} -r src
