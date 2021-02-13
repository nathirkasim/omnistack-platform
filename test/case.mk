SHELL = /bin/sh

GIT ?= git
RM ?= rm -f

REPO_URL ?= example.com
REPO_BRANCH_NAME ?= master

TEST_ARGS = \
	RUNTIME_VERSION="${RUNTIME_VERSION}"

src:
	${GIT} clone -b ${REPO_BRANCH_NAME} --depth 1 ${REPO_URL} src

.PHONY: test
test: src
	${TEST_ARGS} ./test.sh

.PHONY: clean
clean:
	${RM} -r src
