RUNTIME_VERSION = 3.8.0

srcdir = ./src
Dockerfile = ../../Dockerfile

PACKAGE_INSTALLER ?= pip install -r requirements.txt

-include ../../Makefile

SYSTEM_PACKAGES = "libpq-dev"


REPO_URL ?= https://github.com/gothinkster/flask-realworld-example-app.git

-include ../case.mk
