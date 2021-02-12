# Do not provide a default base image in order to make this choice explicit
ARG BASE_IMAGE


# Stage an image without manifested project dependencies
# Produces an image which contains the wanted package managers but has not
# attempted to read any package manifests let alone install the dependencies
# listed within those manifest. An image in the prebuild stage will allow for
# the generation of template manifest files if the package manager exposes this
# feature.
FROM ${BASE_IMAGE} AS prebuild

# Install system dependencies
ARG SYSTEM_PACKAGES=""
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    python-dev \
    ${SYSTEM_PACKAGES} \
    && rm -rf /var/lib/apt/lists/*

ARG PACKAGE_INSTALLER_VERSION

# Install Poetry to $POETRY_HOME and allow all users to execute Poetry binaries
# https://python-poetry.org/docs/#introduction
ENV POETRY_HOME=/opt/poetry
ENV POETRY_BASE_URL=https://raw.githubusercontent.com/python-poetry/poetry
RUN curl -sSL \
  ${POETRY_BASE_URL}/${PACKAGE_INSTALLER_VERSION}/get-poetry.py \
  > /tmp/get-poetry.py && \
  python /tmp/get-poetry.py --version ${PACKAGE_INSTALLER_VERSION} && \
  chmod -R a+x /opt/poetry/bin

# TODO: Clean /var/cache /var/log var/*log /var/log/(fail,last)log

# Define environment vars for venv and initialize a venv
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:/opt/poetry/bin/:$PATH"
RUN python -m venv /opt/venv

ARG PROJECT=app
ENV PROJECT=${PROJECT}

WORKDIR /tmp/${PROJECT}


# Stage an image with manifested project dependencies
# Produces an image which has the packages listed within a package manifest
# installed such that it is equiped to build the application of interest.
FROM prebuild as build

# Copy Python dependency manifests into temporary working directory
COPY . /tmp/${PROJECT}/

# Install Python packages
ARG PACKAGE_INSTALLER="poetry install --no-dev"
RUN ${PACKAGE_INSTALLER}


# Stage an image for production use
# Produces an image which only copies binaries and other package resources from
# the build stages and sets up a sufficiently-restricted user such that the
# drop-in shell is safe for production use.
FROM ${BASE_IMAGE} AS production

# Provision a non-root user
ARG GID=20000
ARG UID=20000
ARG GECOS=",,,,"
RUN \
  addgroup \
    --gid ${GID} \
    appgroup \
  && \
  adduser \
    --no-create-home \
    --uid ${UID} \
    --gecos ${GECOS} \
    --gid ${GID} \
    --disabled-password \
    --disabled-login \
    appuser \
  && \
  > /var/log/faillog && > /var/log/lastlog
USER ${UID}:${GID}

# Copy venv from build image
COPY --chown=${UID}:${GID} --from=build /opt/venv /opt/venv

# Configure venv paths
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

ENV PROJECT=${PROJECT}

# For the production image, application-specific assets are stored into a
# subdirectory of "/opt" which is the FHS-designated destination for add-on
# application software packages.
WORKDIR /opt/${PROJECT}

# Explicitly listing all files to be copied into an image instead of listing
# not-wanted files in a .dockerignore. This make it more explicit what will be
# shipped with builds.
# Use the .dockerignore file to reduce the build context
# Prefer COPY over ADD
COPY --chown=${UID}:${GID} . /opt/${PROJECT}/

# NOTE: Do not define default PORTS in order to make configuration explicit
ARG PORTS
EXPOSE ${PORTS}
