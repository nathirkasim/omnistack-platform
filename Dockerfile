# Do not provide a default base image in order to make this choice explicit
ARG BASE_IMAGE


FROM ${BASE_IMAGE} AS build

# Install system dependencies
ARG SYSTEM_PACKAGES=""
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    python-dev \
    ${SYSTEM_PACKAGES} \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry to $POETRY_HOME and allow all users to execute Poetry binaries
# https://python-poetry.org/docs/#introduction
ENV POETRY_HOME=/opt/poetry
RUN curl -sSL \
  https://raw.githubusercontent.com/python-poetry/poetry/1.0.3/get-poetry.py \
  > /tmp/get-poetry.py && \
  python /tmp/get-poetry.py && \
  chmod -R a+x ${POETRY_HOME}/bin

# TODO: Clean /var/cache /var/log var/*log /var/log/(fail,last)log

# Define environment vars for venv and initialize a venv
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:/opt/poetry/bin/:$PATH"
RUN python -m venv /opt/venv

ARG PROJECT=app
ENV PROJECT=${PROJECT}

WORKDIR /tmp/${PROJECT}

# Copy Python dependency manifests into temporary working directory
COPY . /tmp/${PROJECT}/

# Install Python packages
ARG PYTHON_PACKAGE_INSTALLER="poetry install --no-dev"
RUN ${PYTHON_PACKAGE_INSTALLER}


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

# Explicitly listing all files to be copied as opposed to listing non-wanted
# files in a .dockerignore file makes it easier to examine (e.g.: during
# code-reviews) which files will be shipped with builds. Relying on
# .dockerignore as the primary means to manage the assets for build images is
# arguably less robust as it doesn't explicitly require approval or listing of
# assets prior to them finding their way into a shipped image.
# As a rule of thumb, use the .dockerignore file to reduce the build context
# and avoid using it as the primary means to keep files from ending up in
# images mean for deployment.
# Prefer COPY over ADD
COPY --chown=${UID}:${GID} . /opt/${PROJECT}/

# NOTE: Do not define default to PORTS in order to make this choice explicit
ARG PORTS
EXPOSE ${PORTS}
