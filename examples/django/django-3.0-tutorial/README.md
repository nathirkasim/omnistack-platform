# Django Tutorial

This example implements parts of the [Django Tutorial][tut].

[tut]: https://docs.djangoproject.com/en/3.0/intro/tutorial01/

## Usage

In order to build the Django example, the Dockerfile needs to be modified to
account for the differences in compiling the Python packages in relation to the
default configuration. Furthermore, the necessary images will need to be created.

### Update Dockerfile for Package Manager
Comment out the `COPY` and `RUN` commands for the dev-image target in
[Dockerfile](/Dockerfile) in order to use pip to install Python dependencies.

```diff
:100644 100644 e1480a2 0000000 M	Dockerfile

diff --git a/Dockerfile b/Dockerfile
index e1480a2..5d98ca3 100644
--- a/Dockerfile
+++ b/Dockerfile
@@ -42,8 +42,10 @@ ENV PROJECT=${PROJECT}
 WORKDIR /tmp/${PROJECT}
 
 # Copy Python dependency manifests and install listed dependencies
-COPY pyproject.toml poetry.lock /tmp/${PROJECT}/
-RUN poetry install --no-dev
+COPY requirements.txt /tmp/${PROJECT}/
+RUN pip install -r requirements.txt
 
 
 FROM ${DOCKER_BASE_IMAGE} AS prod-image
```

### Build images

Build the images for the given example by running:

```bash
APP_PATH=examples/django/django-3.0-tutorial make dev-image
```

```bash
APP_PATH=examples/django/django-3.0-tutorial make prod-image
```

# TODO

- [ ] Set gunicorn or daphne ENTRYPOINT and CMD in prod-image
