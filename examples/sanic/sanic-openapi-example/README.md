# Sanic OpenAPI example

This example demonstrates the sanic-openapi example code demonstrated at
[GitHub][sanic-github] and the [Sanic Documentation][sanic-readthedocs].

[sanic-readthedocs]: https://sanic-openapi.readthedocs.io/en/latest/
[sanic-github]: https://github.com/huge-success/sanic-openapi

## Usage
In order to build the Sanic OpenAPI example, execute the provided make rules
with the APP_PATH and TAG variables set to point to the [home directory][pwd]
of this README and a descriptive tag such as sanic-openapi-example
respectively.

### Build images
Build the images for the given example by running:

```bash
APP_PATH=examples/sanic/sanic-openapi-example make dev-image
```

```bash
APP_PATH=examples/sanic/sanic-openapi-example make prod-image
```

### Development
For development, navigate to the example application by starting a Bash shell
with the sanic-openapi-example directory as the working directory

```
APP_PATH=examples/sanic/sanic-openapi-example make bash
```

or by simply spawning a `bash shell` and cd-ing into the
[examples/sanic/sanic-openapi-example][pwd] directory.

[pwd]: /examples/sanic/sanic-openapi-example


Install the needed packages by running

```
poetry install
```

within the [home directory][pwd] of this example.


Start the Sanic OpenAPI example application by running

```
python sanic_openapi_example/main.py
```
