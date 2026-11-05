FROM cgr.dev/chainguard/static:latest@sha256:d8bb6aa16709a3dc5877f24032d84db8cc3bc5ab6ce6e5c8e235804aa3d56fcf

WORKDIR /app
COPY --chown=65532:65532 binary /app/binary

USER 65532:65532

ENTRYPOINT ["/app/binary"]
