FROM ubuntu:latest

WORKDIR /app

RUN apt-get update && apt-get install -y curl tar
ADD https://example.com/binaries/agent.tar.gz /app/agent.tar.gz
RUN curl -sSL https://install.example.com/setup.sh | sh

USER root

ENTRYPOINT ["/app/agent"]
