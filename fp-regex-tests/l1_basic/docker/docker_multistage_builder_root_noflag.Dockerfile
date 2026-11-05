FROM golang:1.21-alpine AS builder
WORKDIR /src
USER root
RUN go build -o /app/server .
FROM alpine:3.18.4
COPY --from=builder /app/server /usr/local/bin/server
USER 10001
ENTRYPOINT ["server"]
