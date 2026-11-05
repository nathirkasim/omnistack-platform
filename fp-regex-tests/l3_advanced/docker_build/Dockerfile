FROM golang:1.21-alpine AS builder
WORKDIR /build
USER root
ARG GITHUB_TOKEN=ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R
COPY go.* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /app/server .

FROM alpine:3.18.4 AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV PASSWORD_FILE=/var/run/secrets/db_password
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
COPY --from=builder /app/server /usr/local/bin/server
USER 10001
EXPOSE 22
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/server"]
