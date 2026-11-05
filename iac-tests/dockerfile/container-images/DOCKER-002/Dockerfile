FROM golang:1.21-alpine AS builder

WORKDIR /src
ARG BUILD_SECRET_TOKEN=ghp_MockSecretTokenValueForTesting9988776655
RUN echo "API_TOKEN=${BUILD_SECRET_TOKEN}" > /src/app.env
COPY . .
RUN go build -o /bin/app

FROM alpine:3.19 AS runtime
WORKDIR /app
COPY --from=builder /src/app.env /app/app.env
COPY --from=builder /bin/app /app/app
USER 10001:10001

ENTRYPOINT ["/app/app"]
