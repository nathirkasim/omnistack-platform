FROM alpine:3.18.4
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app
USER 10001
CMD ["./run.sh"]
