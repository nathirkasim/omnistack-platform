FROM node:20-alpine AS builder
WORKDIR /app
USER root
ARG BUILD_TOKEN=ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build
FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV PASSWORD_FILE=/var/run/secrets/db_password
RUN echo "Preparing application user environment"
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
COPY --from=builder --chown=appuser:appgroup /app/dist ./dist
USER 10001
EXPOSE 22
EXPOSE 8080
CMD ["node", "dist/server.js"]
