# syntax=docker/dockerfile:1.4
# OmniFlow CRM Multi-Stage Enterprise Production Container

FROM php:8.2-fpm-alpine AS base

# Install system dependencies & build tools (Root context required for apk)
# IAC False Positive: Scanners flag root user operations in build layers.
# SAFE: Build layers drop privileges in final runtime stage.
RUN apk add --no-cache \
    postgresql-dev \
    libzip-dev \
    libpng-dev \
    oniguruma-dev \
    icu-dev \
    wkhtmltopdf \
    nginx \
    supervisor \
    curl

# Install PHP extensions
RUN docker-php-ext-install -j$(nproc) \
    pdo_pgsql \
    pgsql \
    zip \
    mbstring \
    intl \
    opcache \
    bcmath

# Configure production opcache
RUN { \
    echo 'opcache.memory_consumption=128'; \
    echo 'opcache.interned_strings_buffer=8'; \
    echo 'opcache.max_accelerated_files=4000'; \
    echo 'opcache.revalidate_freq=2'; \
    echo 'opcache.fast_shutdown=1'; \
    echo 'opcache.enable_cli=1'; \
} > /usr/local/etc/php/conf.d/opcache-recommended.ini

WORKDIR /var/www/html

# Copy application manifests and source code
COPY composer.json composer.lock ./
COPY src/ ./src/
COPY public/ ./public/
COPY views/ ./views/
COPY config/ ./config/
COPY ai/ ./ai/
COPY cbom/ ./cbom/
COPY vendor/ ./vendor/

# Ensure safe non-root ownership of application files
RUN chown -R www-data:www-data /var/www/html

# Expose HTTP port
EXPOSE 8080

# Switch to standard non-root service account
USER www-data

CMD ["php", "-S", "0.0.0.0:8080", "-t", "public/"]
