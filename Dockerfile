FROM php:8.2-cli

# Install system dependencies
RUN apt-get update && apt-get install -y \
    unzip \
    curl \
    sqlite3 \
    libsqlite3-dev \
    cron \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Install PHP extensions
RUN docker-php-ext-install pdo pdo_sqlite pcntl

# Install Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

WORKDIR /app

# Copy application files
COPY . .

# Set permissions
RUN chmod -R 775 storage bootstrap/cache

# Install PHP dependencies
RUN composer config policy.advisories.block false || true
RUN composer install --no-interaction --optimize-autoloader --no-dev

# Setup environment
RUN cp .env.example .env && \
    php artisan key:generate

# Setup supervisor for web server and scheduler
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expose port
EXPOSE 8080

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
