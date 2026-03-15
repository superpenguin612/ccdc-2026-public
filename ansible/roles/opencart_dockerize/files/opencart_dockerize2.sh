#!/bin/bash
# Clean OpenCart Dockerizer (root DB dump version)

set -euo pipefail

IMAGE_TAG="ccdc26/opencart:latest"
HOST_PORT=80
STAGING="/tmp/opencart_docker"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root"

############################################
# Discover OpenCart
############################################

info "Discovering OpenCart..."

CONFIG_PHP=$(find /var/www -name config.php 2>/dev/null \
    | xargs grep -l "DB_HOSTNAME" 2>/dev/null \
    | awk '{print NF,$0}' FS=/ | sort -n | head -1 | cut -d' ' -f2-)

[[ -n "$CONFIG_PHP" ]] || die "OpenCart config.php not found"

UPLOAD_DIR=$(dirname "$CONFIG_PHP")

STORAGE_DIR=$(php -r "include '$CONFIG_PHP'; echo rtrim(DIR_STORAGE,'/');" 2>/dev/null)

DB_USER=$(php -r "include '$CONFIG_PHP'; echo DB_USERNAME;" 2>/dev/null)
DB_PASS=$(php -r "include '$CONFIG_PHP'; echo DB_PASSWORD;" 2>/dev/null)
DB_NAME=$(php -r "include '$CONFIG_PHP'; echo DB_DATABASE;" 2>/dev/null)

info "Upload dir: $UPLOAD_DIR"
info "Storage dir: $STORAGE_DIR"
info "Database: $DB_NAME"

############################################
# Install Docker if missing
############################################

if ! command -v docker &>/dev/null; then
    info "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
fi

############################################
# Prepare staging
############################################

info "Preparing staging..."

rm -rf "$STAGING"

mkdir -p \
"$STAGING/opencart_upload" \
"$STAGING/opencart_storage" \
"$STAGING/mysql"

############################################
# Dump database as root
############################################

info "Dumping database using MySQL root..."

MYSQL_AUTH="-u root"

if ! mysql $MYSQL_AUTH -e "SELECT 1" &>/dev/null; then
    read -rsp "MySQL root password: " MYSQL_ROOT_PASS
    echo
    MYSQL_AUTH="-u root -p$MYSQL_ROOT_PASS"
fi

mysqldump $MYSQL_AUTH \
    --single-transaction \
    --routines \
    --triggers \
    "$DB_NAME" > "$STAGING/mysql/opencart.sql"

info "Database dumped successfully"

############################################
# Patch DB hostname
############################################

info "Updating config.php DB host..."

find "$STAGING/opencart_upload" -name config.php \
-exec sed -i "s|define('DB_HOSTNAME'.*|define('DB_HOSTNAME','mysql');|" {} \;

############################################
# Dockerfile
############################################

cat > "$STAGING/Dockerfile" <<'EOF'
FROM php:8.1-apache

RUN apt-get update && apt-get install -y \
    libpng-dev \
    libzip-dev \
    libxml2-dev \
    libcurl4-openssl-dev \
    && docker-php-ext-install mysqli gd zip

RUN a2enmod rewrite

COPY opencart_upload/ /var/www/html/
COPY opencart_storage/ /var/www/opencart_storage/

RUN chown -R www-data:www-data /var/www
EOF

############################################
# docker-compose.yml
############################################

cat > "$STAGING/docker-compose.yml" <<EOF
version: "3.9"

services:

  opencart:
    build: .
    container_name: opencart_app
    restart: unless-stopped
    ports:
      - "${HOST_PORT}:80"
    depends_on:
      - mysql
    volumes:
      - storage:/var/www/opencart_storage

  mysql:
    image: mysql:8
    container_name: opencart_db
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: changeme
      MYSQL_DATABASE: ${DB_NAME}
      MYSQL_USER: ${DB_USER}
      MYSQL_PASSWORD: ${DB_PASS}
    volumes:
      - mysql_data:/var/lib/mysql
      - ./mysql/opencart.sql:/docker-entrypoint-initdb.d/opencart.sql

volumes:
  mysql_data:
  storage:
EOF

############################################
# Build image
############################################

info "Building container..."

cd "$STAGING"

docker build -t "$IMAGE_TAG" .

############################################
# Start stack
############################################

info "Starting containers..."

docker compose up -d

############################################
# Wait for OpenCart
############################################

info "Waiting for OpenCart..."

for i in {1..60}; do
    if curl -sf "http://127.0.0.1:${HOST_PORT}" >/dev/null; then
        info "OpenCart is live!"
        break
    fi
    sleep 2
done

############################################
# Cleanup
############################################

info "Cleaning staging..."

rm -rf "$STAGING"

info "Done."