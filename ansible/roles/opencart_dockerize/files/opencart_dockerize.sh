#!/bin/bash
# opencart_dockerize.sh

set -euo pipefail

IMAGE_TAG="ccdc26/opencart:latest"
CONTAINER_NAME="opencart"
HOST_PORT=80
CONTAINER_PORT=80
STAGING="/tmp/ccdc26_oc_docker"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Must run as root"

info "Discovering OpenCart webroot..."
CONFIG_PHP=$(find /var/www -name 'config.php' 2>/dev/null \
    | xargs grep -l "DB_HOSTNAME" 2>/dev/null \
    | awk '{ print NF, $0 }' FS=/ | sort -n | head -1 | cut -d' ' -f2-)
[[ -n "$CONFIG_PHP" ]] || die "Could not find config.php under /var/www"
UPLOAD_DIR=$(dirname "$CONFIG_PHP")
info "  upload dir: $UPLOAD_DIR"

STORAGE_DIR=$(php -r "include '$CONFIG_PHP'; echo rtrim(DIR_STORAGE, '/');" 2>/dev/null || echo "/var/www/opencart_storage")
info "  storage: $STORAGE_DIR"

info "Reading DB credentials from config.php..."
DB_USER=$(php -r "include '$CONFIG_PHP'; echo DB_USERNAME;" 2>/dev/null)
DB_PASS=$(php -r "include '$CONFIG_PHP'; echo DB_PASSWORD;" 2>/dev/null)
DB_NAME=$(php -r "include '$CONFIG_PHP'; echo DB_DATABASE;" 2>/dev/null)
[[ -n "$DB_USER" && -n "$DB_NAME" ]] || die "Could not read DB credentials from config.php"
info "  db: $DB_USER/$DB_NAME"

MYSQL_ROOT_PASS=""
for candidate in "root" "" "toor" "mysql" "changeme"; do
    if mysqladmin -u root -p"$candidate" status &>/dev/null 2>&1; then
        MYSQL_ROOT_PASS="$candidate"
        break
    fi
done
if [[ -z "$MYSQL_ROOT_PASS" ]] && mysqladmin -u root status &>/dev/null 2>&1; then
    MYSQL_ROOT_PASS=""
fi
if [[ -z "$MYSQL_ROOT_PASS" ]] && ! mysqladmin -u root status &>/dev/null 2>&1; then
    read -rsp "MySQL root password: " MYSQL_ROOT_PASS
    echo
fi

if ! command -v docker &>/dev/null; then
    info "Installing Docker CE..."
    apt-get install -y ca-certificates curl
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    DISTRO=$(. /etc/os-release && echo "$VERSION_CODENAME")
    cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${DISTRO}
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
    info "Docker installed."
else
    info "Docker already installed: $(docker --version)"
fi

info "Preparing staging directory $STAGING..."
rm -rf "$STAGING"
mkdir -p "$STAGING/opencart_upload" "$STAGING/opencart_storage" "$STAGING/docker-entrypoint-initdb"
chmod 700 "$STAGING"

find "$UPLOAD_DIR" -name 'config.php' 2>/dev/null | xargs -r chattr -i 2>/dev/null || true

info "Dumping database $DB_NAME..."
if [[ -n "$MYSQL_ROOT_PASS" ]]; then
    mysqldump -u root -p"$MYSQL_ROOT_PASS" --single-transaction --routines --triggers --add-drop-table \
        "$DB_NAME" > "$STAGING/docker-entrypoint-initdb/opencart.sql"
else
    mysqldump -u root --single-transaction --routines --triggers --add-drop-table \
        "$DB_NAME" > "$STAGING/docker-entrypoint-initdb/opencart.sql"
fi
info "  dump size: $(du -sh "$STAGING/docker-entrypoint-initdb/opencart.sql" | cut -f1)"

info "Patching config files for container (DB_HOSTNAME → 127.0.0.1)..."
find "$STAGING/opencart_upload" -name 'config.php' | \
    xargs -r sed -i "s|define('DB_HOSTNAME'.*|define('DB_HOSTNAME', '127.0.0.1');|"

info "Setting permissions on staging files..."
chmod -R u=rwX,go=rX "$STAGING/opencart_upload"
chmod -R u=rwX,go=rX "$STAGING/opencart_storage"

cat > "$STAGING/Dockerfile" <<DOCKEREOF
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
ENV APACHE_RUN_USER=www-data
ENV APACHE_RUN_GROUP=www-data
ENV APACHE_LOG_DIR=/var/log/apache2

RUN apt-get update && apt-get install -y --no-install-recommends \\
    apache2 \\
    php8.1 \\
    php8.1-mysql \\
    php8.1-gd \\
    php8.1-curl \\
    php8.1-zip \\
    php8.1-xml \\
    php8.1-mbstring \\
    libapache2-mod-php8.1 \\
    mysql-server \\
    mysql-client \\
    supervisor \\
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN a2enmod rewrite php8.1
COPY apache-opencart.conf /etc/apache2/sites-available/opencart.conf
RUN a2dissite 000-default && a2ensite opencart

COPY --chown=www-data:www-data opencart_upload/ /var/www/opencart/
COPY --chown=www-data:www-data opencart_storage/ /var/www/opencart_storage/

COPY docker-entrypoint-initdb/opencart.sql /docker-entrypoint-initdb/opencart.sql
COPY mysql-init.sh /mysql-init.sh
RUN chmod +x /mysql-init.sh

COPY supervisord.conf /etc/supervisor/conf.d/opencart.conf

EXPOSE ${CONTAINER_PORT}

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
DOCKEREOF

cat > "$STAGING/apache-opencart.conf" <<APACHEEOF
<VirtualHost *:${CONTAINER_PORT}>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/opencart

    <Directory /var/www/opencart>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    <Directory /var/www/opencart/image>
        php_flag engine off
        Options -ExecCGI -Indexes
    </Directory>
    <Directory /var/www/opencart/catalog/view/theme>
        php_flag engine off
        Options -ExecCGI -Indexes
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/opencart_error.log
    CustomLog \${APACHE_LOG_DIR}/opencart_access.log combined
</VirtualHost>
APACHEEOF

cat > "$STAGING/supervisord.conf" <<SUPEOF
[supervisord]
nodaemon=true
logfile=/var/log/supervisor/supervisord.log
pidfile=/var/run/supervisord.pid
user=root

[program:mysql]
command=/usr/bin/mysqld_safe --skip-networking=0 --user=mysql
user=root
autostart=true
autorestart=true
stdout_logfile=/var/log/supervisor/mysql.log
stderr_logfile=/var/log/supervisor/mysql.log
priority=10

[program:apache2]
command=/usr/sbin/apache2ctl -D FOREGROUND
user=root
autostart=true
autorestart=true
stdout_logfile=/var/log/supervisor/apache2.log
stderr_logfile=/var/log/supervisor/apache2.log
priority=20
SUPEOF

cat > "$STAGING/mysql-init.sh" <<INITEOF
#!/bin/bash
set -ex
MYSQL_ROOT_PASSWORD='${MYSQL_ROOT_PASS:-changeme}'
DB_NAME='${DB_NAME}'
DB_USER='${DB_USER}'
DB_PASSWORD='${DB_PASS}'

# Fresh data dir — no root password, no auth plugin issues
rm -rf /var/lib/mysql
mkdir -p /var/lib/mysql
chown -R mysql:mysql /var/lib/mysql
mysqld --initialize-insecure --user=mysql

mysqld_safe --skip-networking --user=mysql &
MYSQL_PID=\$!
for i in \$(seq 1 30); do
    mysqladmin -u root ping --silent 2>/dev/null && break
    sleep 1
done

mysql -u root <<SQL
ALTER USER 'root'@'localhost' IDENTIFIED BY '\${MYSQL_ROOT_PASSWORD}';
CREATE DATABASE \${DB_NAME};
CREATE USER '\${DB_USER}'@'localhost' IDENTIFIED BY '\${DB_PASSWORD}';
GRANT ALL PRIVILEGES ON \${DB_NAME}.* TO '\${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL

mysql -u root -p"\${MYSQL_ROOT_PASSWORD}" "\${DB_NAME}" < /docker-entrypoint-initdb/opencart.sql

kill \$MYSQL_PID 2>/dev/null || true
wait \$MYSQL_PID 2>/dev/null || true
INITEOF
chmod 700 "$STAGING/mysql-init.sh"

cat > "$STAGING/entrypoint.sh" <<ENTEOF
#!/bin/bash
set -e
INIT_MARKER=/var/lib/mysql/.opencart_initialized

if [ ! -f "\$INIT_MARKER" ]; then
    echo "[entrypoint] First boot — initializing MySQL..."
    /mysql-init.sh
    touch "\$INIT_MARKER"
    echo "[entrypoint] MySQL initialized."
fi

echo "[entrypoint] Starting services via supervisord..."
exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
ENTEOF
chmod 700 "$STAGING/entrypoint.sh"

info "Building Docker image $IMAGE_TAG (this takes a few minutes)..."
docker build -t "$IMAGE_TAG" "$STAGING"
info "Build complete."

info "Stopping host Apache (container will take port $HOST_PORT)..."
systemctl stop apache2 && systemctl disable apache2 || true

docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

info "Starting container..."
docker run -d \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    -p "${HOST_PORT}:${CONTAINER_PORT}" \
    "$IMAGE_TAG"

info "Waiting for port $HOST_PORT to be ready..."
for i in $(seq 1 60); do
    if curl -sf "http://127.0.0.1:${HOST_PORT}" -o /dev/null 2>/dev/null; then
        info "Port $HOST_PORT is up after ${i}s."
        break
    fi
    sleep 2
done

find "$UPLOAD_DIR" -name 'config.php' 2>/dev/null | xargs -r chattr +i 2>/dev/null || true

info "Cleaning up staging..."
rm -rf "$STAGING"

