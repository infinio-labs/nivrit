#!/bin/sh
set -e

# Run pending SQLx migrations before starting the API. The migrations are baked
# into the image at /usr/local/share/nivrit/migrations.
if [ -n "$DATABASE_URL" ]; then
    echo "Running database migrations..."
    sqlx migrate run --source /usr/local/share/nivrit/migrations
fi

exec "$@"
