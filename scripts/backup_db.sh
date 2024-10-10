#!/bin/bash

# Load environment variables
source ./scripts/.env.scripts

# Ensure the backup directory exists
if [ -z "$BACKUP_DIR" ] || [ -z "$MYSQL_HOST" ] || [ -z "$MYSQL_USER" ] || [ -z "$MYSQL_PASSWORD" ] || [ -z "$MYSQL_DB" ]; then
    echo "Error: Missing environment variables. Please check .env.scripts."
    exit 1
fi

mkdir -p $BACKUP_DIR

# Set the backup file name with date
DB_BACKUP_FILE="$BACKUP_DIR/secure_storage_$(date +\%F_%T).sql"

# Backup the MySQL database
mysqldump -h $MYSQL_HOST -u $MYSQL_USER -p$MYSQL_PASSWORD $MYSQL_DB > $DB_BACKUP_FILE

if [ $? -eq 0 ]; then
    echo "Database backup successful: $DB_BACKUP_FILE"
else
    echo "Database backup failed!"
    exit 1
fi
