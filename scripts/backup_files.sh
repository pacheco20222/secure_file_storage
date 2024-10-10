#!/bin/bash

# Load environment variables
source ./scripts/.env.scripts

# Ensure necessary environment variables are loaded
if [ -z "$BACKUP_DIR" ] || [ -z "$UPLOADS_DIR" ]; then
    echo "Error: Missing environment variables. Please check .env.scripts."
    exit 1
fi

# Ensure the backup directory exists
mkdir -p $BACKUP_DIR

# Set the backup file name with date
UPLOADS_BACKUP_FILE="$BACKUP_DIR/uploads_backup_$(date +\%F_%T).tar.gz"

# Backup the uploads directory
tar -czf $UPLOADS_BACKUP_FILE $UPLOADS_DIR

if [ $? -eq 0 ]; then
    echo "Files backup successful: $UPLOADS_BACKUP_FILE"
else
    echo "Files backup failed!"
    exit 1
fi