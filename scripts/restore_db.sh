#!/bin/bash

# Load environment variables
source ./scripts/.env.scripts

# Check if the backup file exists
if [ -f "$DB_RESTORE_FILE" ]; then
    echo "Starting database restoration from: $DB_RESTORE_FILE"
    
    # Restore the MySQL database from the latest backup file
    mysql -h $MYSQL_HOST -u $MYSQL_USER -p$MYSQL_PASSWORD $MYSQL_DB < $DB_RESTORE_FILE

    if [ $? -eq 0 ]; then
        echo "Database restoration successful from: $DB_RESTORE_FILE"
    else
        echo "Database restoration failed!"
    fi
else
    echo "Error: Backup file $DB_RESTORE_FILE does not exist."
    exit 1
fi
