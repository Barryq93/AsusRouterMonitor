#!/bin/sh
set -e

# Log function for better debugging
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

log "Starting database initialization..."

mysql -h localhost -u root -p${ROOT_PASS} <<-EOSQL
    -- Create database if it doesn't exist
    CREATE DATABASE IF NOT EXISTS ${dbName};
    USE ${dbName};

    log "Database ${dbName} created or already exists."

    -- Create users if they don't exist
    CREATE USER IF NOT EXISTS '${grafanaUser}'@'%' IDENTIFIED BY '${grafanaPass}';
    CREATE USER IF NOT EXISTS '${monitorUser}'@'%' IDENTIFIED BY '${monitorPass}';

    log "Users created or already exist."

    -- Grant restricted privileges
    GRANT SELECT, INSERT, UPDATE, DELETE ON ${dbName}.* TO '${monitorUser}'@'%';
    GRANT SELECT ON ${dbName}.* TO '${grafanaUser}'@'%';
    FLUSH PRIVILEGES;

    log "Privileges granted to users."

    -- Create tables if they don't exist
    CREATE TABLE IF NOT EXISTS ${tableName} (
        Uptime INT NOT NULL,
        memTotal INT NOT NULL,
        memFree INT NOT NULL,
        memUsed INT NOT NULL,
        cpu1Total INT NOT NULL,
        cpu2Total INT NOT NULL,
        cpu3Total INT NOT NULL,
        cpu4Total INT NOT NULL,
        cpu1Usage INT NOT NULL,
        cpu2Usage INT NOT NULL,
        cpu3Usage INT NOT NULL,
        cpu4Usage INT NOT NULL,
        wanStatus VARCHAR(255) NOT NULL,
        deviceCount INT NOT NULL,
        internetTXSpeed FLOAT NOT NULL,
        internetRXSpeed FLOAT NOT NULL,
        2GHXTXSpeed FLOAT NOT NULL,
        2GHXRXSpeed FLOAT NOT NULL,
        5GHXTXSpeed FLOAT NOT NULL,
        5GHXRXSpeed FLOAT NOT NULL,
        wiredTXSpeed FLOAT NOT NULL,
        wiredRXSpeed FLOAT NOT NULL,
        bridgeTXSpeed FLOAT NOT NULL,
        bridgeRXSpeed FLOAT NOT NULL,
        sentData FLOAT NOT NULL,
        recvData FLOAT NOT NULL,
        timeStamp TIMESTAMP NOT NULL PRIMARY KEY
    );

    log "Table ${tableName} created or already exists."

    -- Add index on the timeStamp column for faster queries
    CREATE INDEX IF NOT EXISTS idx_timestamp ON ${tableName} (timeStamp);

    log "Index on timeStamp column created or already exists."

    -- Create clearedEvents table if it doesn't exist
    CREATE TABLE IF NOT EXISTS clearedEvents (
        timeStamp TIMESTAMP NOT NULL PRIMARY KEY,
        clearCount INT
    );

    log "Table clearedEvents created or already exists."

    -- Enable event scheduler for this session
    SET GLOBAL event_scheduler = ON;

    log "Event scheduler enabled."

    -- Create cleanup event if it doesn't exist
    DELIMITER //
    CREATE EVENT IF NOT EXISTS cleaning
        ON SCHEDULE EVERY 21 DAY
        STARTS CURRENT_TIMESTAMP
        ON COMPLETION PRESERVE
        DO
        BEGIN
            DECLARE MaxTime TIMESTAMP;
            SET MaxTime = CURRENT_TIMESTAMP - INTERVAL 14 DAY;
            INSERT INTO ${dbName}.clearedEvents (timeStamp, clearCount)
                SELECT CURRENT_TIMESTAMP, COUNT(*)
                FROM ${dbName}.${tableName}
                WHERE timeStamp < MaxTime;
            DELETE FROM ${dbName}.${tableName}
            WHERE timeStamp < MaxTime;
        END //
    DELIMITER ;

    log "Cleanup event created or already exists."
EOSQL

if [ $? -eq 0 ]; then
    log "Database initialization completed successfully."
else
    log "Database initialization failed."
    exit 1
fi