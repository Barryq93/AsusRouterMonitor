#!/bin/sh
set -e

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

log "Starting database initialization..."

mariadb -h localhost -u root -p ${ROOT_PASS} <<-EOSQL
    CREATE DATABASE IF NOT EXISTS ${dbName};
    USE ${dbName};

    CREATE USER IF NOT EXISTS '${grafanaUser}'@'%' IDENTIFIED BY '${grafanaPass}';
    CREATE USER IF NOT EXISTS '${monitorUser}'@'%' IDENTIFIED BY '${monitorPass}';
    GRANT ALL PRIVILEGES ON *.* TO '${grafanaUser}'@'%';
    GRANT ALL PRIVILEGES ON *.* TO '${monitorUser}'@'%';
    FLUSH PRIVILEGES;

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
        speedDownload FLOAT NOT NULL DEFAULT 0.0,
        speedUpload FLOAT NOT NULL DEFAULT 0.0,
        ping FLOAT NOT NULL DEFAULT 0.0,
        timeStamp TIMESTAMP NOT NULL PRIMARY KEY
    );

    CREATE INDEX IF NOT EXISTS idx_timestamp ON ${tableName} (timeStamp);

    CREATE TABLE IF NOT EXISTS clearedEvents (
        timeStamp TIMESTAMP NOT NULL PRIMARY KEY,
        clearCount INT
    );

    SET GLOBAL event_scheduler = ON;

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
EOSQL

if [ $? -eq 0 ]; then
    log "Database initialization completed successfully."
else
    log "Database initialization failed."
    exit 1
fi