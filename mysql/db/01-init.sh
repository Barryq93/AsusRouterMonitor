#!/bin/sh
set -e

mysql -h localhost -u root -p${ROOT_PASS} <<-EOSQL
  CREATE USER '${grafanaUser}'@'%' IDENTIFIED BY '${grafanaPass}';
  CREATE USER '${monitorUser}'@'%' IDENTIFIED BY '${monitorPass}';
  GRANT ALL PRIVILEGES ON *.* TO '${grafanaUser}'@'%';
  GRANT ALL PRIVILEGES ON *.* TO '${monitorUser}'@'%';

  SET CHARSET UTF8;

  use ${dbName};

  SET CHARACTER_SET_CLIENT = utf8;
  SET CHARACTER_SET_CONNECTION = utf8;

  DROP TABLE IF EXISTS ${tableName};
  CREATE TABLE ${tableName} (
          Uptime  INT,
          memTotal INT,
          memFree INT,
          memUsed INT,
          cpu1Total INT,
          cpu2Total INT,
          cpu3Total INT,
          cpu4Total INT,
          cpu1Usage INT,
          cpu2Usage INT,
          cpu3Usage INT,
          cpu4Usage INT,
          wanStatus VARCHAR(255),
          deviceCount INT,
          internetTXSpeed FLOAT,
          internetRXSpeed FLOAT,
          2GHXTXSpeed FLOAT,
          2GHXRXSpeed FLOAT,
          5GHXTXSpeed FLOAT,
          5GHXRXSpeed FLOAT,
          wiredTXSpeed FLOAT,
          wiredRXSpeed FLOAT,
          bridgeTXSpeed FLOAT,
          bridgeRXSpeed FLOAT,
          sentData FLOAT,
          recvData FLOAT,
          timeStamp TIMESTAMP NOT NULL PRIMARY KEY);

  flush privileges;

  DROP TABLE IF EXISTS clearedEvents;
  CREATE TABLE clearedEvents (
        timeStamp TIMESTAMP NOT NULL PRIMARY KEY,
        clearCount int);

  SET GLOBAL event_scheduler = ON;

  DELIMITER //
  CREATE EVENT cleaning 
    ON SCHEDULE 
      EVERY 21 DAY 
      STARTS CURRENT_TIMESTAMP
      ON COMPLETION PRESERVE
    DO
    BEGIN
      DECLARE MaxTime TIMESTAMP;
      SET MaxTime = CURRENT_TIMESTAMP - INTERVAL 14 DAY;
      INSERT INTO ${dbName}.clearedEvents (timeStamp, clearCount)
        SELECT CURRENT_TIMESTAMP, count(*)
          FROM ${dbName}.${tableName}
          WHERE timeStamp < MaxTime;
      DELETE FROM ${dbName}.${tableName}
      WHERE ${tableName}.timeStamp < MaxTime;
    END //
  DELIMITER ;
EOSQL