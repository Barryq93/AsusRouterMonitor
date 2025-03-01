#!/usr/bin/python3

from RouterInfo import RouterInfo
import mysql.connector
from apscheduler.schedulers.blocking import BlockingScheduler
import os
import time
import logging
import sys
from typing import Optional, Tuple

# Setting up logging
os.environ['TZ']
time.tzset()
logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
stdout_handler.setFormatter(formatter)
logger.addHandler(stdout_handler)

# Set Asus router variables
asusIP = os.environ['routerIP']
asusUser = os.environ['routerUser']
asusPass = os.environ['routerPass']

# Set MySQL variables
sqlIP = os.environ['mysqlIP']
sqlPort = os.environ['mysqlPort']
sqlUser = os.environ['monitorUser']
sqlPasswd = os.environ['monitorPass']
sqlDb = os.environ['dbName']
sqlTable = os.environ['tableName']

# Get interval time from environment
interval = int(os.environ['intervalSeconds'])

# Retry settings for router connection
MAX_RETRIES = 3
RETRY_DELAY = 10  # seconds

def connect(values: Tuple) -> None:
    """
    Connect to the MySQL database and insert the provided values.

    Args:
        values (Tuple): The values to insert into the database.
    """
    max_retries = 3
    retry_delay = 5  # seconds

    for attempt in range(max_retries):
        try:
            # Connect to DB
            mydb = mysql.connector.connect(
                host=sqlIP,
                port=sqlPort,
                user=sqlUser,
                passwd=sqlPasswd,
                database=sqlDb
            )
            logger.info('Connected to DB')
            mycursor = mydb.cursor()
            sqlCommand = '''INSERT INTO {}(Uptime, memTotal, memFree, memUsed, cpu1Total, cpu2Total, cpu3Total, cpu4Total, cpu1Usage, cpu2Usage, cpu3Usage, cpu4Usage, wanStatus, deviceCount, internetTXSpeed, internetRXSpeed, 2GHXTXSpeed, 2GHXRXSpeed, 5GHXTXSpeed, 5GHXRXSpeed, wiredTXSpeed, wiredRXSpeed, bridgeTXSpeed, bridgeRXSpeed, sentData, recvData) 
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'''.format(sqlTable)
            mycursor.execute(sqlCommand, values)
            mydb.commit()
            logger.info('Data inserted successfully')
            return
        except Exception as e:
            logger.error(f"Attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
            else:
                logger.error("Max retries reached. Unable to connect to DB.")
                return
        finally:
            if 'mycursor' in locals():
                mycursor.close()
            if 'mydb' in locals():
                mydb.close()
                logger.info('Closed DB connection')

def getAndInsert(ri: RouterInfo) -> None:
    """
    Gather router info and insert it into the database.

    Args:
        ri (RouterInfo): The RouterInfo object used to interact with the router.
    """
    try:
        # Check if the router is online
        if not ri.is_wan_online():
            logger.error("Router is offline. Skipping data collection.")
            return

        # Gather router info
        Uptime = ri.get_uptime_secs()
        memTotal = int(ri.get_memory_usage().get('mem_total'))
        memFree = int(ri.get_memory_usage().get('mem_free'))
        memUsed = int(ri.get_memory_usage().get('mem_used'))
        cpu_usage = ri.get_cpu_usage()
        cpu1Total = int(cpu_usage.get('cpu1_total'))
        cpu2Total = int(cpu_usage.get('cpu2_total'))
        cpu3Total = int(cpu_usage.get('cpu3_total'))
        cpu4Total = int(cpu_usage.get('cpu4_total'))
        cpu1Usage = int(cpu_usage.get('cpu1_usage'))
        cpu2Usage = int(cpu_usage.get('cpu2_usage'))
        cpu3Usage = int(cpu_usage.get('cpu3_usage'))
        cpu4Usage = int(cpu_usage.get('cpu4_usage'))
        wanStatus = ri.get_status_wan().get('statusstr')
        deviceCount = (len(ri.get_dhcp_list().get('dhcpLeaseMacList'))) - 1
        internetTXSpeed = ri.get_traffic().get('speed').get('tx')
        internetRXSpeed = ri.get_traffic().get('speed').get('rx')
        _2GHXTXSpeed = ri.get_traffic_wireless2GHZ().get('speed').get('tx')
        _2GHXRXSpeed = ri.get_traffic_wireless2GHZ().get('speed').get('rx')
        _5GHXTXSpeed = ri.get_traffic_wireless5GHZ().get('speed').get('tx')
        _5GHXRXSpeed = ri.get_traffic_wireless5GHZ().get('speed').get('rx')
        wiredTXSpeed = ri.get_traffic_wired().get('speed').get('tx')
        wiredRXSpeed = ri.get_traffic_wired().get('speed').get('rx')
        bridgeTXSpeed = ri.get_traffic_bridge().get('speed').get('tx')
        bridgeRXSpeed = ri.get_traffic_bridge().get('speed').get('rx')
        sentData = (ri.get_traffic_total().get('sent'))
        recvData = (ri.get_traffic_total().get('recv'))

        logger.info('Router info gathered successfully')
    except Exception as e:
        logger.exception('Error gathering router info')
        return

    # Build insert statement values
    values = (Uptime, memTotal, memFree, memUsed, cpu1Total, cpu2Total, cpu3Total, cpu4Total, cpu1Usage, cpu2Usage, cpu3Usage, cpu4Usage, wanStatus, deviceCount, internetTXSpeed, internetRXSpeed, _2GHXTXSpeed, _2GHXRXSpeed, _5GHXTXSpeed, _5GHXRXSpeed, wiredTXSpeed, wiredRXSpeed, bridgeTXSpeed, bridgeRXSpeed, sentData, recvData)

    # Pass insert statement to DB method
    connect(values)

def connect_to_router() -> Optional[RouterInfo]:
    """
    Attempt to connect to the router with retries.

    Returns:
        Optional[RouterInfo]: The RouterInfo object if successful, None otherwise.
    """
    for attempt in range(MAX_RETRIES):
        try:
            logger.info(f"Attempting to connect to router (Attempt {attempt + 1})")
            ri = RouterInfo(asusIP, asusUser, asusPass)
            logger.info("Successfully connected to router")
            return ri
        except Exception as e:
            logger.error(f"Failed to connect to router: {e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
            else:
                logger.error("Max retries reached. Unable to connect to router.")
                return None

if __name__ == "__main__":
    # Attempt to connect to the router
    ri = connect_to_router()
    if not ri:
        logger.error("Exiting due to inability to connect to router.")
        sys.exit(1)

    logger.info('Starting monitor')
    scheduler = BlockingScheduler()

    # Add a job that gets router info at set intervals
    @scheduler.scheduled_job('interval', seconds=interval, max_instances=5)
    def scheduled_task():
        logger.info("Running scheduled task")
        getAndInsert(ri)

    try:
        scheduler.start()
    except Exception as e:
        logger.exception("Scheduler crashed")
    finally:
        logger.info("Scheduler stopped")