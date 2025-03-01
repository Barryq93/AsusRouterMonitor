#!/usr/bin/python3

from RouterInfo import RouterInfo, RouterRequestError
import mysql.connector
from apscheduler.schedulers.blocking import BlockingScheduler
import os
import time
import logging
import sys

# Logging setup
os.environ['TZ']
time.tzset()
logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
stdout_handler.setFormatter(formatter)
logger.addHandler(stdout_handler)

# Router and MySQL variables from environment
asusIP = os.environ['routerIP']
asusUser = os.environ['routerUser']
asusPass = os.environ['routerPass']
sqlIP = os.environ['mysqlIP']
sqlPort = os.environ['mysqlPort']
sqlUser = os.environ['monitorUser']
sqlPasswd = os.environ['monitorPass']
sqlDb = os.environ['dbName']
sqlTable = os.environ['tableName']
interval = int(os.environ['intervalSeconds'])
speedtest_interval = int(os.environ.get('speedtestIntervalSeconds', 3600))  # Default to 1 hour

# Retry settings
MAX_RETRIES = 3
RETRY_DELAY = 10  # seconds

def connect(values, include_speedtest=False):
    """Connect to MySQL and insert router data."""
    columns = ["Uptime", "memTotal", "memFree", "memUsed", "cpu1Total", "cpu2Total", "cpu3Total", "cpu4Total", 
               "cpu1Usage", "cpu2Usage", "cpu3Usage", "cpu4Usage", "wanStatus", "deviceCount", 
               "internetTXSpeed", "internetRXSpeed", "`2GHXTXSpeed`", "`2GHXRXSpeed`", "`5GHXTXSpeed`", "`5GHXRXSpeed`", 
               "wiredTXSpeed", "wiredRXSpeed", "bridgeTXSpeed", "bridgeRXSpeed", "sentData", "recvData"]
    if include_speedtest:
        columns.extend(["speedDownload", "speedUpload", "ping"])
    sqlCommand = f"INSERT INTO {sqlTable} ({', '.join(columns)}) VALUES ({', '.join(['%s'] * len(columns))})"

    for attempt in range(MAX_RETRIES):
        try:
            mydb = mysql.connector.connect(host=sqlIP, port=sqlPort, user=sqlUser, passwd=sqlPasswd, database=sqlDb)
            logger.info('Connected to DB')
            mycursor = mydb.cursor()
            mycursor.execute(sqlCommand, values)
            mydb.commit()
            logger.info('Data inserted successfully')
            return
        except Exception as e:
            logger.error(f"Attempt {attempt + 1} failed: {e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
        finally:
            if 'mycursor' in locals():
                mycursor.close()
            if 'mydb' in locals():
                mydb.close()
                logger.info('Closed DB connection')

def get_and_insert(ri, include_speedtest=False):
    """Gather router info and insert into the database."""
    try:
        if not ri.is_wan_online():
            logger.error("Router is offline. Skipping data collection.")
            return
        uptime = ri.get_uptime_secs()
        mem = ri.get_memory_usage()
        cpu = ri.get_cpu_usage()
        traffic = ri.get_traffic()
        clients = ri.get_clients_fullinfo()
        values = (
            uptime, int(mem.get('mem_total')), int(mem.get('mem_free')), int(mem.get('mem_used')),
            int(cpu.get('cpu1_total', 0)), int(cpu.get('cpu2_total', 0)), int(cpu.get('cpu3_total', 0)), int(cpu.get('cpu4_total', 0)),
            int(cpu.get('cpu1_usage', 0)), int(cpu.get('cpu2_usage', 0)), int(cpu.get('cpu3_usage', 0)), int(cpu.get('cpu4_usage', 0)),
            ri.get_status_wan().get('statusstr'), len(clients.get('maclist', [])),
            traffic['speed']['tx'], traffic['speed']['rx'],
            ri.get_traffic_wireless2GHZ()['speed']['tx'], ri.get_traffic_wireless2GHZ()['speed']['rx'],
            ri.get_traffic_wireless5GHZ()['speed']['tx'], ri.get_traffic_wireless5GHZ()['speed']['rx'],
            ri.get_traffic_wired()['speed']['tx'], ri.get_traffic_wired()['speed']['rx'],
            ri.get_traffic_bridge()['speed']['tx'], ri.get_traffic_bridge()['speed']['rx'],
            traffic['total']['sent'], traffic['total']['recv']
        )
        if include_speedtest:
            speedtest = ri.get_speedtest_result()
            values += (speedtest.get('download', 0.0), speedtest.get('upload', 0.0), speedtest.get('ping', 0.0))
        connect(values, include_speedtest)
    except RouterRequestError as e:
        logger.exception(f"Error gathering router info: {e}")
        raise

def connect_to_router():
    """Attempt to connect to the router with retries."""
    for attempt in range(MAX_RETRIES):
        try:
            logger.info(f"Attempting to connect to router (Attempt {attempt + 1})")
            ri = RouterInfo(asusIP, asusUser, asusPass)
            logger.info("Successfully connected to router")
            return ri
        except RouterRequestError as e:
            logger.error(f"Failed to connect: {e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
    logger.error("Max retries reached. Unable to connect to router.")
    return None

if __name__ == "__main__":
    ri = connect_to_router()
    if not ri:
        logger.error("Exiting due to inability to connect to router.")
        sys.exit(1)

    scheduler = BlockingScheduler()

    @scheduler.scheduled_job('interval', seconds=interval, max_instances=5)
    def regular_task():
        global ri
        logger.info("Running regular task")
        try:
            get_and_insert(ri)
        except Exception as e:
            logger.error(f"Task failed: {e}. Reconnecting to router.")
            ri = connect_to_router()
            if not ri:
                logger.error("Failed to reconnect. Skipping this run.")

    @scheduler.scheduled_job('interval', seconds=speedtest_interval, max_instances=1)
    def speedtest_task():
        global ri
        logger.info("Running speedtest task")
        try:
            get_and_insert(ri, include_speedtest=True)
        except Exception as e:
            logger.error(f"Speedtest task failed: {e}. Reconnecting to router.")
            ri = connect_to_router()
            if not ri:
                logger.error("Failed to reconnect. Skipping this run.")

    try:
        scheduler.start()
    except Exception as e:
        logger.exception("Scheduler crashed")
    finally:
        logger.info("Scheduler stopped")