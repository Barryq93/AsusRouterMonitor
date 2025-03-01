#!/usr/bin/python3

from RouterInfo import RouterInfo, RouterRequestError
import mysql.connector
from apscheduler.schedulers.blocking import BlockingScheduler
import os
import logging
import sys
import signal
from dotenv import load_dotenv
import time

# Load environment variables from .env file in the current directory
load_dotenv()

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)  # Set to INFO; change to DEBUG for more detail
formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
stdout_handler.setFormatter(formatter)
logger.addHandler(stdout_handler)

# Router and MySQL variables from environment with defaults or checks
asusIP = os.environ.get('routerIP')
asusUser = os.environ.get('routerUser')
asusPass = os.environ.get('routerPass')
sqlIP = os.environ.get('mysqlIP', 'localhost')
sqlPort = os.environ.get('mysqlPort', '3306')
sqlUser = os.environ.get('monitorUser', 'monitor')
sqlPasswd = os.environ.get('monitorPass', 'password')
sqlDb = os.environ.get('dbName', 'asusMonitor')
sqlTable = os.environ.get('tableName', 'monitorTable')
interval = int(os.environ.get('intervalSeconds', '300'))  # Default to 300 seconds
speedtest_interval = int(os.environ.get('speedtestIntervalSeconds', '240'))  # Default to 1 hour
print_only = 'false'  # Use env var, default to true

# Debug print-only mode immediately after setting it
logger.info(f"Print-only mode initialized as: {print_only}")

# Check for required router variables
missing_vars = []
if not asusIP:
    missing_vars.append('routerIP')
if not asusUser:
    missing_vars.append('routerUser')
if not asusPass:
    missing_vars.append('routerPass')

if missing_vars:
    logger.error(f"Missing required environment variables: {', '.join(missing_vars)}. Please set them in .env or environment.")
    sys.exit(1)

# Retry settings
MAX_RETRIES = 3
RETRY_DELAY = 10  # seconds

# Global scheduler instance for shutdown
scheduler = BlockingScheduler()

def signal_handler(signum, frame):
    """Handle SIGTERM and SIGINT (Ctrl+C) to shut down gracefully."""
    logger.info(f"Received signal {signum} (e.g., SIGTERM or Ctrl+C), shutting down scheduler...")
    scheduler.shutdown(wait=False)  # Stop scheduler immediately
    logger.info("Scheduler stopped")
    sys.exit(0)

def connect(values, include_speedtest=False):
    """Connect to MySQL and insert router data."""
    if print_only:  # Safeguard: Skip MySQL entirely if print_only is True
        logger.info("Skipping MySQL connection due to print-only mode")
        return

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
    """Gather router info and either insert into database or print based on PRINT_ONLY flag."""
    logger.info(f"Running get_and_insert with print_only={print_only}")
    try:
        if not ri.is_wan_online():
            logger.error("Router is offline. Skipping data collection.")
            return
        uptime = ri.get_uptime_secs()
        mem = ri.get_memory_usage()
        cpu = ri.get_cpu_usage()
        traffic = ri.get_traffic()
        clients = ri.get_clients_fullinfo()
        data_dict = {
            "Uptime": uptime,
            "memTotal": int(mem.get('mem_total')),
            "memFree": int(mem.get('mem_free')),
            "memUsed": int(mem.get('mem_used')),
            "cpu1Total": int(cpu.get('cpu1_total', 0)),
            "cpu2Total": int(cpu.get('cpu2_total', 0)),
            "cpu3Total": int(cpu.get('cpu3_total', 0)),
            "cpu4Total": int(cpu.get('cpu4_total', 0)),
            "cpu1Usage": int(cpu.get('cpu1_usage', 0)),
            "cpu2Usage": int(cpu.get('cpu2_usage', 0)),
            "cpu3Usage": int(cpu.get('cpu3_usage', 0)),
            "cpu4Usage": int(cpu.get('cpu4_usage', 0)),
            "wanStatus": ri.get_status_wan().get('statusstr'),
            "deviceCount": (len(ri.get_dhcp_list().get('dhcpLeaseMacList'))) - 1,
            "internetTXSpeed": traffic['speed']['tx'],
            "internetRXSpeed": traffic['speed']['rx'],
            "2GHXTXSpeed": ri.get_traffic_wireless2GHZ()['speed']['tx'],
            "2GHXRXSpeed": ri.get_traffic_wireless2GHZ()['speed']['rx'],
            "5GHXTXSpeed": ri.get_traffic_wireless5GHZ()['speed']['tx'],
            "5GHXRXSpeed": ri.get_traffic_wireless5GHZ()['speed']['rx'],
            "wiredTXSpeed": ri.get_traffic_wired()['speed']['tx'],
            "wiredRXSpeed": ri.get_traffic_wired()['speed']['rx'],
            "bridgeTXSpeed": ri.get_traffic_bridge()['speed']['tx'],
            "bridgeRXSpeed": ri.get_traffic_bridge()['speed']['rx'],
            "sentData": traffic['total']['sent'],
            "recvData": traffic['total']['recv']
        }
        if include_speedtest:
            # Use wait_for_speedtest to trigger a new test and get fresh results
            speedtest = ri.wait_for_speedtest(timeout=120)  # Increased timeout to 120s for speed test
            if speedtest:
                data_dict.update({
                    "speedDownload": speedtest.get('speedDownload', 0.0),
                    "speedUpload": speedtest.get('speedUpload', 0.0),
                    "ping": speedtest.get('ping', 0.0)
                })
            else:
                logger.warning("Speedtest failed or returned no results; using defaults")
                data_dict.update({
                    "speedDownload": 0.0,
                    "speedUpload": 0.0,
                    "ping": 0.0
                })
        
        if print_only:
            logger.info("Collected Router Data:")
            for key, value in data_dict.items():
                logger.info(f"{key}: {value}")
        else:
            connect(tuple(data_dict.values()), include_speedtest)
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
    # Set up signal handlers for SIGTERM and SIGINT (Ctrl+C)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    ri = connect_to_router()
    if not ri:
        logger.error("Exiting due to inability to connect to router.")
        sys.exit(1)

    logger.info(f"Interval set to: {interval} seconds for regular task")
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

    logger.info(f"Interval set to: {speedtest_interval} seconds for regular task")
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