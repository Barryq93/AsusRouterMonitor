#!/usr/bin/python3

from RouterInfo import RouterInfo
import mysql.connector
from apscheduler.schedulers.blocking import BlockingScheduler
import os
import time
import logging
import sys

# setting loggers
os.environ['TZ']
time.tzset()
logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
stdout_handler = logging.StreamHandler(sys.stdout.flush())
stdout_handler.setLevel(logging.DEBUG)
stdout_handler.setFormatter(formatter)
logger.addHandler(stdout_handler)

# set asus router variables
asusIP=os.environ['routerIP']
asusUser=os.environ['routerUser']
asusPass=os.environ['routerPass']

# Set mysql variables
sqlIP = os.environ['mysqlIP'] 
sqlPort = os.environ['mysqlPort']
sqlUser = os.environ['monitorUser']
sqlPasswd = os.environ['monitorPass']
sqlDb = os.environ['dbName']
sqlTable = os.environ['tableName']

# getting interval time for env
interval=int(os.environ['intervalSeconds'])

def connect(values):
    try:
        # connect to DB
        mydb = mysql.connector.connect(
            host='{}'.format(sqlIP),
            port='{}'.format(sqlPort),
            user='{}'.format(sqlUser),
            passwd='{}'.format(sqlPasswd),
            database='{}'.format(sqlDb)
        )
    except Exception as e:
        logger.exception('unable to connect to DB')
        sys.exit(1)

    logger.info('Connecting to DB')
    mycursor = mydb.cursor()

    try:
        # execute insert statement
        sqlCommand = '''INSERT INTO {}(Uptime, memTotal, memFree, memUsed, cpu1Total, cpu2Total, cpu3Total, cpu4Total, cpu1Usage, cpu2Usage, cpu3Usage, cpu4Usage, wanStatus, deviceCount, internetTXSpeed, internetRXSpeed, 2GHXTXSpeed, 2GHXRXSpeed, 5GHXTXSpeed, 5GHXRXSpeed, wiredTXSpeed, wiredRXSpeed, bridgeTXSpeed, bridgeRXSpeed, sentData, recvData) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'''.format(sqlTable)
        mycursor.execute(sqlCommand, values)
        logger.info('Insert Complete')
        mydb.commit()
    except Exception as e:
        logger.exception('unable to insert to DB')
        sys.exit(1)

    # close db connection
    mycursor.close()
    mydb.close()
    logger.info('closed db connection')

def getAndInsert(ri):
    try:
        # gather router info
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

        logger.info('Info Gathered')
    except Exception as e:
        logger.exception('problems gathering info')
        sys.exit(1)

    # build insert statement values
    values = (Uptime, memTotal, memFree, memUsed, cpu1Total, cpu2Total, cpu3Total, cpu4Total, cpu1Usage, cpu2Usage, cpu3Usage, cpu4Usage, wanStatus, deviceCount, internetTXSpeed, internetRXSpeed, _2GHXTXSpeed, _2GHXRXSpeed, _5GHXTXSpeed, _5GHXRXSpeed, wiredTXSpeed, wiredRXSpeed, bridgeTXSpeed, bridgeRXSpeed, sentData, recvData)

    # pass insert statement to db method
    connect(values)

if __name__ == "__main__":
    try:
        # set up router info 
        ri = RouterInfo(asusIP, asusUser, asusPass)
    except Exception as e:
        logger.error('Unable to gather info ', e)
        sys.exit(1)

    logger.info('starting monitor')
    scheduler=BlockingScheduler()
    # add a job that gets routerinfo at set interval and passes details to getAndInsert method
    scheduler.add_job(getAndInsert, 'interval', seconds=interval, max_instances=5, args=[ri])
    scheduler.start()