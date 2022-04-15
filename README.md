# Monitoring Asus Router using grafana

Got the idea from two different git repos 

![GrafanaPart](https://github.com/jphilll/GrafanaAsusRouterMonitor)

![CodeSide](https://github.com/lmeulen/AsusRouterMonitor)


# GrafanaAsusRouterMonitor
Monitor your Asus router with Grafana.

## What each piece does 
### Python
This connects to the router and gathers the information and inserts it to the mysql DB at the interval set in the .env file

### mySQL
On startup 2 tables are created, one is named in the .env file, the other is number of cleared events

Added the configuration set up so that the scheduler is always running 
Created an even that runs every 21 days and clears out any data thats over 14 days old

### Grafana
Displays the gathered data

Things are set up to so that connection to the mysql DB is already made 
There is a prebuild dashboard made as part of the build to display the info gathered

![GrafanaAsusRouterMonitor](https://github.com/jphilll/AsusRouterMonitor/raw/main/asusMonitor.png)
This is what it looks like.

## HowTo

### What changes to make 
I've tried to make sure all the changes in the .env file

```shell
# Input basic information below..

# Input router details for the python to gather the info
routerIP=#IP
routerUser=#USER
routerPass=#ROUTERPASS

# mySql details to connect to the DB
mysqlIP=#MYSQLENDPOINT
mysqlPort=3306
dbName=asusMonitor
tableName=monitorTable
monitorUser=monitor
monitorPass=#password

# Interval that the information will be gathered in seconds
intervalSeconds=300

# Additional user for grafana to poll the data
grafanaUser=grafana
grafanaPass=#password

# Setting the timezone for mySql 
TZ=Europe/Dublin

# Grafana user and pass and the type of db that will be created
ADMIN_USER=admin
ADMIN_PASSWORD=admin
DBTYPE=mysql
```

### How to run

1. Install install ![docker-compose](https://docs.docker.com/compose/install/)
2. Make changes to .env file that suit
3. Run `docker-compose up` and check that things are working 
4. Once you are sure everything is working correctly run `docker-compose up -d` to keep things running in the background