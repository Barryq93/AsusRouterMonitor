import requests
import base64
import json
import time
import logging
import re
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class RouterRequestError(Exception):
    """Custom exception for router request failures."""
    pass

class RouterInfo:
    def __init__(self, ipaddress: str, username: str, password: str):
        """Initialize the RouterInfo object and authenticate with the router."""
        self.url = f'http://{ipaddress}/appGet.cgi'
        self.ipaddress = ipaddress
        self.username = username
        self.password = password
        self.headers = None
        if not self.__authenticate():
            logger.error("Failed to authenticate with the router.")
            raise RouterRequestError("Authentication failed")

    def __authenticate(self) -> bool:
        """Authenticate with the router and store the authentication token."""
        auth = f"{self.username}:{self.password}".encode('ascii')
        logintoken = base64.b64encode(auth).decode('ascii')
        payload = f"login_authorization={logintoken}"
        headers = {'user-agent': "asusrouter-Android-DUTUtil-1.0.0.245"}
        try:
            r = requests.post(url=f'http://{self.ipaddress}/login.cgi', data=payload, headers=headers, timeout=5)
            r.raise_for_status()
            response = r.json()
            if "asus_token" in response:
                self.headers = {
                    'user-agent': "asusrouter-Android-DUTUtil-1.0.0.245",
                    'cookie': f'asus_token={response["asus_token"]}'
                }
                return True
            logger.error("Failed to authenticate: No token received.")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Authentication failed: {e}")
            return False

    def __refresh_token(self) -> bool:
        """Refresh the authentication token if it expires."""
        return self.__authenticate()

    def __get(self, command: str) -> str:
        """Send a command to the router and return the response."""
        if not self.headers:
            raise RouterRequestError("Not authenticated. Please log in first.")
        payload = f"hook={command}"
        try:
            r = requests.post(url=self.url, data=payload, headers=self.headers, timeout=5)
            r.raise_for_status()
            return r.text
        except requests.exceptions.RequestException as e:
            if isinstance(e, requests.exceptions.HTTPError) and getattr(e.response, 'status_code', None) == 401:
                logger.info("Token expired, attempting to refresh.")
                if self.__refresh_token():
                    return self.__get(command)  # Retry with new token
            raise RouterRequestError(f"Request to router failed: {e}")

    def get_uptime(self) -> Dict[str, str]:
        """Return the uptime of the router."""
        r = self.__get('uptime()')
        try:
            since = r.partition(':')[2].partition('(')[0].strip().rstrip(':')
            uptime = r.partition('(')[2].partition(' ')[0]
            return {"since": since, "uptime": uptime}
        except Exception as e:
            raise RouterRequestError(f"Failed to parse uptime response: {e}")

    def get_uptime_secs(self) -> int:
        """Return the uptime of the router in seconds."""
        return int(self.get_uptime()['uptime'])

    def get_memory_usage(self):
        """
        Return memory usage of the router
        Format: {'mem_total': '262144', 'mem_free': '107320', 'mem_used': '154824'}
        :returns: JSON with memory variables
        """
        s = self.__get('memory_usage()')
        return json.loads('{' + s[17:])

    def get_cpu_usage(self) -> Dict[str, int]:
        """Return CPU usage statistics of the router."""
        r = self.__get('cpu_usage()')
        try:
            return json.loads('{' + r[14:])
        except json.JSONDecodeError as e:
            raise RouterRequestError(f"Failed to parse CPU usage response: {e}")

    def get_clients_fullinfo(self) -> Dict[str, Any]:
        """Obtain a list of all clients connected to the router."""
        r = self.__get('get_clientlist()')
        return json.loads(r)
    
    def get_dhcp_list(self):
        """
        Obtain a list of DHCP leases
        Format: { "dhcpLeaseMacList":[["00:00:00:00:00:00", "name"], ...]
        :returns: JSON with a list of DHCP leases
        """
        r = self.__get("dhcpLeaseMacList()")
        return json.loads(r)

    def get_traffic_total(self) -> Dict[str, float]:
        """Get total traffic since the last router reboot."""
        r = self.__get('netdev(appobj)')
        data = json.loads(r)
        tx = int(data['netdev']['INTERNET_tx'], base=16) * 8 / 1024 / 1024 / 2
        rx = int(data['netdev']['INTERNET_rx'], base=16) * 8 / 1024 / 1024 / 2
        return {'sent': tx, 'recv': rx}

    def get_traffic(self) -> Dict[str, Dict[str, float]]:
        """Get current and total traffic since the last router reboot."""
        meas_1 = self.__get('netdev(appobj)')
        time.sleep(2)
        meas_2 = self.__get('netdev(appobj)')
        meas_1 = json.loads(meas_1)
        meas_2 = json.loads(meas_2)
        persec = {}
        totaldata = {}
        tx = int(meas_2['netdev']['INTERNET_tx'], base=16) * 8 / 1024 / 1024 / 2
        totaldata['sent'] = tx
        tx -= int(meas_1['netdev']['INTERNET_tx'], base=16) * 8 / 1024 / 1024 / 2
        persec['tx'] = tx
        rx = int(meas_2['netdev']['INTERNET_rx'], base=16) * 8 / 1024 / 1024 / 2
        totaldata['recv'] = rx
        rx -= int(meas_1['netdev']['INTERNET_rx'], base=16) * 8 / 1024 / 1024 / 2
        persec['rx'] = rx
        return {'speed': persec, 'total': totaldata}

    def get_traffic_wireless2GHZ(self) -> Dict[str, Dict[str, float]]:
        """Get current traffic for 2.4GHz wireless."""
        meas_1 = self.__get('netdev(appobj)')
        time.sleep(1)
        meas_2 = self.__get('netdev(appobj)')
        meas_1 = json.loads(meas_1)
        meas_2 = json.loads(meas_2)
        tx = (int(meas_2['netdev']['WIRELESS0_tx'], base=16) - int(meas_1['netdev']['WIRELESS0_tx'], base=16)) * 8 / 1024 / 1024
        rx = (int(meas_2['netdev']['WIRELESS0_rx'], base=16) - int(meas_1['netdev']['WIRELESS0_rx'], base=16)) * 8 / 1024 / 1024
        return {"speed": {"tx": tx, "rx": rx}, "total": {}}

    def get_traffic_wireless5GHZ(self) -> Dict[str, Dict[str, float]]:
        """Get current traffic for 5GHz wireless."""
        meas_1 = self.__get('netdev(appobj)')
        time.sleep(1)
        meas_2 = self.__get('netdev(appobj)')
        meas_1 = json.loads(meas_1)
        meas_2 = json.loads(meas_2)
        tx = (int(meas_2['netdev']['WIRELESS1_tx'], base=16) - int(meas_1['netdev']['WIRELESS1_tx'], base=16)) * 8 / 1024 / 1024
        rx = (int(meas_2['netdev']['WIRELESS1_rx'], base=16) - int(meas_1['netdev']['WIRELESS1_rx'], base=16)) * 8 / 1024 / 1024
        return {"speed": {"tx": tx, "rx": rx}, "total": {}}

    def get_traffic_wired(self) -> Dict[str, Dict[str, float]]:
        """Get current traffic for wired connections."""
        meas_1 = self.__get('netdev(appobj)')
        time.sleep(1)
        meas_2 = self.__get('netdev(appobj)')
        meas_1 = json.loads(meas_1)
        meas_2 = json.loads(meas_2)
        tx = (int(meas_2['netdev']['WIRED_tx'], base=16) - int(meas_1['netdev']['WIRED_tx'], base=16)) * 8 / 1024 / 1024
        rx = (int(meas_2['netdev']['WIRED_rx'], base=16) - int(meas_1['netdev']['WIRED_rx'], base=16)) * 8 / 1024 / 1024
        return {"speed": {"tx": tx, "rx": rx}, "total": {}}

    def get_traffic_bridge(self) -> Dict[str, Dict[str, float]]:
        """Get current traffic for bridge connections."""
        meas_1 = self.__get('netdev(appobj)')
        time.sleep(1)
        meas_2 = self.__get('netdev(appobj)')
        meas_1 = json.loads(meas_1)
        meas_2 = json.loads(meas_2)
        tx = (int(meas_2['netdev']['BRIDGE_tx'], base=16) - int(meas_1['netdev']['BRIDGE_tx'], base=16)) * 8 / 1024 / 1024
        rx = (int(meas_2['netdev']['BRIDGE_rx'], base=16) - int(meas_1['netdev']['BRIDGE_rx'], base=16)) * 8 / 1024 / 1024
        return {"speed": {"tx": tx, "rx": rx}, "total": {}}

    def get_status_wan(self) -> Dict[str, str]:
        """Get the status of the WAN connection."""
        r = self.__get('wanlink()')
        status = {}
        for f in r.split('\n'):
            if 'return' in f and 'wanlink_' in f:
                key = f.partition('(')[0].partition('_')[2]
                value = f.rpartition(' ')[-1][:-2]
                status[key] = value
        return status

    def is_wan_online(self) -> bool:
        """Check if the WAN connection is online."""
        return self.get_status_wan().get('status') == '1'

    def start_speedtest(self) -> bool:
        """Start a new speed test on the router using ookla_speedtest_exe.cgi with POST."""
        try:
            url = f'http://{self.ipaddress}/ookla_speedtest_exe.cgi'
            # Log the attempt to trigger the speed test with request details
            logger.info(f"Attempting to trigger speed test via POST to URL: {url}")
            logger.debug(f"Request headers: {self.headers}")
            data = {}  # Empty payload; adjust if UI inspection reveals specific data
            logger.debug(f"Request payload: {data}")
            
            r = requests.post(url, headers=self.headers, data=data, timeout=5)
            r.raise_for_status()
            
            # Log the successful response
            logger.info(f"Speedtest triggered successfully. Response status: {r.status_code}")
            logger.debug(f"Speedtest response text: {r.text}")
            return True
        except requests.exceptions.RequestException as e:
            # Log the failure with details
            logger.error(f"Failed to trigger speedtest: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response status code: {e.response.status_code}")
                logger.error(f"Response text: {e.response.text}")
            return False

    def get_speedtest_result(self) -> Optional[Dict[str, float]]:
        """Extract the latest speed test results for download, upload, and latency."""
        r = self.__get('ookla_speedtest_get_result()')
        try:
            data = json.loads(r)
            if not isinstance(data, dict) or "ookla_speedtest_get_result" not in data:
                raise ValueError("Unexpected speedtest data format: Missing 'ookla_speedtest_get_result' key")

            test_results = data["ookla_speedtest_get_result"]
            if not isinstance(test_results, list):
                raise ValueError("Speedtest result is not a list")

            download_bandwidth = 0
            upload_bandwidth = 0
            ping_latencies = []

            for entry in test_results:
                if not isinstance(entry, dict):
                    continue
                if entry.get("type") == "result":
                    if "download" in entry and "upload" in entry:
                        download_bandwidth = entry["download"].get("bandwidth", 0)
                        upload_bandwidth = entry["upload"].get("bandwidth", 0)
                elif entry.get("type") == "ping" and "ping" in entry:
                    latency = entry["ping"].get("latency", None)
                    if latency is not None:
                        ping_latencies.append(latency)

            final_latency = sum(ping_latencies) / len(ping_latencies) if ping_latencies else None
            if download_bandwidth == 0 and upload_bandwidth == 0 and final_latency is None:
                logger.error("No valid speed test data found")
                return None

            result = {
                "speedDownload": (download_bandwidth * 8) / 1_000_000 if download_bandwidth else 0.0,
                "speedUpload": (upload_bandwidth * 8) / 1_000_000 if upload_bandwidth else 0.0,
                "ping": final_latency if final_latency is not None else 0.0
            }
            logger.info(f"Speedtest Results: {result}")
            return result
        except (ValueError, json.JSONDecodeError, KeyError, TypeError) as e:
            logger.error(f"Failed to parse speedtest response: {e}")
            return None

    def wait_for_speedtest(self, timeout: int = 60, interval: int = 5) -> Optional[Dict[str, float]]:
        """Wait for the speed test to complete and return the results."""
        if not self.start_speedtest():
            logger.error("Failed to start speed test. Aborting.")
            return None

        start_time = time.time()
        while time.time() - start_time < timeout:
            result = self.get_speedtest_result()
            if result and result["speedDownload"] > 0 and result["speedUpload"] > 0:
                logger.info("Speed test completed successfully")
                return result
            logger.info("Speed test not yet complete, waiting...")
            time.sleep(interval)
        logger.error("Speed test did not complete within timeout")
        return None

    def set_speedtest_start_time(self) -> bool:
        """Set the speed test start time using set_ookla_speedtest_start_time.cgi."""
        try:
            url = f'http://{self.ipaddress}/set_ookla_speedtest_start_time.cgi'
            r = requests.get(url, headers=self.headers, timeout=5)
            r.raise_for_status()
            logger.info(f"Successfully set speed test start time: {r.text}")
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to set speed test start time: {e}")
            return False