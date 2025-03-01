import requests
import base64
import json
import time
import logging
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

class RouterInfo:
    def __init__(self, ipaddress: str, username: str, password: str):
        """
        Initialize the RouterInfo object and authenticate with the router.

        Args:
            ipaddress (str): The IP address of the router.
            username (str): The username for authentication.
            password (str): The password for authentication.

        Raises:
            Exception: If authentication fails.
        """
        self.url = f'http://{ipaddress}/appGet.cgi'
        self.headers = None
        if not self.__authenticate(ipaddress, username, password):
            logger.error("Failed to authenticate with the router.")
            raise Exception("Authentication failed")

    def __authenticate(self, ipaddress: str, username: str, password: str) -> bool:
        """
        Authenticate with the router and store the authentication token.

        Args:
            ipaddress (str): The IP address of the router.
            username (str): The username for authentication.
            password (str): The password for authentication.

        Returns:
            bool: True if authentication is successful, False otherwise.
        """
        auth = f"{username}:{password}".encode('ascii')
        logintoken = base64.b64encode(auth).decode('ascii')
        payload = f"login_authorization={logintoken}"
        headers = {
            'user-agent': "asusrouter-Android-DUTUtil-1.0.0.245"
        }
        try:
            r = requests.post(url=f'http://{ipaddress}/login.cgi', data=payload, headers=headers, timeout=5)
            r.raise_for_status()
            response = r.json()
            if "asus_token" in response:
                self.headers = {
                    'user-agent': "asusrouter-Android-DUTUtil-1.0.0.245",
                    'cookie': f'asus_token={response["asus_token"]}'
                }
                return True
            else:
                logger.error("Failed to authenticate: No token received.")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Authentication failed: {e}")
            return False

    def __get(self, command: str) -> Optional[str]:
        """
        Send a command to the router and return the response.

        Args:
            command (str): The command to send to the router.

        Returns:
            Optional[str]: The response from the router, or None if the request fails.
        """
        if not self.headers:
            logger.error("Not authenticated. Please log in first.")
            return None

        payload = f"hook={command}"
        try:
            r = requests.post(url=self.url, data=payload, headers=self.headers, timeout=5)
            r.raise_for_status()
            return r.text
        except requests.exceptions.Timeout:
            logger.error("Request to router timed out.")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Request to router failed: {e}")
            return None

    def get_uptime(self) -> Optional[Dict[str, str]]:
        """
        Return the uptime of the router.

        Returns:
            Optional[Dict[str, str]]: A dictionary containing the following keys:
                - since (str): The timestamp of the last boot.
                - uptime (str): The uptime in seconds.
            None: If the request fails or the response is invalid.
        """
        r = self.__get('uptime()')
        if not r:
            return None

        try:
            since = r.partition(':')[2].partition('(')[0]
            up = r.partition('(')[2].partition(' ')[0]
            return json.loads('{' + f'"since":"{since}", "uptime":"{up}"' + '}')
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse uptime response: {e}")
            return None

    def get_uptime_secs(self) -> Optional[int]:
        """
        Return the uptime of the router in seconds.

        Returns:
            Optional[int]: The uptime in seconds, or None if the request fails.
        """
        uptime = self.get_uptime()
        return int(uptime['uptime']) if uptime else None

    def get_memory_usage(self) -> Optional[Dict[str, int]]:
        """
        Return memory usage statistics of the router.

        Returns:
            Optional[Dict[str, int]]: A dictionary containing the following keys:
                - mem_total (int): Total memory in KB.
                - mem_free (int): Free memory in KB.
                - mem_used (int): Used memory in KB.
            None: If the request fails or the response is invalid.
        """
        r = self.__get('memory_usage()')
        if not r:
            return None

        try:
            return json.loads('{' + r[17:])
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse memory usage response: {e}")
            return None

    def get_cpu_usage(self) -> Optional[Dict[str, int]]:
        """
        Return CPU usage statistics of the router.

        Returns:
            Optional[Dict[str, int]]: A dictionary containing the following keys:
                - cpu1_total (int): Total CPU 1 usage.
                - cpu1_usage (int): Used CPU 1 usage.
                - cpu2_total (int): Total CPU 2 usage.
                - cpu2_usage (int): Used CPU 2 usage.
            None: If the request fails or the response is invalid.
        """
        r = self.__get('cpu_usage()')
        if not r:
            return None

        try:
            return json.loads('{' + r[14:])
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse CPU usage response: {e}")
            return None

    def get_clients_fullinfo(self) -> Optional[Dict[str, Any]]:
        """
        Obtain a list of all clients connected to the router.

        Returns:
            Optional[Dict[str, Any]]: A dictionary containing client information, or None if the request fails.
        """
        r = self.__get('get_clientlist()')
        if not r:
            return None

        try:
            return json.loads(r)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse client list response: {e}")
            return None

    def get_traffic_total(self) -> Optional[Dict[str, float]]:
        """
        Get total traffic since the last router reboot.

        Returns:
            Optional[Dict[str, float]]: A dictionary containing the following keys:
                - sent (float): Total data sent in MB.
                - recv (float): Total data received in MB.
            None: If the request fails or the response is invalid.
        """
        r = self.__get('netdev(appobj)')
        if not r:
            return None

        try:
            data = json.loads(r)
            tx = int(data['netdev']['INTERNET_tx'], base=16) * 8 / 1024 / 1024 / 2
            rx = int(data['netdev']['INTERNET_rx'], base=16) * 8 / 1024 / 1024 / 2
            return {'sent': tx, 'recv': rx}
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse traffic total response: {e}")
            return None

    def get_traffic(self) -> Optional[Dict[str, Dict[str, float]]]:
        """
        Get current and total traffic since the last router reboot.

        Returns:
            Optional[Dict[str, Dict[str, float]]]: A dictionary containing the following keys:
                - speed: A dictionary with "tx" and "rx" keys for current traffic in MB/s.
                - total: A dictionary with "sent" and "recv" keys for total traffic in MB.
            None: If the request fails or the response is invalid.
        """
        meas_1 = self.__get('netdev(appobj)')
        if not meas_1:
            return None

        time.sleep(2)  # Wait to calculate current traffic
        meas_2 = self.__get('netdev(appobj)')
        if not meas_2:
            return None

        try:
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
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse traffic response: {e}")
            return None

    def get_status_wan(self) -> Optional[Dict[str, str]]:
        """
        Get the status of the WAN connection.

        Returns:
            Optional[Dict[str, str]]: A dictionary containing WAN status information, or None if the request fails.
        """
        r = self.__get('wanlink()')
        if not r:
            return None

        try:
            status = {}
            for f in r.split('\n'):
                if 'return' in f and 'wanlink_' in f:
                    key = f.partition('(')[0].partition('_')[2]
                    value = f.rpartition(' ')[-1][:-2]
                    status[key] = value
            return status
        except Exception as e:
            logger.error(f"Failed to parse WAN status response: {e}")
            return None

    def is_wan_online(self) -> bool:
        """
        Check if the WAN connection is online.

        Returns:
            bool: True if the WAN connection is online, False otherwise.
        """
        status = self.get_status_wan()
        return status and status.get('status') == '1'