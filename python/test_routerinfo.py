import unittest
from unittest.mock import patch, Mock
from RouterInfo import RouterInfo, RouterRequestError

class TestRouterInfo(unittest.TestCase):
    def setUp(self):
        self.ri = RouterInfo("192.168.1.1", "admin", "password")
        self.ri.headers = {'user-agent': "test", 'cookie': "asus_token=test_token"}

    @patch('requests.post')
    def test_authenticate_success(self, mock_post):
        mock_response = Mock()
        mock_response.json.return_value = {"asus_token": "test_token"}
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        ri = RouterInfo("192.168.1.1", "admin", "password")
        self.assertIsNotNone(ri.headers)

    @patch('requests.post')
    def test_authenticate_failure(self, mock_post):
        mock_response = Mock()
        mock_response.json.return_value = {}
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        with self.assertRaises(RouterRequestError):
            RouterInfo("192.168.1.1", "admin", "password")

    @patch('requests.post')
    def test_get_uptime(self, mock_post):
        mock_response = Mock()
        mock_response.text = "uptime: Mon Jan 01 00:00:00 2023:(3600 secs)"
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        result = self.ri.get_uptime()
        self.assertEqual(result, {"since": "Mon Jan 01 00:00:00 2023", "uptime": "3600"})

    @patch('requests.post')
    def test_get_memory_usage(self, mock_post):
        mock_response = Mock()
        mock_response.text = "memory_usage(): \"mem_total\": 1024, \"mem_free\": 512, \"mem_used\": 512}"
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        result = self.ri.get_memory_usage()
        self.assertEqual(result, {"mem_total": 1024, "mem_free": 512, "mem_used": 512})

    @patch('requests.post')
    def test_get_speedtest_result(self, mock_post):
        mock_response = Mock()
        mock_response.text = '{"download": 100.5, "upload": 50.2, "ping": 20.1}'
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        result = self.ri.get_speedtest_result()
        self.assertEqual(result, {"download": 100.5, "upload": 50.2, "ping": 20.1})

    @patch('requests.post')
    def test_request_failure(self, mock_post):
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("401 Unauthorized")
        mock_post.return_value = mock_response
        with self.assertRaises(RouterRequestError):
            self.ri.get_uptime()

if __name__ == '__main__':
    unittest.main()