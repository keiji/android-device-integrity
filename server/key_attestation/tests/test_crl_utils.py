import unittest
import requests
import json
import time
import threading
from unittest.mock import patch, MagicMock, mock_open
from server.key_attestation import crl_utils

class TestCrlUtils(unittest.TestCase):

    def setUp(self):
        # Reset the global updater for each test
        crl_utils._updater = crl_utils.CrlUpdater()
        # Ensure we mock the cache directory to avoid file system side effects
        self.addCleanup(self.stop_updater)

    def stop_updater(self):
        crl_utils._updater._stop_event.set()
        if crl_utils._updater._thread and crl_utils._updater._thread.is_alive():
             crl_utils._updater._thread.join(timeout=2)

    @patch('server.key_attestation.crl_utils.requests.get')
    def test_download_crl_success(self, mock_get):
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'{"entries": {}}'
        mock_response.json.return_value = {"entries": {}}
        mock_response.headers = {"Cache-Control": "max-age=3600"}
        mock_get.return_value = mock_response

        # Use the internal function to test download specifically
        with patch('server.key_attestation.crl_utils._cache_crl', return_value=int(time.time()) + 3600):
            crl_data, expiry = crl_utils._download_crl()

        self.assertIsNotNone(crl_data)
        self.assertIsNotNone(expiry)
        mock_get.assert_called_once()

    @patch('server.key_attestation.crl_utils.requests.get')
    def test_download_crl_failure(self, mock_get):
        # Mock failed response
        mock_get.side_effect = requests.exceptions.RequestException("Network error")

        crl_data, expiry = crl_utils._download_crl()

        self.assertIsNone(crl_data)
        self.assertIsNone(expiry)

    @patch('server.key_attestation.crl_utils.requests.get')
    @patch('server.key_attestation.crl_utils._get_cached_crl')
    def test_get_crl_via_updater(self, mock_get_cached, mock_get):
        # Mock no cache
        mock_get_cached.return_value = (None, None)

        # Mock successful download
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'{"entries": {"123": {"status": "REVOKED"}}}' # Add content for hashlib
        mock_response.json.return_value = {"entries": {"123": {"status": "REVOKED"}}}
        mock_response.headers = {"Cache-Control": "max-age=3600"}
        mock_get.return_value = mock_response

        # Mock os calls to avoid disk writes
        with patch('server.key_attestation.crl_utils.os.makedirs'), \
             patch('server.key_attestation.crl_utils.open', mock_open()), \
             patch('server.key_attestation.crl_utils.os.rename'):

             # Call get_crl
             data = crl_utils.get_crl()

             self.assertIsNotNone(data)
             self.assertIn("entries", data)
             self.assertIn("123", data["entries"])

    @patch('server.key_attestation.crl_utils.requests.get')
    @patch('server.key_attestation.crl_utils._get_cached_crl')
    def test_get_crl_with_existing_cache(self, mock_get_cached, mock_get):
        # Mock existing fresh cache
        # Use +7200 to ensure we are well before the "refresh 1 hour before expiry" window
        mock_get_cached.return_value = ({"entries": {}}, int(time.time()) + 7200)

        # Call get_crl
        data = crl_utils.get_crl()

        self.assertIsNotNone(data)
        # Should not have called download because cache is fresh
        mock_get.assert_not_called()

if __name__ == '__main__':
    unittest.main()
