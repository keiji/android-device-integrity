import unittest
import json
import os
import time
import tempfile
from unittest.mock import MagicMock, patch

import requests

from server.key_attestation import root_certificates
from server.key_attestation.root_certificates import (
    ROOT_CERTIFICATES,
    RootCertificatesUpdater,
    get_root_certificates,
)

SAMPLE_ROOT_PEM = """-----BEGIN CERTIFICATE-----
MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc
MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET
MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4
WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex
MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG
EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt
G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5
Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA
MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH
EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY
uR2zh/80lQyu9vAFCj6E4AXc+osmRg==
-----END CERTIFICATE-----"""


def _mock_response(payload, cache_control='max-age=3600'):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = payload
    response.headers = {'Cache-Control': cache_control}
    return response


class RootCertificatesUpdaterTest(unittest.TestCase):

    def setUp(self):
        self.cache_dir = tempfile.mkdtemp()
        patcher = patch.object(root_certificates, 'ROOTS_CACHE_DIR', self.cache_dir)
        patcher.start()
        self.addCleanup(patcher.stop)

    @patch('server.key_attestation.root_certificates.requests.get')
    def test_download_roots_success(self, mock_get):
        payload = [SAMPLE_ROOT_PEM]
        mock_get.return_value = _mock_response(payload, 'max-age=3600')

        before = int(time.time())
        roots, expiry = root_certificates._download_roots()

        self.assertEqual(roots, payload)
        self.assertIsNotNone(expiry)
        self.assertTrue(before + 3600 <= expiry <= before + 3600 + 5)
        self.assertTrue(
            os.path.exists(os.path.join(self.cache_dir, f'roots-{expiry}.json'))
        )

    @patch('server.key_attestation.root_certificates.requests.get')
    def test_download_roots_failure(self, mock_get):
        mock_get.side_effect = requests.exceptions.RequestException('Network error')

        roots, expiry = root_certificates._download_roots()

        self.assertIsNone(roots)
        self.assertIsNone(expiry)

    @patch('server.key_attestation.root_certificates.requests.get')
    def test_download_roots_invalid_payload(self, mock_get):
        mock_get.return_value = _mock_response({'entries': {}})

        roots, expiry = root_certificates._download_roots()

        self.assertIsNone(roots)
        self.assertIsNone(expiry)

    @patch('server.key_attestation.root_certificates.requests.get')
    @patch('server.key_attestation.root_certificates._get_cached_roots', return_value=(None, None))
    def test_get_roots_via_updater(self, mock_get_cached, mock_get):
        payload = [SAMPLE_ROOT_PEM]
        mock_get.return_value = _mock_response(payload, 'max-age=3600')
        updater = RootCertificatesUpdater()
        updater.start()

        with patch.object(root_certificates, '_updater', updater):
            roots = get_root_certificates()

        self.assertEqual(roots, payload)
        updater._stop_event.set()
        if updater._thread and updater._thread.is_alive():
            updater._thread.join(timeout=2)

    @patch('server.key_attestation.root_certificates.requests.get')
    def test_get_roots_from_valid_cache(self, mock_get):
        expiry = int(time.time()) + 7200
        cache_path = os.path.join(self.cache_dir, f'roots-{expiry}.json')
        with open(cache_path, 'w') as f:
            json.dump([SAMPLE_ROOT_PEM], f)

        roots, cached_expiry = root_certificates._get_cached_roots()

        self.assertEqual(roots, [SAMPLE_ROOT_PEM])
        self.assertEqual(cached_expiry, expiry)
        mock_get.assert_not_called()

    def test_expired_cache_is_deleted(self):
        expired = int(time.time()) - 100
        cache_path = os.path.join(self.cache_dir, f'roots-{expired}.json')
        with open(cache_path, 'w') as f:
            json.dump([SAMPLE_ROOT_PEM], f)

        roots, expiry = root_certificates._get_cached_roots()

        self.assertIsNone(roots)
        self.assertIsNone(expiry)
        self.assertFalse(os.path.exists(cache_path))

    @patch('server.key_attestation.root_certificates.requests.get')
    def test_download_roots_uses_default_max_age_without_header(self, mock_get):
        payload = [SAMPLE_ROOT_PEM]
        mock_get.return_value = _mock_response(payload, cache_control=None)

        before = int(time.time())
        roots, expiry = root_certificates._download_roots()

        self.assertEqual(roots, payload)
        self.assertIsNotNone(expiry)
        self.assertTrue(before + root_certificates.DEFAULT_CACHE_MAX_AGE_SECONDS <= expiry)

    def test_cache_roots_no_store(self):
        expiry = root_certificates._cache_roots([SAMPLE_ROOT_PEM], 'no-store')

        self.assertEqual(expiry, 0)

    def test_updater_serves_previously_fetched_roots(self):
        updater = RootCertificatesUpdater()
        updater._started = True  # Prevent spawning the background thread
        updater._roots = [SAMPLE_ROOT_PEM]

        with patch.object(root_certificates, 'requests') as mock_requests:
            roots = updater.get_roots()

        self.assertEqual(roots, [SAMPLE_ROOT_PEM])
        mock_requests.get.assert_not_called()

    def test_fallback_to_baked_in_list(self):
        stub_updater = MagicMock()
        stub_updater.get_roots.return_value = None

        with patch.object(root_certificates, '_updater', stub_updater):
            roots = get_root_certificates()

        self.assertEqual(roots, ROOT_CERTIFICATES)
        for entry in roots:
            self.assertIsInstance(entry, str)
            self.assertTrue(entry.startswith('-----BEGIN CERTIFICATE-----'))


if __name__ == '__main__':
    unittest.main()
