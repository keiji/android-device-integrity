# -*- coding: utf-8 -*-

import json
import logging
import os
import re
import threading
import time

import requests

logger = logging.getLogger(__name__)

ROOT_CERTIFICATES_URL = 'https://android.googleapis.com/attestation/root'
ROOTS_CACHE_DIR = '/tmp/attestation_roots'
ROOTS_FILENAME_PATTERN = re.compile(r'roots-(\d+)\.json')
# Google serves both the attestation root list and the CRL with
# "Cache-Control: public, max-age=86400". When the header is missing,
# refresh at most 24 hours later.
DEFAULT_CACHE_MAX_AGE_SECONDS = 86400

# Subject SerialNumber of the Google Hardware Attestation Root. Certificates
# that chain to this root are generated from factory keys and remain trusted
# regardless of their validity period (unless revoked), per the official
# key attestation documentation. Remote Key Provisioning (RKP) chains use
# other roots and keep strict validity checks.
GOOGLE_FACTORY_KEY_ROOT_SERIAL_NUMBER = 'f92009e853b6b045'

# Baked-in fallback root certificates, used only when the remote list has
# never been fetched successfully (e.g. no network at cold start).
ROOT_CERTIFICATES = [
    """-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw
NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7
174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC
W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G
tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx
oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG
1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF
mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz
lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw
n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu
zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo
vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn
w1IdYIg2Wxg7yHcQZemFQg==
-----END CERTIFICATE-----""",
    """-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----""",
]


def _get_cached_roots():
    """
    Checks for cached root certificate lists on disk and returns the content
    if it is still valid.
    Returns (roots, expire_epoch). expire_epoch is None if the cache does not expire.
    """
    if not os.path.exists(ROOTS_CACHE_DIR):
        logger.info(f"Root cache directory '{ROOTS_CACHE_DIR}' does not exist.")
        return None, None

    roots_file_path = os.path.join(ROOTS_CACHE_DIR, 'roots.json')
    if os.path.exists(roots_file_path):
        logger.info(f"Found non-expiring root cache file at '{roots_file_path}'.")
        with open(roots_file_path, 'r') as f:
            return json.load(f), None

    current_time = int(time.time())
    for filename in os.listdir(ROOTS_CACHE_DIR):
        if not (filename.startswith('roots-') and filename.endswith('.json')):
            continue
        match = ROOTS_FILENAME_PATTERN.match(filename)
        if not match:
            logger.warning(f"File '{filename}' looks like a root cache file but failed to parse.")
            continue
        expire_epoch = int(match.group(1))
        file_path = os.path.join(ROOTS_CACHE_DIR, filename)
        if current_time < expire_epoch:
            logger.info(f"Root cache '{filename}' is not expired (expire={expire_epoch}). Using it.")
            with open(file_path, 'r') as f:
                return json.load(f), expire_epoch
        logger.info(f"Root cache '{filename}' is expired. Deleting it.")
        try:
            os.remove(file_path)
        except FileNotFoundError:
            pass  # Race condition handling
    logger.info("No valid cached root certificate list found.")
    return None, None


def _validate_roots_payload(payload):
    """
    Validates that the downloaded payload is a list of PEM strings.
    """
    if not isinstance(payload, list):
        return False, 'payload is not a list'
    if not payload:
        return False, 'payload is empty'
    for i, pem in enumerate(payload):
        if not isinstance(pem, str):
            return False, f'entry {i} is not a string'
        if not pem.startswith('-----BEGIN CERTIFICATE-----'):
            return False, f'entry {i} is not a PEM certificate'
    return True, None


def _cache_roots(roots, cache_control_header):
    """
    Caches the root certificate list based on the Cache-Control header.
    Returns expire_epoch or None (indefinite).
    """
    if not os.path.exists(ROOTS_CACHE_DIR):
        os.makedirs(ROOTS_CACHE_DIR, exist_ok=True)

    _expire_epoch = None
    if cache_control_header:
        logger.info(f"Received Cache-Control header: '{cache_control_header}'")
        max_age_match = re.search(r'max-age=(\d+)', cache_control_header)
        if max_age_match:
            max_age_seconds = int(max_age_match.group(1))
            if max_age_seconds > 0:
                _expire_epoch = int(time.time()) + max_age_seconds
        elif 'no-store' in cache_control_header or 'no-cache' in cache_control_header:
            logger.info('Cache-Control specifies no-store or no-cache. Roots will not be stored.')
            return 0
    if _expire_epoch is None:
        _expire_epoch = int(time.time()) + DEFAULT_CACHE_MAX_AGE_SECONDS
        logger.info(
            'Cache-Control does not specify max-age. '
            f'Using default cache duration of {DEFAULT_CACHE_MAX_AGE_SECONDS} seconds.'
        )

    filename = f'roots-{_expire_epoch}.json'
    logger.info(f'Caching roots with expiration at {_expire_epoch} in \'{filename}\'.')

    temp_filename = f'{filename}.tmp'
    temp_path = os.path.join(ROOTS_CACHE_DIR, temp_filename)
    final_path = os.path.join(ROOTS_CACHE_DIR, filename)

    with open(temp_path, 'w') as f:
        json.dump(roots, f)
    os.rename(temp_path, final_path)

    return _expire_epoch


def _download_roots():
    """
    Downloads the root certificate list from ROOT_CERTIFICATES_URL.
    Returns (roots, expire_epoch).
    """
    logger.info(f'Downloading root certificate list from {ROOT_CERTIFICATES_URL}')
    try:
        response = requests.get(ROOT_CERTIFICATES_URL, timeout=10)
        response.raise_for_status()

        payload = response.json()
        is_valid, reason = _validate_roots_payload(payload)
        if not is_valid:
            logger.error(f'Received invalid root certificate list payload: {reason}')
            return None, None

        expire_epoch = _cache_roots(payload, response.headers.get('Cache-Control'))
        return payload, expire_epoch
    except requests.exceptions.RequestException as e:
        logger.error(f'Failed to download root certificate list: {e}')
        return None, None
    except json.JSONDecodeError as e:
        logger.error(f'Failed to parse root certificate list JSON: {e}')
        return None, None


class RootCertificatesUpdater:
    def __init__(self):
        self._roots = None
        self._next_update = 0
        self._lock = threading.Lock()
        self._ready_event = threading.Event()
        self._stop_event = threading.Event()
        self._thread = None
        self._started = False

    def start(self):
        with self._lock:
            if not self._started:
                self._thread = threading.Thread(target=self._update_loop, daemon=True)
                self._thread.start()
                self._started = True

    def get_roots(self):
        # Lazy start of the background thread
        if not self._started:
            self.start()

        # Try to return cached data immediately
        with self._lock:
            if self._roots:
                return self._roots

        # If no data, wait for the initial download (up to 10s)
        if not self._ready_event.is_set():
            logger.info('Waiting for initial root certificate list download...')
            self._ready_event.wait(timeout=12)  # Slightly longer than request timeout

        with self._lock:
            return self._roots

    def _update_loop(self):
        logger.info('Starting root certificates updater loop')
        while not self._stop_event.is_set():
            try:
                cached_roots, expiry = _get_cached_roots()

                current_time = time.time()
                if not self._roots and cached_roots:
                    with self._lock:
                        self._roots = cached_roots
                        self._next_update = expiry or current_time + DEFAULT_CACHE_MAX_AGE_SECONDS
                    self._ready_event.set()

                should_download = False
                if not cached_roots:
                    should_download = True
                else:
                    # Refresh if close to expiration (e.g., within 1 hour)
                    if current_time > (expiry - 3600):
                        should_download = True

                if should_download:
                    logger.info('Initiating root certificate list download in background thread.')
                    new_roots, new_expiry = _download_roots()
                    if new_roots:
                        cached_roots = new_roots
                        expiry = new_expiry
                        with self._lock:
                            self._roots = cached_roots
                            self._next_update = expiry or current_time + DEFAULT_CACHE_MAX_AGE_SECONDS
                        self._ready_event.set()
                    else:
                        # Keep serving the previously fetched list (even if expired)
                        # rather than having no trust anchors at all.
                        if self._roots:
                            logger.warning('Failed to refresh root certificate list. Using the existing cached list.')
                        else:
                            logger.warning('Failed to obtain root certificate list.')

                with self._lock:
                    target_time = self._next_update

                # Wake up 1 hour before expiration to refresh
                wake_up_time = target_time - 3600
                sleep_seconds = wake_up_time - time.time()

                if sleep_seconds < 60:
                    sleep_seconds = 60  # Minimum sleep 1 minute

                logger.debug(f'Root certificates updater sleeping for {sleep_seconds} seconds')
                if self._stop_event.wait(timeout=sleep_seconds):
                    break

            except Exception as e:
                logger.error(f'Error in root certificates updater loop: {e}', exc_info=True)
                time.sleep(60)  # Retry delay on error


_updater = RootCertificatesUpdater()


def get_root_certificates() -> list[str]:
    """
    Returns the trusted attestation root certificates.

    Prefers the list fetched from ROOT_CERTIFICATES_URL (subject to
    Cache-Control). If the list has never been fetched successfully, falls
    back to the baked-in ROOT_CERTIFICATES.
    """
    roots = _updater.get_roots()
    if roots:
        return roots

    logger.warning(
        'Root certificate list has never been fetched successfully. '
        'Falling back to the baked-in list.'
    )
    return ROOT_CERTIFICATES
