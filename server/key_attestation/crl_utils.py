import logging
import os
import time
import json
import hashlib
import re
import requests
import threading

logger = logging.getLogger(__name__)

CRL_URL = "https://android.googleapis.com/attestation/status"
CRL_CACHE_DIR = "/tmp/crl"
CRL_FILENAME_PATTERN = re.compile(r"crl-(\d+)\.json")

def _get_cached_crl():
    """
    Checks for a cached CRL file and returns its content if it's valid.
    Returns (crl_data, expire_epoch). expire_epoch is None if indefinite.
    """
    if not os.path.exists(CRL_CACHE_DIR):
        logger.info(f"CRL cache directory '{CRL_CACHE_DIR}' does not exist. Creating it.")
        os.makedirs(CRL_CACHE_DIR, exist_ok=True)
        return None, None

    crl_file_path = os.path.join(CRL_CACHE_DIR, "crl.json")
    if os.path.exists(crl_file_path):
        logger.info(f"Found non-expiring CRL cache file at '{crl_file_path}'.")
        with open(crl_file_path, 'r') as f:
            return json.load(f), None

    current_time = int(time.time())
    for filename in os.listdir(CRL_CACHE_DIR):
        if filename.startswith("crl-") and filename.endswith(".json"):
            logger.info(f"Found potentially expiring CRL cache file: '{filename}'")
            match = CRL_FILENAME_PATTERN.match(filename)
            if match:
                expire_epoch = int(match.group(1))
                # Allow using slightly expired cache (handled by updater logic),
                # but here we just return what we find.
                logger.info(f"File has expiration epoch: {expire_epoch}. Current epoch: {current_time}.")
                # If we are strictly deleting expired files here, the updater might race.
                # Since the updater now manages the cache, we should just read the valid one.
                if current_time < expire_epoch:
                    logger.info("Cache is not expired. Using this file.")
                    file_path = os.path.join(CRL_CACHE_DIR, filename)
                    with open(file_path, 'r') as f:
                        return json.load(f), expire_epoch
                else:
                    logger.info("Cache is expired. Deleting this file.")
                    try:
                        os.remove(os.path.join(CRL_CACHE_DIR, filename))
                    except FileNotFoundError:
                        pass # Race condition handling
            else:
                logger.warning(f"Filename '{filename}' looks like an expiring cache file but failed to parse.")

    logger.info("No valid cached CRL found.")
    return None, None


def _download_crl():
    """
    Downloads the CRL from the CRL_URL.
    Returns (crl_data, expire_epoch).
    """
    logger.info(f"Downloading CRL from {CRL_URL}")
    try:
        # Added timeout to prevent indefinite blocking
        response = requests.get(CRL_URL, timeout=10)
        response.raise_for_status()

        sha256_hash = hashlib.sha256(response.content).hexdigest()
        logger.info(f"Downloaded CRL SHA256 hash: {sha256_hash}")

        cache_control = response.headers.get("Cache-Control")
        crl_data = response.json()
        expire_epoch = _cache_crl(crl_data, cache_control)
        return crl_data, expire_epoch
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to download CRL: {e}")
        return None, None


def _cache_crl(crl_data, cache_control_header):
    """
    Caches the CRL data based on the Cache-Control header.
    Returns expire_epoch or None (indefinite).
    """
    if not os.path.exists(CRL_CACHE_DIR):
        os.makedirs(CRL_CACHE_DIR, exist_ok=True)

    if cache_control_header:
        logger.info(f"Received Cache-Control header: '{cache_control_header}'")
        max_age_match = re.search(r"max-age=(\d+)", cache_control_header)
        if max_age_match:
            max_age_seconds = int(max_age_match.group(1))
            if max_age_seconds > 0:
                expire_epoch = int(time.time()) + max_age_seconds
                filename = f"crl-{expire_epoch}.json"
                logger.info(f"Cache-Control specifies max-age. Caching CRL with expiration at {expire_epoch} in '{filename}'.")

                # Write to temp file and rename for atomicity
                temp_filename = f"{filename}.tmp"
                temp_path = os.path.join(CRL_CACHE_DIR, temp_filename)
                final_path = os.path.join(CRL_CACHE_DIR, filename)

                with open(temp_path, 'w') as f:
                    json.dump(crl_data, f)
                os.rename(temp_path, final_path)

                return expire_epoch
        if "no-store" in cache_control_header or "no-cache" in cache_control_header:
             logger.info("Cache-Control specifies no-store or no-cache. CRL will not be stored.")
             return 0

    # Default case or if caching is allowed indefinitely
    filename = "crl.json"
    logger.info(f"Cache-Control header not present or allows indefinite caching. Saving as '{filename}'.")
    with open(os.path.join(CRL_CACHE_DIR, filename), 'w') as f:
        json.dump(crl_data, f)
    return None


class CrlUpdater:
    def __init__(self):
        self._crl_data = None
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

    def get_crl_data(self):
        # Lazy start of the background thread
        if not self._started:
            self.start()

        # Try to return cached data immediately
        with self._lock:
             # If we have data, return it regardless of expiration status?
             # Currently we only store valid data in _crl_data ideally.
             if self._crl_data:
                 return self._crl_data

        # If no data, wait for the initial download (up to 10s)
        if not self._ready_event.is_set():
             logger.info("Waiting for initial CRL download...")
             self._ready_event.wait(timeout=12) # Slightly longer than request timeout

        with self._lock:
             return self._crl_data

    def _update_loop(self):
        logger.info("Starting CRL updater loop")
        while not self._stop_event.is_set():
             try:
                 # Check memory/disk first
                 data, expiry = _get_cached_crl()

                 current_time = time.time()
                 should_download = False

                 if not data:
                     should_download = True
                 elif expiry:
                     # Refresh if close to expiration (e.g., within 1 hour)
                     # or if it's already expired (though _get_cached_crl deletes expired files)
                     if current_time > (expiry - 3600):
                         should_download = True

                 if should_download:
                      logger.info("Initiating CRL download in background thread.")
                      new_data, new_expiry = _download_crl()
                      if new_data:
                          data = new_data
                          expiry = new_expiry

                 if data:
                      with self._lock:
                           self._crl_data = data
                           if expiry:
                               self._next_update = expiry
                           else:
                               # Default to 24h if indefinite
                               self._next_update = current_time + 86400
                      self._ready_event.set()
                 else:
                      logger.warning("Failed to obtain CRL data.")

                 # Calculate sleep time
                 with self._lock:
                      target_time = self._next_update

                 # Wake up 1 hour before expiration to refresh
                 wake_up_time = target_time - 3600
                 sleep_seconds = wake_up_time - time.time()

                 if sleep_seconds < 60:
                      sleep_seconds = 60 # Minimum sleep 1 minute

                 logger.debug(f"CRL updater sleeping for {sleep_seconds} seconds")
                 if self._stop_event.wait(timeout=sleep_seconds):
                      break

             except Exception as e:
                 logger.error(f"Error in CRL updater loop: {e}", exc_info=True)
                 time.sleep(60) # Retry delay on error

_updater = CrlUpdater()

def get_crl():
    """
    Gets the CRL, utilizing the background updater.
    """
    return _updater.get_crl_data()


def verify_certificate_with_crl(certificate: object, crl_data: dict) -> bool:
    """
    Verifies a single certificate against the provided CRL data.
    """
    if 'entries' not in crl_data:
        logger.warning("CRL data is missing the 'entries' key. Cannot check for revocations.")
        return True

    serial_number_int = certificate.serial_number
    serial_number_hex = hex(serial_number_int).lower()

    if serial_number_hex.startswith('0x'):
        serial_number_hex = serial_number_hex[2:]

    revoked_entry = crl_data['entries'].get(serial_number_hex)

    if revoked_entry:
        status = revoked_entry.get('status')
        expires = revoked_entry.get('expires')
        reason = revoked_entry.get('reason')
        comment = revoked_entry.get('comment')
        logger.warning(
            f"Certificate with serial number {serial_number_hex} is revoked. "
            f"Status: {status}, Expires: {expires}, Reason: {reason}, Comment: {comment}"
        )
        return False
    else:
        logger.info(f"Certificate with serial number {serial_number_hex} is not in the CRL.")
        return True
