import logging
import os
import time
import json
import hashlib
import re
import requests

logger = logging.getLogger(__name__)

CRL_URL = "https://android.googleapis.com/attestation/status"
CRL_CACHE_DIR = "/tmp/crl"

CRL_FILENAME_PATTERN = re.compile(r"crl-(\d+)\.json")


def _get_cached_crl():
    """
    Checks for a cached CRL file and returns its content if it's valid.
    """
    if not os.path.exists(CRL_CACHE_DIR):
        logger.info(f"CRL cache directory '{CRL_CACHE_DIR}' does not exist. Creating it.")
        os.makedirs(CRL_CACHE_DIR)
        return None

    crl_file_path = os.path.join(CRL_CACHE_DIR, "crl.json")
    if os.path.exists(crl_file_path):
        logger.info(f"Found non-expiring CRL cache file at '{crl_file_path}'.")
        with open(crl_file_path, 'r') as f:
            return json.load(f)

    current_time = int(time.time())
    for filename in os.listdir(CRL_CACHE_DIR):
        if filename.startswith("crl-") and filename.endswith(".json"):
            logger.info(f"Found potentially expiring CRL cache file: '{filename}'")
            match = CRL_FILENAME_PATTERN.match(filename)
            if match:
                expire_epoch = int(match.group(1))
                logger.info(f"File has expiration epoch: {expire_epoch}. Current epoch: {current_time}.")
                if current_time < expire_epoch:
                    logger.info("Cache is not expired. Using this file.")
                    file_path = os.path.join(CRL_CACHE_DIR, filename)
                    with open(file_path, 'r') as f:
                        return json.load(f)
                else:
                    logger.info("Cache is expired. Deleting this file.")
                    os.remove(os.path.join(CRL_CACHE_DIR, filename))
            else:
                logger.warning(f"Filename '{filename}' looks like an expiring cache file but failed to parse.")

    logger.info("No valid cached CRL found.")
    return None


def _download_crl():
    """
    Downloads the CRL from the CRL_URL.
    """
    logger.info(f"Downloading CRL from {CRL_URL}")
    try:
        response = requests.get(CRL_URL)
        response.raise_for_status()

        sha256_hash = hashlib.sha256(response.content).hexdigest()
        logger.info(f"Downloaded CRL SHA256 hash: {sha256_hash}")

        cache_control = response.headers.get("Cache-Control")
        crl_data = response.json()
        _cache_crl(crl_data, cache_control)
        return crl_data
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to download CRL: {e}")
        return None


def _cache_crl(crl_data, cache_control_header):
    """
    Caches the CRL data based on the Cache-Control header.
    """
    if not os.path.exists(CRL_CACHE_DIR):
        os.makedirs(CRL_CACHE_DIR)

    if cache_control_header:
        logger.info(f"Received Cache-Control header: '{cache_control_header}'")
        max_age_match = re.search(r"max-age=(\d+)", cache_control_header)
        if max_age_match:
            max_age_seconds = int(max_age_match.group(1))
            if max_age_seconds > 0:
                expire_epoch = int(time.time()) + max_age_seconds
                filename = f"crl-{expire_epoch}.json"
                logger.info(f"Cache-Control specifies max-age. Caching CRL with expiration at {expire_epoch} in '{filename}'.")
                with open(os.path.join(CRL_CACHE_DIR, filename), 'w') as f:
                    json.dump(crl_data, f)
                return
        if "no-store" in cache_control_header or "no-cache" in cache_control_header:
             logger.info("Cache-Control specifies no-store or no-cache. CRL will not be stored.")
             return
    # Default case or if caching is allowed indefinitely
    filename = "crl.json"
    logger.info(f"Cache-Control header not present or allows indefinite caching. Saving as '{filename}'.")
    with open(os.path.join(CRL_CACHE_DIR, filename), 'w') as f:
        json.dump(crl_data, f)


def get_crl():
    """
    Gets the CRL, either from cache or by downloading it.
    """
    crl = _get_cached_crl()
    if crl:
        return crl
    return _download_crl()


def verify_certificate_with_crl(certificate: object, crl_data: dict) -> bool:
    """
    Verifies a single certificate against the provided CRL data.
    """
    if 'entries' not in crl_data:
        logger.warning("CRL data is missing the 'entries' key. Cannot check for revocations.")
        return True # Or False, depending on strictness. Assume not revoked if CRL is malformed.

    serial_number_int = certificate.serial_number
    serial_number_hex = hex(serial_number_int).lower()

    # The Google CRL uses a hex string for the serial number, which might or might not
    # have a '0x' prefix. The `hex()` function in Python adds '0x'.
    # It's safer to handle both cases by stripping the prefix if it exists.
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
