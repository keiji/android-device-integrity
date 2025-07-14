import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from google.cloud import datastore

from .utils import generate_unique_id

# Configure logging
logger = logging.getLogger(__name__)

# Datastore Kind constants
NONCE_KIND = "PlayIntegrityNonce"
VERIFIED_PAYLOAD_KIND = "PlayIntegrityVerifiedPayload"

# Nonce configuration
NONCE_EXPIRY_MINUTES = 10

# Result status constants, to be shared across modules
RESULT_SUCCESS = "Success"
RESULT_FAILED = "Failed"
RESULT_ERROR = "Error"

def cleanup_expired_nonces(datastore_client: datastore.Client):
    """Removes expired nonce entities from Datastore."""
    try:
        now = datetime.now(timezone.utc)
        query = datastore_client.query(kind=NONCE_KIND)
        query.add_filter('expiry_datetime', '<', now)

        expired_keys = [entity.key for entity in query.fetch()]

        if expired_keys:
            datastore_client.delete_multi(expired_keys)
            logger.info(f"Cleaned up {len(expired_keys)} expired nonce entities from Datastore.")
        else:
            logger.info("No expired nonce entities found in Datastore to cleanup.")

    except Exception as e:
        logger.error(f"Error during Datastore cleanup of expired nonces: {e}", exc_info=True)


def generate_and_store_nonce_with_session(datastore_client: datastore.Client, session_id: str, raw_nonce: bytes) -> tuple[str, int]:
    """
    Generates a cryptographically secure nonce, associates it with a session_id,
    stores it in Datastore, and returns it.
    If an entity for the session_id already exists, it's overwritten.
    """
    import base64
    encoded_nonce = base64.urlsafe_b64encode(raw_nonce).decode('utf-8').rstrip('=')

    now = datetime.now(timezone.utc)
    generated_datetime_ms = int(now.timestamp() * 1000)
    expiry_datetime = now + timedelta(minutes=NONCE_EXPIRY_MINUTES)

    key = datastore_client.key(NONCE_KIND, session_id)
    entity = datastore.Entity(key=key)
    entity.update({
        'nonce': encoded_nonce,
        'generated_datetime': generated_datetime_ms,
        'expiry_datetime': expiry_datetime,
        'session_id': session_id
    })

    datastore_client.put(entity)
    logger.info(f"Stored/Updated nonce for session_id: {session_id}")

    cleanup_expired_nonces(datastore_client)

    return encoded_nonce, generated_datetime_ms


def get_nonce_entity(datastore_client: datastore.Client, session_id: str) -> Optional[datastore.Entity]:
    """Retrieves a nonce entity from Datastore, returning None if expired or not found."""
    key = datastore_client.key(NONCE_KIND, session_id)
    entity = datastore_client.get(key)

    if not entity:
        logger.warning(f"No nonce found for session_id: {session_id}")
        return None

    expiry_datetime = entity.get('expiry_datetime')
    if expiry_datetime and expiry_datetime < datetime.now(timezone.utc):
        logger.warning(f"Nonce for session_id: {session_id} has expired.")
        try:
            datastore_client.delete(key)
            logger.info(f"Deleted expired nonce for session_id: {session_id} during retrieval.")
        except Exception as e_del:
            logger.error(f"Failed to delete expired nonce for session_id {session_id}: {e_del}")
        return None

    return entity

def delete_nonce(datastore_client: datastore.Client, session_id: str):
    """Deletes a nonce entity from Datastore."""
    try:
        key = datastore_client.key(NONCE_KIND, session_id)
        datastore_client.delete(key)
        logger.info(f"Nonce for session_id: {session_id} used and deleted.")
    except Exception as e:
        logger.error(f"Failed to delete used nonce for session_id {session_id}: {e}", exc_info=True)


def store_verification_attempt(
    datastore_client: datastore.Client,
    session_id: str,
    client_request_data: Optional[Dict[str, Any]],
    result: str,
    verification_type: str,
    reason: Optional[str],
    api_response: Optional[Dict[str, Any]]
):
    """Stores the result of a verification attempt in Datastore."""
    try:
        generated_id = generate_unique_id()
        payload_key = datastore_client.key(VERIFIED_PAYLOAD_KIND, generated_id)
        payload_entity = datastore.Entity(key=payload_key)
        now = datetime.now(timezone.utc)

        payload_to_store = {}
        if client_request_data:
            excluded_keys = {'token', 'session_id', 'contentBinding'}
            payload_to_store = {k: v for k, v in client_request_data.items() if k not in excluded_keys}
            payload_to_store['device_info'] = client_request_data.get('device_info', {})
            payload_to_store['security_info'] = client_request_data.get('security_info', {})
            payload_to_store['google_play_developer_service_info'] = client_request_data.get('google_play_developer_service_info', {})
        else:
            payload_to_store['device_info'] = {}
            payload_to_store['security_info'] = {}
            payload_to_store['google_play_developer_service_info'] = {}

        entity_data = {
            'session_id': session_id if session_id else "UNKNOWN",
            'payload_data': payload_to_store,
            'created_at': now,
            'verification_type': verification_type,
            'result': result if result else RESULT_FAILED,
            'reason': reason,
            'api_response': api_response
        }
        payload_entity.update(entity_data)
        datastore_client.put(payload_entity)
        logger.info(f"Stored verification attempt with generated_id: {generated_id} (client session_id: {session_id}). Result: {result}.")
    except Exception as e:
        logger.critical(
            f"Failed to store verification attempt for session_id '{session_id}'. "
            f"Result: {result}. Error: {e}. Client Data: {client_request_data}. "
            f"Decoded Token: {api_response}", exc_info=True
        )
