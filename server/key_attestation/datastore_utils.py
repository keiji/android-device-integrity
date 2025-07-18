import logging
from datetime import datetime, timezone, timedelta
from google.api_core.exceptions import Conflict
# from google.cloud import datastore # Avoid direct import if client is passed

logger = logging.getLogger(__name__)

KEY_ATTESTATION_SESSION_KIND = 'KeyAttestationSignatureSession'
AGREEMENT_KEY_ATTESTATION_SESSION_KIND = 'KeyAttestationAgreementSession'
KEY_ATTESTATION_RESULT_KIND = 'KeyAttestationVerifiedPayload'
NONCE_EXPIRY_MINUTES = 10

def store_key_attestation_session(datastore_client, session_id: str, nonce_encoded: str, challenge_encoded: str):
    """
    Stores the key attestation session data in Datastore.
    The entity key will be the session_id to ensure uniqueness and allow easy lookup.
    """
    if not datastore_client:
        logger.error('Datastore client not provided. Cannot store session.')
        # This should ideally not happen if called correctly from main module
        raise ConnectionError('Datastore client not initialized or provided.')

    now = datetime.now(timezone.utc)
    expiry_datetime = now + timedelta(minutes=NONCE_EXPIRY_MINUTES)
    key = datastore_client.key(KEY_ATTESTATION_SESSION_KIND, session_id)
    entity = datastore_client.entity(key=key) # Use datastore_client.entity for new entities
    entity.update({
        'session_id': session_id,
        'nonce': nonce_encoded,
        'challenge': challenge_encoded,
        'generated_at': now,
        'expiry_datetime': expiry_datetime,
    })
    with datastore_client.transaction():
        if datastore_client.get(key):
            # Entity already exists, so this is a collision.
            # Raise a specific exception to be caught by the caller's retry loop.
            raise Conflict(f'Session ID {session_id} already exists.')
        datastore_client.put(entity)
        logger.info(f'Stored key attestation session for session_id: {session_id}')
    try:
        cleanup_expired_sessions(datastore_client, KEY_ATTESTATION_SESSION_KIND)
    except Exception as e:
        logger.error(f"Failed to cleanup expired sessions for {KEY_ATTESTATION_SESSION_KIND}: {e}")


def store_agreement_key_attestation_session(datastore_client, session_id: str, nonce_encoded: str, challenge_encoded: str, public_key_encoded: str = None, private_key_encoded: str = None):
    """
    Stores the agreement key attestation session data in Datastore.
    """
    if not datastore_client:
        logger.error('Datastore client not provided. Cannot store agreement session.')
        raise ConnectionError('Datastore client not initialized or provided.')

    now = datetime.now(timezone.utc)
    expiry_datetime = now + timedelta(minutes=NONCE_EXPIRY_MINUTES)
    key = datastore_client.key(AGREEMENT_KEY_ATTESTATION_SESSION_KIND, session_id)
    entity = datastore_client.entity(key=key)
    entity.update({
        'session_id': session_id,
        'nonce': nonce_encoded,
        'challenge': challenge_encoded,
        'generated_at': now,
        'expiry_datetime': expiry_datetime,
    })
    if public_key_encoded:
        entity['public_key'] = public_key_encoded
    if private_key_encoded: # Storing private keys needs careful consideration for security.
        entity['private_key'] = private_key_encoded

    with datastore_client.transaction():
        if datastore_client.get(key):
            raise Conflict(f'Session ID {session_id} already exists.')
        datastore_client.put(entity)
        logger.info(f'Stored agreement key attestation session for session_id: {session_id}')
    try:
        cleanup_expired_sessions(datastore_client, AGREEMENT_KEY_ATTESTATION_SESSION_KIND)
    except Exception as e:
        logger.error(f"Failed to cleanup expired sessions for {AGREEMENT_KEY_ATTESTATION_SESSION_KIND}: {e}")


def get_key_attestation_session(datastore_client, session_id: str):
    """
    Retrieves and validates key attestation session data from Datastore.
    Returns the session entity if valid and not expired, otherwise None.
    """
    if not datastore_client:
        logger.error('Datastore client not provided. Cannot retrieve session.')
        return None # Or raise error

    key = datastore_client.key(KEY_ATTESTATION_SESSION_KIND, session_id)
    try:
        entity = datastore_client.get(key)
    except Exception as e:
        logger.error(f"Failed to get session {session_id} from Datastore: {e}")
        return None


    if not entity:
        logger.warning(f'Session not found for session_id: {session_id} (Kind: {KEY_ATTESTATION_SESSION_KIND})')
        return None

    expiry_datetime = entity.get('expiry_datetime')
    if not expiry_datetime:
        logger.error(f'Session {session_id} is missing \'expiry_datetime\' timestamp.')
        return None

    if not isinstance(expiry_datetime, datetime):
        logger.error(f'Session {session_id} has invalid \'expiry_datetime\' type: {type(expiry_datetime)}.')
        return None

    # Ensure expiry_datetime is offset-aware for comparison
    if expiry_datetime.tzinfo is None:
        expiry_datetime = expiry_datetime.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > expiry_datetime:
        logger.warning(f'Session expired for session_id: {session_id}. Expired at: {expiry_datetime}')
        return None

    logger.info(f'Successfully retrieved and validated session for session_id: {session_id} (Kind: {KEY_ATTESTATION_SESSION_KIND})')
    return entity

def get_agreement_key_attestation_session(datastore_client, session_id: str):
    """
    Retrieves and validates agreement key attestation session data from Datastore.
    Returns the session entity if valid and not expired, otherwise None.
    """
    if not datastore_client:
        logger.error('Datastore client not provided. Cannot retrieve agreement session.')
        return None

    key = datastore_client.key(AGREEMENT_KEY_ATTESTATION_SESSION_KIND, session_id)
    try:
        entity = datastore_client.get(key)
    except Exception as e:
        logger.error(f"Failed to get agreement session {session_id} from Datastore: {e}")
        return None

    if not entity:
        logger.warning(f'Agreement session not found for session_id: {session_id} (Kind: {AGREEMENT_KEY_ATTESTATION_SESSION_KIND})')
        return None

    expiry_datetime = entity.get('expiry_datetime')
    if not expiry_datetime:
        logger.error(f'Agreement session {session_id} is missing \'expiry_datetime\' timestamp.')
        return None

    if not isinstance(expiry_datetime, datetime):
        logger.error(f'Agreement session {session_id} has invalid \'expiry_datetime\' type: {type(expiry_datetime)}.')
        return None

    if expiry_datetime.tzinfo is None:
        expiry_datetime = expiry_datetime.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > expiry_datetime:
        logger.warning(f'Agreement session expired for session_id: {session_id}. Expired at: {expiry_datetime}')
        return None

    logger.info(f'Successfully retrieved and validated agreement session for session_id: {session_id} (Kind: {AGREEMENT_KEY_ATTESTATION_SESSION_KIND})')
    return entity

def cleanup_expired_sessions(datastore_client, kind: str):
    """Removes expired session entities of a specific kind from Datastore."""
    if not datastore_client:
        logger.warning(f'Datastore client not provided. Skipping cleanup of expired {kind} sessions.')
        return
    try:
        query = datastore_client.query(kind=kind)
        query.add_filter('expiry_datetime', '<', datetime.now(timezone.utc))
        # Fetching only keys can be more efficient if entities are large
        query.keys_only()
        expired_entity_keys = [entity.key for entity in query.fetch()]

        if expired_entity_keys:
            datastore_client.delete_multi(expired_entity_keys)
            logger.info(f'Cleaned up {len(expired_entity_keys)} expired {kind} session entities.')
        else:
            logger.info(f'No expired {kind} session entities found to cleanup.')
    except Exception as e:
        logger.error(f'Error during Datastore cleanup of expired {kind} sessions: {e}')

def delete_key_attestation_session(datastore_client, session_id: str, kind: str):
    """Deletes a specific session entity of the given kind from Datastore."""
    if not datastore_client:
        logger.warning(f'Datastore client not provided. Cannot delete {kind} session {session_id}.')
        return # Or raise an error
    try:
        key = datastore_client.key(kind, session_id)
        datastore_client.delete(key)
        logger.info(f'Successfully deleted {kind} session for session_id: {session_id}')
    except Exception as e:
        logger.error(f'Error deleting {kind} session {session_id} from Datastore: {e}')
        # Optionally re-raise or handle more gracefully

def store_key_attestation_result(datastore_client, session_id: str, result: str, reason: str, payload_data_json_str: str, attestation_data_json_str: str, certificate_chain_b64_json_str: str):
    """Stores the key attestation verification result in Datastore."""
    if not datastore_client:
        logger.error('Datastore client not provided. Cannot store attestation result.')
        return # Or raise

    # Use session_id as the key name for the entity.
    # This assumes session_id is unique for each verification attempt that needs storing.
    # If a session_id could lead to multiple distinct results needing storage,
    # a different keying strategy (e.g., generating a unique ID for the result entity) would be needed.
    key = datastore_client.key(KEY_ATTESTATION_RESULT_KIND, session_id)
    entity = datastore_client.entity(
        key=key,
        exclude_from_indexes=['payload_data', 'attestation_data', 'certificate_chain'])
    entity.update({
        'session_id': session_id,
        'created_at': datetime.now(timezone.utc),
        'result': result,  # e.g., "verified", "failed"
        'reason': reason,  # Detailed reason for failure, or success message
        'payload_data': payload_data_json_str, # JSON string of original request payload (device_info, etc.)
        'attestation_data': attestation_data_json_str, # JSON string of parsed attestation properties
        'certificate_chain': certificate_chain_b64_json_str,
    })
    try:
        datastore_client.put(entity)
        logger.info(f'Stored key attestation result for session_id: {session_id}')
    except Exception as e:
        logger.error(f'Failed to store key attestation result for session_id {session_id}: {e}')
        # Optionally re-raise
