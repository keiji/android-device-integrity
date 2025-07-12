import logging
from datetime import datetime, timezone, timedelta
# from google.cloud import datastore # Avoid direct import if client is passed

logger = logging.getLogger(__name__)

KEY_ATTESTATION_SESSION_KIND = 'SignatureKeyAttestationSession'
AGREEMENT_KEY_ATTESTATION_SESSION_KIND = 'AgreementKeyAttestationSession'
KEY_ATTESTATION_RESULT_KIND = 'KeyAttestationResult'
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
    key = datastore_client.key(KEY_ATTESTATION_SESSION_KIND, session_id)
    entity = datastore_client.entity(key=key) # Use datastore_client.entity for new entities
    entity.update({
        'session_id': session_id,
        'nonce': nonce_encoded,
        'challenge': challenge_encoded,
        'generated_at': now,
    })
    try:
        datastore_client.put(entity)
        logger.info(f'Stored key attestation session for session_id: {session_id}')
        # Consider moving cleanup to a separate, scheduled task if frequent calls are an issue.
        cleanup_expired_sessions(datastore_client, KEY_ATTESTATION_SESSION_KIND)
    except Exception as e:
        logger.error(f"Failed to put key attestation session {session_id} to Datastore: {e}")
        raise # Re-raise to allow caller to handle


def store_agreement_key_attestation_session(datastore_client, session_id: str, nonce_encoded: str, challenge_encoded: str, public_key_encoded: str = None, private_key_encoded: str = None):
    """
    Stores the agreement key attestation session data in Datastore.
    """
    if not datastore_client:
        logger.error('Datastore client not provided. Cannot store agreement session.')
        raise ConnectionError('Datastore client not initialized or provided.')

    now = datetime.now(timezone.utc)
    key = datastore_client.key(AGREEMENT_KEY_ATTESTATION_SESSION_KIND, session_id)
    entity = datastore_client.entity(key=key)
    entity.update({
        'session_id': session_id,
        'nonce': nonce_encoded,
        'challenge': challenge_encoded,
        'generated_at': now,
    })
    if public_key_encoded:
        entity['public_key'] = public_key_encoded
    if private_key_encoded: # Storing private keys needs careful consideration for security.
        entity['private_key'] = private_key_encoded

    try:
        datastore_client.put(entity)
        logger.info(f'Stored agreement key attestation session for session_id: {session_id}')
        cleanup_expired_sessions(datastore_client, AGREEMENT_KEY_ATTESTATION_SESSION_KIND)
    except Exception as e:
        logger.error(f"Failed to put agreement key attestation session {session_id} to Datastore: {e}")
        raise


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

    generated_at = entity.get('generated_at')
    if not generated_at:
        logger.error(f'Session {session_id} is missing \'generated_at\' timestamp.')
        return None # Data integrity issue

    if not isinstance(generated_at, datetime):
         logger.error(f'Session {session_id} has invalid \'generated_at\' type: {type(generated_at)}.')
         # Attempt to parse if it's a string, or handle as error. For now, treat as error.
         return None


    # Ensure generated_at is offset-aware for comparison
    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=timezone.utc)

    expiry_datetime = generated_at + timedelta(minutes=NONCE_EXPIRY_MINUTES)
    if datetime.now(timezone.utc) > expiry_datetime:
        logger.warning(f'Session expired for session_id: {session_id}. Generated at: {generated_at}, Expired at: {expiry_datetime}')
        # Optionally delete the expired entity here or rely on cleanup_expired_sessions
        # delete_key_attestation_session(datastore_client, session_id, KEY_ATTESTATION_SESSION_KIND) # if we want immediate deletion
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

    generated_at = entity.get('generated_at')
    if not generated_at:
        logger.error(f'Agreement session {session_id} is missing \'generated_at\' timestamp.')
        return None

    if not isinstance(generated_at, datetime):
         logger.error(f'Agreement session {session_id} has invalid \'generated_at\' type: {type(generated_at)}.')
         return None

    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=timezone.utc)

    expiry_datetime = generated_at + timedelta(minutes=NONCE_EXPIRY_MINUTES)
    if datetime.now(timezone.utc) > expiry_datetime:
        logger.warning(f'Agreement session expired for session_id: {session_id}. Generated at: {generated_at}, Expired at: {expiry_datetime}')
        # delete_key_attestation_session(datastore_client, session_id, AGREEMENT_KEY_ATTESTATION_SESSION_KIND)
        return None

    logger.info(f'Successfully retrieved and validated agreement session for session_id: {session_id} (Kind: {AGREEMENT_KEY_ATTESTATION_SESSION_KIND})')
    return entity

def cleanup_expired_sessions(datastore_client, kind: str):
    """Removes expired session entities of a specific kind from Datastore."""
    if not datastore_client:
        logger.warning(f'Datastore client not provided. Skipping cleanup of expired {kind} sessions.')
        return
    try:
        # Ensure NONCE_EXPIRY_MINUTES is positive to avoid issues with timedelta
        if NONCE_EXPIRY_MINUTES <= 0:
            logger.warning(f"NONCE_EXPIRY_MINUTES ({NONCE_EXPIRY_MINUTES}) is not positive. Skipping cleanup for kind {kind}.")
            return

        expiry_time_check = datetime.now(timezone.utc) - timedelta(minutes=NONCE_EXPIRY_MINUTES)
        query = datastore_client.query(kind=kind)
        query.add_filter('generated_at', '<', expiry_time_check)
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

def store_key_attestation_result(datastore_client, session_id: str, result: str, reason: str, payload_data_json_str: str, attestation_data_json_str: str):
    """Stores the key attestation verification result in Datastore."""
    if not datastore_client:
        logger.error('Datastore client not provided. Cannot store attestation result.')
        return # Or raise

    # Use session_id as the key name for the entity.
    # This assumes session_id is unique for each verification attempt that needs storing.
    # If a session_id could lead to multiple distinct results needing storage,
    # a different keying strategy (e.g., generating a unique ID for the result entity) would be needed.
    key = datastore_client.key(KEY_ATTESTATION_RESULT_KIND, session_id)
    entity = datastore_client.entity(key=key)
    entity.update({
        'session_id': session_id,
        'created_at': datetime.now(timezone.utc),
        'result': result,  # e.g., "verified", "failed"
        'reason': reason,  # Detailed reason for failure, or success message
        'payload_data': payload_data_json_str, # JSON string of original request payload (device_info, etc.)
        'attestation_data': attestation_data_json_str # JSON string of parsed attestation properties
    })
    try:
        datastore_client.put(entity)
        logger.info(f'Stored key attestation result for session_id: {session_id}')
    except Exception as e:
        logger.error(f'Failed to store key attestation result for session_id {session_id}: {e}')
        # Optionally re-raise
