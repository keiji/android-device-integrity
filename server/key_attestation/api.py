import os
import json
import logging
import hmac
import uuid

from flask import Blueprint, request, jsonify
from google.cloud import datastore
from google.api_core.exceptions import Conflict
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Local module imports
from .attestation_parser import get_attestation_extension_properties
from .cryptographic_utils import (
    decode_certificate_chain,
    validate_attestation_signature,
    verify_certificate_chain,
    derive_shared_key,
    decrypt_data,
    extract_certificate_details,
    base64url_decode as crypto_base64url_decode # Renamed to avoid conflict if utils.base64url_decode is different
)
from .datastore_utils import (
    store_key_attestation_session,
    store_agreement_key_attestation_session,
    get_key_attestation_session as get_ds_key_attestation_session, # Renamed to avoid conflict
    get_agreement_key_attestation_session as get_ds_agreement_key_attestation_session, # Renamed
    delete_key_attestation_session as delete_ds_key_attestation_session, # Renamed
    store_key_attestation_result as store_ds_key_attestation_result, # Renamed
    KEY_ATTESTATION_SESSION_KIND, # Import kind for deletion logic
    AGREEMENT_KEY_ATTESTATION_SESSION_KIND # Import kind for deletion logic
)
from .utils import (
    generate_random_bytes,
    base64url_encode,
    base64url_decode,
    convert_bytes_to_hex_str
)


key_attestation_api = Blueprint('key_attestation_api', __name__)
logging.basicConfig(level=logging.INFO) # Configure logging
logger = logging.getLogger(__name__)

# Constants
MAX_SESSION_ID_GENERATION_ATTEMPTS = 8

# Initialize Datastore client
try:
    datastore_client = datastore.Client()
    logger.info('Datastore client initialized successfully.')
except Exception as e:
    logger.critical(f'Failed to initialize Datastore client: {e}', exc_info=True)
    datastore_client = None # Application might not function correctly

# --- Endpoints ---

@key_attestation_api.route('/v1/prepare/signature', methods=['GET'])
def prepare_signature_attestation():
    """
    Prepares for key attestation signature by generating a nonce and challenge.
    Response body: { "session_id": "string", "nonce": "string (Base64URLEncoded)", "challenge": "string (Base64URLEncoded)" }
    """
    if not datastore_client:
        logger.error('Datastore client not available for /prepare endpoint.')
        return jsonify({'error': 'Datastore service not available'}), 503

    for attempt in range(MAX_SESSION_ID_GENERATION_ATTEMPTS):
        session_id = str(uuid.uuid4())
        try:
            nonce_bytes = generate_random_bytes()
            challenge_bytes = generate_random_bytes()
            nonce_encoded = base64url_encode(nonce_bytes)
            challenge_encoded = base64url_encode(challenge_bytes)

            store_key_attestation_session(datastore_client, session_id, nonce_encoded, challenge_encoded)

            response_data = {
                'session_id': session_id,
                'nonce': nonce_encoded,
                'challenge': challenge_encoded
            }
            logger.info(f'Successfully prepared attestation for session_id: {session_id}')
            return jsonify(response_data), 200

        except ConnectionError as e:
             logger.error(f'Datastore connection error during store_key_attestation_session on attempt {attempt+1}: {e}')
             if attempt >= MAX_SESSION_ID_GENERATION_ATTEMPTS - 1:
                return jsonify({'error': 'Failed to store session due to datastore connectivity'}), 503
        except Conflict:
            logger.warning(f'Session ID {session_id} collision on attempt {attempt+1}. Retrying...')
            if attempt >= MAX_SESSION_ID_GENERATION_ATTEMPTS - 1:
                logger.error(f'Failed to generate unique session ID after {MAX_SESSION_ID_GENERATION_ATTEMPTS} attempts.')
                return jsonify({'error': 'Failed to generate unique session ID'}), 500
        except Exception as e:
            logger.error(f'An unexpected error occurred in /prepare endpoint on attempt {attempt+1} for session_id {session_id}: {e}')
            if attempt >= MAX_SESSION_ID_GENERATION_ATTEMPTS - 1:
                return jsonify({'error': 'An unexpected error occurred'}), 500

    # This part should ideally not be reached if the loop is exited correctly.
    logger.error('Exited retry loop unexpectedly in /prepare/signature.')
    return jsonify({'error': 'Failed to process request after multiple retries'}), 500

@key_attestation_api.route('/v1/prepare/agreement', methods=['GET'])
def prepare_agreement_attestation():
    """
    Prepares for key attestation agreement by generating a nonce, challenge, and a server-side key pair.
    Response body: { "session_id": "string", "nonce": "string (Base64URLEncoded)", "challenge": "string (Base64URLEncoded)", "public_key": "string (Base64URLEncoded)" }
    """
    if not datastore_client:
        logger.error('Datastore client not available for /prepare/agreement endpoint.')
        return jsonify({'error': 'Datastore service not available'}), 503

    for attempt in range(MAX_SESSION_ID_GENERATION_ATTEMPTS):
        session_id = str(uuid.uuid4())
        try:
            nonce_bytes = generate_random_bytes()
            challenge_bytes = generate_random_bytes()
            nonce_encoded = base64url_encode(nonce_bytes)
            challenge_encoded = base64url_encode(challenge_bytes)

            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            public_key_encoded = base64url_encode(public_key_bytes)
            private_key_pem_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            private_key_pem_encoded = base64url_encode(private_key_pem_bytes)

            store_agreement_key_attestation_session(
                datastore_client,
                session_id,
                nonce_encoded,
                challenge_encoded,
                public_key_encoded,
                private_key_pem_encoded
            )

            response_data = {
                'session_id': session_id,
                'nonce': nonce_encoded,
                'challenge': challenge_encoded,
                'public_key': public_key_encoded
            }
            logger.info(f'Successfully prepared agreement attestation for session_id: {session_id}')
            return jsonify(response_data), 200

        except ConnectionError as e:
            logger.error(f'Datastore connection error during store_agreement_key_attestation_session on attempt {attempt+1}: {e}')
            if attempt >= MAX_SESSION_ID_GENERATION_ATTEMPTS - 1:
                return jsonify({'error': 'Failed to store session due to datastore connectivity'}), 503
        except Conflict:
            logger.warning(f'Session ID {session_id} collision on attempt {attempt+1}. Retrying...')
            if attempt >= MAX_SESSION_ID_GENERATION_ATTEMPTS - 1:
                logger.error(f'Failed to generate unique session ID after {MAX_SESSION_ID_GENERATION_ATTEMPTS} attempts.')
                return jsonify({'error': 'Failed to generate unique session ID'}), 500
        except Exception as e:
            logger.error(f'An unexpected error occurred in /prepare/agreement endpoint on attempt {attempt+1} for session_id {session_id}: {e}')
            if attempt >= MAX_SESSION_ID_GENERATION_ATTEMPTS - 1:
                return jsonify({'error': 'An unexpected error occurred'}), 500

    logger.error('Exited retry loop unexpectedly in /prepare/agreement.')
    return jsonify({'error': 'Failed to process request after multiple retries'}), 500

def _verify_common(session_id, certificate_chain_b64, challenge_from_store_b64):
    """
    Common verification logic for both signature and agreement endpoints.
    """
    # Decode certificate chain and extract details
    try:
        certificates = decode_certificate_chain(certificate_chain_b64)
        extracted_cert_details = [extract_certificate_details(cert) for cert in certificates]
        logger.info(f'Successfully decoded certificate chain for session_id: {session_id}. Chain length: {len(certificates)}')
    except ValueError as e:
        logger.warning(f'Failed to decode certificate chain for session {session_id}: {e}')
        raise ValueError(f'Invalid certificate chain: {e}')

    # Verify certificate chain
    try:
        verify_certificate_chain(certificates)
        logger.info(f'Certificate chain verified successfully for session_id: {session_id}')
    except ValueError as e:
        logger.warning(f'Certificate chain verification failed for session {session_id}: {e}')
        raise ValueError(f'Certificate chain verification failed: {e}')

    # Parse attestation extension properties
    try:
        attestation_properties = get_attestation_extension_properties(certificates[0])
        if not attestation_properties or 'attestation_challenge' not in attestation_properties:
            logger.warning(f'Failed to parse attestation extension or missing challenge for session {session_id}.')
            raise ValueError('Failed to parse key attestation extension or attestation challenge not found.')
        logger.info(f'Successfully parsed attestation extension for session_id: {session_id}. Version: {attestation_properties.get("attestation_version")}')
    except ValueError as e:
        logger.warning(f'ASN.1 parsing of attestation extension failed for session {session_id}: {e}')
        raise ValueError(f'ASN.1 parsing failed: {e}')

    # Verify challenge
    try:
        challenge_from_store_bytes = base64url_decode(challenge_from_store_b64)
    except Exception as e:
        logger.error(f'Failed to base64url_decode challenge_from_store_b64 for session {session_id}: {e}')
        raise ValueError('Internal server error: Could not decode stored challenge.')

    client_attestation_challenge_bytes = attestation_properties.get('attestation_challenge')
    if not client_attestation_challenge_bytes or not hmac.compare_digest(challenge_from_store_bytes, client_attestation_challenge_bytes):
        logger.warning(f'Challenge mismatch for session {session_id}.')
        raise ValueError('Attestation challenge mismatch.')

    logger.info(f'Attestation challenge matched successfully for session_id: {session_id}')
    return certificates, attestation_properties, extracted_cert_details

@key_attestation_api.route('/v1/verify/signature', methods=['POST'])
def verify_signature_attestation():
    """
    Verifies the Key Attestation Signature.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Missing JSON payload'}), 400

        session_id = data.get('session_id')
        signature_b64 = data.get('signature')
        client_nonce_b64 = data.get('client_nonce')
        certificate_chain_b64 = data.get('certificate_chain')
        device_info = data.get('device_info', {})
        security_info = data.get('security_info', {})

        if not all([session_id, signature_b64, client_nonce_b64, certificate_chain_b64]):
            return jsonify({'error': 'Missing one or more required fields'}), 400

        if not datastore_client:
            return jsonify({'error': 'Datastore service not available'}), 503

        session_entity = get_ds_key_attestation_session(datastore_client, session_id)
        if not session_entity:
            return jsonify({'error': 'Session ID not found, expired, or invalid.'}), 403

        nonce_from_store_b64 = session_entity.get('nonce')
        challenge_from_store_b64 = session_entity.get('challenge')

        if not nonce_from_store_b64 or not challenge_from_store_b64:
            return jsonify({'error': 'Corrupted session data.'}), 500

        certificates, attestation_properties, extracted_cert_details = _verify_common(session_id, certificate_chain_b64, challenge_from_store_b64)

        validate_attestation_signature(certificates[0], nonce_from_store_b64, client_nonce_b64, signature_b64)

        attestation_challenge_b64url = base64url_encode(attestation_properties.get('attestation_challenge'))
        software_enforced_serializable = convert_bytes_to_hex_str(attestation_properties.get('software_enforced', {}))
        hardware_enforced_serializable = convert_bytes_to_hex_str(attestation_properties.get('hardware_enforced', {}))

        final_response = {
            'session_id': session_id,
            'is_verified': True,
            'reason': 'Key attestation verified successfully.',
            'attestation_info': {
                'attestation_version': attestation_properties.get('attestation_version'),
                'attestation_security_level': attestation_properties.get('attestation_security_level'),
                'keymint_version': attestation_properties.get('keymint_or_keymaster_version'),
                'keymint_security_level': attestation_properties.get('keymint_or_keymaster_security_level'),
                'attestation_challenge': attestation_challenge_b64url,
                'software_enforced_properties': software_enforced_serializable,
                'hardware_enforced_properties': hardware_enforced_serializable
            },
            'device_info': device_info,
            'security_info': security_info,
            'certificate_chain': extracted_cert_details
        }

        try:
            certificate_chain_b64_json_str = json.dumps(certificate_chain_b64)
            # Create a copy for storing, and remove the certificate_chain from it
            # as it is now stored in its own property.
            final_response_for_payload = final_response.copy()
            del final_response_for_payload['certificate_chain']
            payload_data_json_str = json.dumps(final_response_for_payload)
            attestation_data_json_str = json.dumps(final_response.get('attestation_info', {}))

            store_ds_key_attestation_result(
                datastore_client,
                session_id=session_id,
                result='verified',
                reason='Key attestation verified successfully.',
                payload_data_json_str=payload_data_json_str,
                attestation_data_json_str=attestation_data_json_str,
                certificate_chain_b64_json_str=certificate_chain_b64_json_str
            )
            logger.info(f'Successfully stored key attestation result for session_id: {session_id}')
        except Exception as e:
            logger.error(f'Failed to store key attestation result for session_id {session_id}: {e}', exc_info=True)
            # Decide if this should be a critical failure. For now, we'll log and continue.

        delete_ds_key_attestation_session(datastore_client, session_id, KEY_ATTESTATION_SESSION_KIND)
        return jsonify(final_response), 200

    except ValueError as e:
        # Proper logging should be done within the functions that raise the error
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f'An unexpected error occurred in /verify/signature: {e}', exc_info=True)
        return jsonify({'error': 'An unexpected error occurred'}), 500

@key_attestation_api.route('/v1/verify/agreement', methods=['POST'])
def verify_agreement_attestation():
    """
    Verifies the Key Attestation Agreement.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Missing JSON payload'}), 400

        session_id = data.get('session_id')
        encrypted_param_b64url = data.get('encrypted_data')
        client_salt_b64url = data.get('salt')
        certificate_chain_b64 = data.get('certificate_chain')
        device_info = data.get('device_info', {})
        security_info = data.get('security_info', {})

        if not all([session_id, encrypted_param_b64url, client_salt_b64url, certificate_chain_b64, device_info, security_info]):
            return jsonify({'error': 'Missing one or more required fields'}), 400

        if not datastore_client:
            return jsonify({'error': 'Datastore service not available'}), 503

        agreement_session_entity = get_ds_agreement_key_attestation_session(datastore_client, session_id)
        if not agreement_session_entity:
            return jsonify({'error': 'Agreement Session ID not found, expired, or invalid.'}), 403

        nonce_from_store_b64url = agreement_session_entity.get('nonce')
        challenge_from_store_b64url = agreement_session_entity.get('challenge')
        server_private_key_pem_b64url = agreement_session_entity.get('private_key')

        if not nonce_from_store_b64url or not challenge_from_store_b64url or not server_private_key_pem_b64url:
            return jsonify({'error': 'Corrupted session data.'}), 500

        certificates, attestation_properties, extracted_cert_details = _verify_common(session_id, certificate_chain_b64, challenge_from_store_b64url)

        encrypted_param_bytes = base64url_decode(encrypted_param_b64url)
        if len(encrypted_param_bytes) < 12:
            return jsonify({'error': 'Encrypted data too short.'}), 400
        iv_bytes = encrypted_param_bytes[:12]
        encrypted_nonce_bytes = encrypted_param_bytes[12:]
        client_public_key_der_bytes = certificates[0].public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_salt_bytes = base64url_decode(client_salt_b64url)
        server_private_key_pem_bytes = base64url_decode(server_private_key_pem_b64url)
        nonce_from_store_bytes = base64url_decode(nonce_from_store_b64url)
        session_id_bytes_for_aad = session_id.encode('ascii')

        aes_key = derive_shared_key(
            server_private_key_pem=server_private_key_pem_bytes,
            client_public_key_der=client_public_key_der_bytes,
            salt=client_salt_bytes
        )
        decrypted_nonce_bytes = decrypt_data(
            aes_key=aes_key,
            iv=iv_bytes,
            encrypted_data=encrypted_nonce_bytes,
            aad=session_id_bytes_for_aad
        )

        if not hmac.compare_digest(decrypted_nonce_bytes, nonce_from_store_bytes):
            return jsonify({'error': 'Nonce mismatch.'}), 400

        attestation_challenge_b64url = base64url_encode(attestation_properties.get('attestation_challenge'))
        software_enforced_serializable = convert_bytes_to_hex_str(attestation_properties.get('software_enforced', {}))
        hardware_enforced_serializable = convert_bytes_to_hex_str(attestation_properties.get('hardware_enforced', {}))

        final_response = {
            'session_id': session_id,
            'is_verified': True,
            'reason': 'Key agreement and attestation verified successfully.',
            'attestation_info': {
                'attestation_version': attestation_properties.get('attestation_version'),
                'attestation_security_level': attestation_properties.get('attestation_security_level'),
                'keymint_version': attestation_properties.get('keymint_or_keymaster_version'),
                'keymint_security_level': attestation_properties.get('keymint_or_keymaster_security_level'),
                'attestation_challenge': attestation_challenge_b64url,
                'software_enforced_properties': software_enforced_serializable,
                'hardware_enforced_properties': hardware_enforced_serializable
            },
            'device_info': device_info,
            'security_info': security_info,
            'certificate_chain': extracted_cert_details
        }

        try:
            certificate_chain_b64_json_str = json.dumps(certificate_chain_b64)
            # Create a copy for storing, and remove the certificate_chain from it
            # as it is now stored in its own property.
            final_response_for_payload = final_response.copy()
            del final_response_for_payload['certificate_chain']
            payload_data_json_str = json.dumps(final_response_for_payload)
            attestation_data_json_str = json.dumps(final_response.get('attestation_info', {}))
            store_ds_key_attestation_result(
                datastore_client,
                session_id=session_id,
                result='verified',
                reason='Key agreement and attestation verified successfully.',
                payload_data_json_str=payload_data_json_str,
                attestation_data_json_str=attestation_data_json_str,
                certificate_chain_b64_json_str=certificate_chain_b64_json_str
            )
            logger.info(f'Successfully stored key attestation result for session_id: {session_id}')
        except Exception as e:
            logger.error(f'Failed to store key attestation result for session_id {session_id}: {e}', exc_info=True)
            # Decide if this should be a critical failure. For now, we'll log and continue.

        delete_ds_key_attestation_session(datastore_client, session_id, AGREEMENT_KEY_ATTESTATION_SESSION_KIND)
        return jsonify(final_response), 200

    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f'An unexpected error occurred in /verify/agreement: {e}', exc_info=True)
        return jsonify({'error': 'An unexpected error occurred'}), 500

@key_attestation_api.route('/v1/revision', methods=['GET'])
def get_revision():
    """
    Returns the commit hash of the running revision.
    """
    commit_hash = os.environ.get('COMMIT_HASH', 'unknown')
    return jsonify({'revision': commit_hash})


