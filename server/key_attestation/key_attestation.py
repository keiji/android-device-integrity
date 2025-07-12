import os
import json
import logging
import hmac

from flask import Flask, request, jsonify
from google.cloud import datastore
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


app = Flask(__name__)
logging.basicConfig(level=logging.INFO) # Configure logging
logger = logging.getLogger(__name__)

# Initialize Datastore client
try:
    datastore_client = datastore.Client()
    logger.info('Datastore client initialized successfully.')
except Exception as e:
    logger.critical(f'Failed to initialize Datastore client: {e}', exc_info=True)
    datastore_client = None # Application might not function correctly

# --- Endpoints ---

@app.route('/v1/prepare/signature', methods=['POST'])
def prepare_signature_attestation():
    """
    Prepares for key attestation signature by generating a nonce and challenge.
    Request body: { "session_id": "string" }
    Response body: { "nonce": "string (Base64URLEncoded)", "challenge": "string (Base64URLEncoded)" }
    """
    if not datastore_client:
        logger.error('Datastore client not available for /prepare endpoint.')
        return jsonify({'error': 'Datastore service not available'}), 503

    try:
        data = request.get_json()
        if not data:
            logger.warning('Prepare request missing JSON payload.')
            return jsonify({'error': 'Missing JSON payload'}), 400

        session_id = data.get('session_id')
        if not session_id or not isinstance(session_id, str) or not session_id.strip():
            logger.warning(f'Prepare request with invalid session_id: {session_id}')
            return jsonify({'error': '\'session_id\' must be a non-empty string'}), 400

        nonce_bytes = generate_random_bytes()
        challenge_bytes = generate_random_bytes()
        nonce_encoded = base64url_encode(nonce_bytes)
        challenge_encoded = base64url_encode(challenge_bytes)

        try:
            store_key_attestation_session(datastore_client, session_id, nonce_encoded, challenge_encoded)
        except ConnectionError as e: # Catch if datastore_client was None during helper call
             logger.error(f'Datastore connection error during store_key_attestation_session: {e}')
             return jsonify({'error': 'Failed to store session due to datastore connectivity'}), 503
        except Exception as e:
            logger.error(f'Failed to store key attestation session for sessionId {session_id}: {e}')
            return jsonify({'error': 'Failed to store session data'}), 500

        response_data = {
            'nonce': nonce_encoded,
            'challenge': challenge_encoded
        }
        logger.info(f'Successfully prepared attestation for sessionId: {session_id}')
        return jsonify(response_data), 200
    except Exception as e:
        logger.error(f'Error in /prepare endpoint: {e}')
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/v1/prepare/agreement', methods=['POST'])
def prepare_agreement_attestation():
    """
    Prepares for key attestation agreement by generating a nonce and challenge.
    Request body: { "session_id": "string" }
    Response body: { "nonce": "string (Base64URLEncoded)", "challenge": "string (Base64URLEncoded)", "public_key": "string (Base64URLEncoded, optional)" }
    """
    if not datastore_client:
        logger.error('Datastore client not available for /prepare/agreement endpoint.')
        return jsonify({'error': 'Datastore service not available'}), 503

    try:
        data = request.get_json()
        if not data:
            logger.warning('Prepare agreement request missing JSON payload.')
            return jsonify({'error': 'Missing JSON payload'}), 400

        session_id = data.get('session_id')
        if not session_id or not isinstance(session_id, str) or not session_id.strip():
            logger.warning(f'Prepare agreement request with invalid session_id: {session_id}')
            return jsonify({'error': '\'session_id\' must be a non-empty string'}), 400

        nonce_bytes = generate_random_bytes()
        challenge_bytes = generate_random_bytes()
        nonce_encoded = base64url_encode(nonce_bytes)
        challenge_encoded = base64url_encode(challenge_bytes)

        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo # Standard X.509 format
        )
        public_key_encoded = base64url_encode(public_key_bytes)
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_encoded = base64url_encode(private_key_bytes)

        try:
            store_agreement_key_attestation_session(datastore_client, session_id, nonce_encoded, challenge_encoded, public_key_encoded, private_key_encoded)
        except ConnectionError as e:
             logger.error(f'Datastore connection error during store_agreement_key_attestation_session: {e}')
             return jsonify({'error': 'Failed to store session due to datastore connectivity'}), 503
        except Exception as e:
            logger.error(f'Failed to store agreement key attestation session for sessionId {session_id}: {e}')
            return jsonify({'error': 'Failed to store session data'}), 500

        response_data = {
            'nonce': nonce_encoded,
            'challenge': challenge_encoded,
            'public_key': public_key_encoded
        }
        logger.info(f'Successfully prepared agreement attestation for sessionId: {session_id}')
        return jsonify(response_data), 200
    except Exception as e:
        logger.error(f'Error in /prepare/agreement endpoint: {e}')
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/v1/verify/signature', methods=['POST'])
def verify_signature_attestation():
    """
    Verifies the Key Attestation Signature.
    Request body: { "session_id": "string", "signature": "string (Base64Encoded)", "client_nonce": "string (Base64Encoded)", "certificate_chain": ["string (Base64Encoded)"] }
    Response body: (details successful verification structure, errors are standard JSON)
    """
    try:
        data = request.get_json()
        if not data:
            logger.warning('Verify Signature request missing JSON payload.')
            store_ds_key_attestation_result(datastore_client, 'unknown_session', 'failed', 'Missing JSON payload', '{}', '{}')
            return jsonify({'error': 'Missing JSON payload'}), 400

        session_id = data.get('session_id')
        signature_b64 = data.get('signature')
        client_nonce_b64 = data.get('client_nonce')
        certificate_chain_b64 = data.get('certificate_chain')
        device_info_from_request = data.get('device_info', {})
        security_info_from_request = data.get('security_info', {})

        payload_data_for_datastore = {
            'device_info': device_info_from_request,
            'security_info': security_info_from_request
        }
        payload_data_json_str = json.dumps(payload_data_for_datastore)

        if not session_id:
            logger.warning('Verify Signature request missing session_id.')
            store_ds_key_attestation_result(datastore_client, 'missing_session_id', 'failed', 'Missing session_id in request', payload_data_json_str, '{}')
            return jsonify({'error': 'Missing \'session_id\''}), 400

        if not all([signature_b64, client_nonce_b64, certificate_chain_b64]):
            logger.warning(f'Verify Signature request for session \'{session_id}\' missing one or more required fields (signature, client_nonce, certificate_chain).')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', 'Missing one or more required fields: signature, client_nonce, certificate_chain', payload_data_json_str, '{}')
            return jsonify({'error': 'Missing one or more required fields: signature, client_nonce, certificate_chain'}), 400

        if not isinstance(session_id, str) or \
           not isinstance(signature_b64, str) or \
           not isinstance(client_nonce_b64, str) or \
           not isinstance(certificate_chain_b64, list) or \
           not all(isinstance(cert, str) for cert in certificate_chain_b64):
            logger.warning(f'Verify Signature request for session \'{session_id}\' has type mismatch for one or more fields.')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', 'Type mismatch for one or more fields.', payload_data_json_str, '{}')
            return jsonify({'error': 'Type mismatch for one or more fields. Ensure session_id, signature, client_nonce are strings and certificate_chain is a list of strings.'}), 400

        if not datastore_client:
            logger.error('Datastore client not available for /verify/signature endpoint.')
            return jsonify({'error': 'Datastore service not available'}), 503

        session_entity = get_ds_key_attestation_session(datastore_client, session_id)
        if not session_entity:
            logger.warning(f'Session ID \'{session_id}\' not found, expired, or invalid.')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', 'Session ID not found, expired, or invalid.', payload_data_json_str, '{}')
            return jsonify({'error': 'Session ID not found, expired, or invalid.'}), 403

        nonce_from_store_b64 = session_entity.get('nonce')
        challenge_from_store_b64 = session_entity.get('challenge')

        if not nonce_from_store_b64 or not challenge_from_store_b64:
            logger.error(f'Session \'{session_id}\' is missing nonce or challenge in Datastore.')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', 'Corrupted session data in Datastore.', payload_data_json_str, '{}')
            return jsonify({'error': 'Corrupted session data.'}), 500

        logger.info(f'Session validation successful for session_id: {session_id}')
        attestation_properties = None

        try:
            certificates = decode_certificate_chain(certificate_chain_b64)
            logger.info(f'Successfully decoded certificate chain for session_id: {session_id}. Chain length: {len(certificates)}')
        except ValueError as e:
            logger.warning(f'Failed to decode certificate chain for session {session_id}: {e}')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', f'Invalid certificate chain: {e}', payload_data_json_str, '{}')
            delete_ds_key_attestation_session(datastore_client, session_id, KEY_ATTESTATION_SESSION_KIND)
            return jsonify({'error': f'Invalid certificate chain: {e}'}), 400

        try:
            validate_attestation_signature(certificates[0], nonce_from_store_b64, client_nonce_b64, signature_b64)
            logger.info(f'Attestation signature validated successfully for session_id: {session_id}')
        except ValueError as e:
            logger.warning(f'Attestation signature validation failed for session {session_id}: {e}')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', f'Attestation signature validation failed: {e}', payload_data_json_str, '{}')
            delete_ds_key_attestation_session(datastore_client, session_id, KEY_ATTESTATION_SESSION_KIND)
            return jsonify({'error': f'Attestation signature validation failed: {e}'}), 400

        try:
            verify_certificate_chain(certificates)
            logger.info(f'Certificate chain verified successfully for session_id: {session_id}')
        except ValueError as e:
            logger.warning(f'Certificate chain verification failed for session {session_id}: {e}')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', f'Certificate chain verification failed: {e}', payload_data_json_str, '{}')
            delete_ds_key_attestation_session(datastore_client, session_id, KEY_ATTESTATION_SESSION_KIND)
            return jsonify({'error': f'Certificate chain verification failed: {e}'}), 400

        try:
            attestation_properties = get_attestation_extension_properties(certificates[0])
            if not attestation_properties or 'attestation_challenge' not in attestation_properties:
                logger.warning(f'Failed to parse attestation extension or missing challenge for session {session_id}.')
                sanitized_att_props = convert_bytes_to_hex_str(attestation_properties or {})
                attestation_data_json_str = json.dumps(sanitized_att_props)
                store_ds_key_attestation_result(datastore_client, session_id, 'failed', 'Failed to parse key attestation extension or attestation challenge not found.', payload_data_json_str, attestation_data_json_str)
                return jsonify({'error': 'Failed to parse key attestation extension or attestation challenge not found.'}), 400
            logger.info(f'Successfully parsed attestation extension for session_id: {session_id}. Version: {attestation_properties.get("attestation_version")}')
        except ValueError as e:
            logger.warning(f'ASN.1 parsing of attestation extension failed for session {session_id}: {e}')
            sanitized_att_props = convert_bytes_to_hex_str(attestation_properties or {})
            attestation_data_json_str = json.dumps(sanitized_att_props)
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', f'ASN.1 parsing failed: {e}', payload_data_json_str, attestation_data_json_str)
            return jsonify({'error': f'ASN.1 parsing failed: {e}'}), 400

        sanitized_att_props_for_error = convert_bytes_to_hex_str(attestation_properties or {})
        attestation_data_json_str_for_error = json.dumps(sanitized_att_props_for_error)

        try:
            challenge_from_store_bytes = base64url_decode(challenge_from_store_b64)
        except Exception as e:
            logger.error(f'Failed to base64url_decode challenge_from_store_b64 for session {session_id}: {e}')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', 'Internal server error: Could not decode stored challenge.', payload_data_json_str, attestation_data_json_str_for_error)
            return jsonify({'error': 'Internal server error: Could not decode stored challenge.'}), 500

        client_attestation_challenge_bytes = attestation_properties.get('attestation_challenge')

        if not client_attestation_challenge_bytes or \
           not hmac.compare_digest(challenge_from_store_bytes, client_attestation_challenge_bytes):
            logger.warning(f'Challenge mismatch for session {session_id}. Store (bytes_hex): \'{challenge_from_store_bytes.hex()}\', Cert (bytes_hex): \'{client_attestation_challenge_bytes.hex() if client_attestation_challenge_bytes else "None"}\'')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', 'Attestation challenge mismatch.', payload_data_json_str, attestation_data_json_str_for_error)
            delete_ds_key_attestation_session(datastore_client, session_id, KEY_ATTESTATION_SESSION_KIND)
            return jsonify({'error': 'Attestation challenge mismatch.'}), 400

        logger.info(f'Attestation challenge matched successfully for session_id: {session_id}')
        attestation_challenge_b64url = base64url_encode(client_attestation_challenge_bytes)
        software_enforced_serializable = convert_bytes_to_hex_str(attestation_properties.get('software_enforced', {}))
        hardware_enforced_from_props = attestation_properties.get('hardware_enforced')
        hardware_enforced_serializable = convert_bytes_to_hex_str(hardware_enforced_from_props if hardware_enforced_from_props is not None else {})

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
            'device_info': device_info_from_request,
            'security_info': security_info_from_request
        }

        attestation_data_for_datastore = {'attestation_info': final_response['attestation_info']}
        attestation_data_json_str_success = json.dumps(attestation_data_for_datastore)

        store_ds_key_attestation_result(datastore_client, session_id, 'verified', final_response['reason'], payload_data_json_str, attestation_data_json_str_success)
        delete_ds_key_attestation_session(datastore_client, session_id, KEY_ATTESTATION_SESSION_KIND)

        logger.info(f'Successfully verified Key Attestation Signature for session_id: {session_id}')
        return jsonify(final_response), 200
    except ValueError as e:
        current_session_id = locals().get('session_id', 'unknown_session_value_error')
        payload_str = locals().get('payload_data_json_str', '{}')
        raw_att_props = locals().get('attestation_properties') or {}
        sanitized_att_props = convert_bytes_to_hex_str(raw_att_props)
        att_props_str = json.dumps(sanitized_att_props)
        logger.warning(f'ValueError in /verify/signature for session {current_session_id}: {e}')
        store_ds_key_attestation_result(datastore_client, current_session_id, 'failed', str(e), payload_str, att_props_str)
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_session_id = locals().get('session_id', 'unknown_session_exception')
        payload_str = locals().get('payload_data_json_str', '{}')
        raw_att_props = locals().get('attestation_properties') or {}
        sanitized_att_props = convert_bytes_to_hex_str(raw_att_props)
        att_props_str = json.dumps(sanitized_att_props)
        logger.error(f'Error in /verify/signature endpoint for session {current_session_id}: {e}', exc_info=True)
        store_ds_key_attestation_result(datastore_client, current_session_id, 'failed', 'An unexpected error occurred.', payload_str, att_props_str)
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/v1/verify/agreement', methods=['POST'])
def verify_agreement_attestation():
    """
    Verifies the Key Attestation Agreement.
    Request body: {
        "session_id": "string",
        "encrypted_data": "string (Base64URL Encoded, no padding, first 12 bytes are IV)",
        "client_public_key": "string (Base64URL Encoded, DER format)",
        "salt": "string (Base64URL Encoded, no padding)",
        "certificate_chain": ["string (Base64Encoded)"],
        "device_info": {}, # Optional
        "security_info": {}  # Optional
    }
    Response body: (details successful verification structure, errors are standard JSON)
    """
    try:
        data = request.get_json()
        if not data:
            logger.warning('Verify Agreement request missing JSON payload.')
            # Minimal data for storing result if session_id is unknown at this stage
            store_ds_key_attestation_result(datastore_client, 'unknown_session_agreement', 'failed', 'Missing JSON payload for agreement', '{}', '{}')
            return jsonify({'error': 'Missing JSON payload'}), 400

        session_id = data.get('session_id')
        encrypted_param_b64url = data.get('encrypted_data') # Renamed from encrypted_data_b64url to reflect it contains IV
        client_public_key_b64url = data.get('client_public_key')
        client_salt_b64url = data.get('salt')
        certificate_chain_b64 = data.get('certificate_chain') # Added for attestation verification
        device_info_from_request = data.get('device_info', {})
        security_info_from_request = data.get('security_info', {})

        payload_data_for_datastore = {
            'device_info': device_info_from_request,
            'security_info': security_info_from_request,
            'encrypted_param_provided': bool(encrypted_param_b64url),
            'client_public_key_provided': bool(client_public_key_b64url),
            'client_salt_provided': bool(client_salt_b64url),
            'certificate_chain_provided': bool(certificate_chain_b64)
        }
        payload_data_json_str = json.dumps(payload_data_for_datastore)

        if not session_id:
            logger.warning('Verify Agreement request missing session_id.')
            store_ds_key_attestation_result(datastore_client, 'missing_session_id_agreement', 'failed', 'Missing session_id in agreement request', payload_data_json_str, '{}')
            return jsonify({'error': 'Missing \'session_id\''}), 400

        # Validate presence of all required fields
        required_fields = {
            'encrypted_data': encrypted_param_b64url,
            'client_public_key': client_public_key_b64url,
            'salt': client_salt_b64url,
            'certificate_chain': certificate_chain_b64
        }
        missing_fields = [name for name, value in required_fields.items() if not value]
        if missing_fields:
            error_msg = f"Missing one or more required fields: {', '.join(missing_fields)}"
            logger.warning(f'Verify Agreement request for session \'{session_id}\' {error_msg.lower()}.')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', error_msg + ' for agreement', payload_data_json_str, '{}')
            return jsonify({'error': error_msg}), 400

        # Type validation
        if not isinstance(session_id, str) or \
           not isinstance(encrypted_param_b64url, str) or \
           not isinstance(client_public_key_b64url, str) or \
           not isinstance(client_salt_b64url, str) or \
           not isinstance(certificate_chain_b64, list) or \
           not all(isinstance(cert, str) for cert in certificate_chain_b64):
            logger.warning(f'Verify Agreement request for session \'{session_id}\' has type mismatch.')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', 'Type mismatch in agreement request fields.', payload_data_json_str, '{}')
            return jsonify({'error': 'Type mismatch for one or more fields.'}), 400

        if not datastore_client:
            logger.error('Datastore client not available for /verify/agreement endpoint.')
            # No session_id specific logging here as it's a general service issue
            return jsonify({'error': 'Datastore service not available'}), 503

        agreement_session_entity = get_ds_agreement_key_attestation_session(datastore_client, session_id)
        if not agreement_session_entity:
            logger.warning(f'Agreement Session ID \'{session_id}\' not found, expired, or invalid.')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', 'Agreement Session ID not found, expired, or invalid.', payload_data_json_str, '{}')
            return jsonify({'error': 'Agreement Session ID not found, expired, or invalid.'}), 403

        nonce_from_store_b64url = agreement_session_entity.get('nonce')
        challenge_from_store_b64url = agreement_session_entity.get('challenge') # For attestation part
        server_private_key_pem_b64url = agreement_session_entity.get('private_key')

        if not nonce_from_store_b64url or not challenge_from_store_b64url or not server_private_key_pem_b64url:
            logger.error(f'Agreement session \'{session_id}\' is missing nonce, challenge, or private_key in Datastore.')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', 'Corrupted agreement session data in Datastore.', payload_data_json_str, '{}')
            return jsonify({'error': 'Corrupted session data.'}), 500

        attestation_properties = None # Initialize for potential error logging

        try:
            encrypted_param_bytes = base64url_decode(encrypted_param_b64url)
            if len(encrypted_param_bytes) < 12: # Check if there's enough data for IV
                logger.warning(f"Encrypted data for session '{session_id}' is too short to contain IV.")
                store_ds_key_attestation_result(datastore_client, session_id, 'failed', 'Encrypted data too short.', payload_data_json_str, '{}')
                delete_ds_key_attestation_session(datastore_client, session_id, AGREEMENT_KEY_ATTESTATION_SESSION_KIND)
                return jsonify({'error': 'Encrypted data too short.'}), 400

            iv_bytes = encrypted_param_bytes[:12]
            encrypted_nonce_bytes = encrypted_param_bytes[12:]
            client_public_key_der_bytes = base64url_decode(client_public_key_b64url)
            client_salt_bytes = base64url_decode(client_salt_b64url)
            server_private_key_pem_bytes = base64url_decode(server_private_key_pem_b64url)
            nonce_from_store_bytes = base64url_decode(nonce_from_store_b64url)
            session_id_bytes_for_aad = session_id.encode('ascii')

        except Exception as e: # Catch decoding errors
            logger.warning(f'Base64URL decoding failed for one or more parameters for session {session_id}: {e}')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', f'Invalid Base64URL encoding in request: {e}', payload_data_json_str, '{}')
            delete_ds_key_attestation_session(datastore_client, session_id, AGREEMENT_KEY_ATTESTATION_SESSION_KIND)
            return jsonify({'error': f'Invalid Base64URL encoding: {e}'}), 400

        try:
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
        except ValueError as e:
            logger.warning(f'Key derivation or decryption failed for session {session_id}: {e}')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', f'Decryption failed: {e}', payload_data_json_str, '{}')
            delete_ds_key_attestation_session(datastore_client, session_id, AGREEMENT_KEY_ATTESTATION_SESSION_KIND)
            return jsonify({'error': f'Decryption failed: {e}'}), 400

        if not hmac.compare_digest(decrypted_nonce_bytes, nonce_from_store_bytes):
            logger.warning(f'Nonce mismatch for session {session_id}. Decrypted (hex): {decrypted_nonce_bytes.hex()}, Store (hex): {nonce_from_store_bytes.hex()}')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', 'Nonce mismatch after decryption.', payload_data_json_str, '{}')
            delete_ds_key_attestation_session(datastore_client, session_id, AGREEMENT_KEY_ATTESTATION_SESSION_KIND)
            return jsonify({'error': 'Nonce mismatch.'}), 400

        logger.info(f'Nonce matched successfully for session_id: {session_id} in verify/agreement.')

        # --- Certificate Chain and Attestation Properties Verification (similar to /verify/signature) ---
        try:
            certificates = decode_certificate_chain(certificate_chain_b64)
            logger.info(f'Successfully decoded certificate chain for agreement session_id: {session_id}. Chain length: {len(certificates)}')
        except ValueError as e:
            logger.warning(f'Failed to decode certificate chain for agreement session {session_id}: {e}')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', f'Invalid certificate chain (agreement): {e}', payload_data_json_str, '{}')
            delete_ds_key_attestation_session(datastore_client, session_id, AGREEMENT_KEY_ATTESTATION_SESSION_KIND)
            return jsonify({'error': f'Invalid certificate chain: {e}'}), 400

        try:
            verify_certificate_chain(certificates)
            logger.info(f'Certificate chain verified successfully for agreement session_id: {session_id}')
        except ValueError as e:
            logger.warning(f'Certificate chain verification failed for agreement session {session_id}: {e}')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', f'Certificate chain verification failed (agreement): {e}', payload_data_json_str, '{}')
            delete_ds_key_attestation_session(datastore_client, session_id, AGREEMENT_KEY_ATTESTATION_SESSION_KIND)
            return jsonify({'error': f'Certificate chain verification failed: {e}'}), 400

        try:
            attestation_properties = get_attestation_extension_properties(certificates[0])
            if not attestation_properties or 'attestation_challenge' not in attestation_properties:
                logger.warning(f'Failed to parse attestation extension or missing challenge for agreement session {session_id}.')
                sanitized_att_props = convert_bytes_to_hex_str(attestation_properties or {})
                attestation_data_json_str = json.dumps(sanitized_att_props)
                store_ds_key_attestation_result(datastore_client, session_id, 'failed', 'Failed to parse key attestation extension or attestation challenge not found (agreement).', payload_data_json_str, attestation_data_json_str)
                delete_ds_key_attestation_session(datastore_client, session_id, AGREEMENT_KEY_ATTESTATION_SESSION_KIND)
                return jsonify({'error': 'Failed to parse key attestation extension or attestation challenge not found.'}), 400
            logger.info(f'Successfully parsed attestation extension for agreement session_id: {session_id}. Version: {attestation_properties.get("attestation_version")}')
        except ValueError as e: # Handles errors from get_attestation_extension_properties
            logger.warning(f'ASN.1 parsing of attestation extension failed for agreement session {session_id}: {e}')
            sanitized_att_props = convert_bytes_to_hex_str(attestation_properties or {}) # attestation_properties might be None or partially filled
            attestation_data_json_str = json.dumps(sanitized_att_props)
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', f'ASN.1 parsing failed (agreement): {e}', payload_data_json_str, attestation_data_json_str)
            delete_ds_key_attestation_session(datastore_client, session_id, AGREEMENT_KEY_ATTESTATION_SESSION_KIND)
            return jsonify({'error': f'ASN.1 parsing failed: {e}'}), 400

        sanitized_att_props_for_error = convert_bytes_to_hex_str(attestation_properties or {})
        attestation_data_json_str_for_error = json.dumps(sanitized_att_props_for_error)

        try:
            challenge_from_store_bytes = base64url_decode(challenge_from_store_b64url)
        except Exception as e:
            logger.error(f'Failed to base64url_decode challenge_from_store_b64url for agreement session {session_id}: {e}')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', 'Internal server error: Could not decode stored challenge (agreement).', payload_data_json_str, attestation_data_json_str_for_error)
            delete_ds_key_attestation_session(datastore_client, session_id, AGREEMENT_KEY_ATTESTATION_SESSION_KIND) # Delete session on critical internal error
            return jsonify({'error': 'Internal server error: Could not decode stored challenge.'}), 500


        client_attestation_challenge_bytes = attestation_properties.get('attestation_challenge')

        if not client_attestation_challenge_bytes or \
           not hmac.compare_digest(challenge_from_store_bytes, client_attestation_challenge_bytes):
            logger.warning(f'Challenge mismatch for agreement session {session_id}. Store (bytes_hex): \'{challenge_from_store_bytes.hex()}\', Cert (bytes_hex): \'{client_attestation_challenge_bytes.hex() if client_attestation_challenge_bytes else "None"}\'')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', 'Attestation challenge mismatch (agreement).', payload_data_json_str, attestation_data_json_str_for_error)
            delete_ds_key_attestation_session(datastore_client, session_id, AGREEMENT_KEY_ATTESTATION_SESSION_KIND)
            return jsonify({'error': 'Attestation challenge mismatch.'}), 400

        logger.info(f'Attestation challenge matched successfully for agreement session_id: {session_id}')
        attestation_challenge_b64url = base64url_encode(client_attestation_challenge_bytes) # from cert
        software_enforced_serializable = convert_bytes_to_hex_str(attestation_properties.get('software_enforced', {}))
        hardware_enforced_from_props = attestation_properties.get('hardware_enforced')
        hardware_enforced_serializable = convert_bytes_to_hex_str(hardware_enforced_from_props if hardware_enforced_from_props is not None else {})


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
            'device_info': device_info_from_request,
            'security_info': security_info_from_request
        }

        attestation_data_for_datastore = {'attestation_info': final_response['attestation_info']}
        attestation_data_json_str_success = json.dumps(attestation_data_for_datastore)

        store_ds_key_attestation_result(
            datastore_client,
            session_id,
            'verified_agreement', # Mark as agreement verification
            final_response['reason'],
            payload_data_json_str,
            attestation_data_json_str_success
        )
        delete_ds_key_attestation_session(datastore_client, session_id, AGREEMENT_KEY_ATTESTATION_SESSION_KIND)

        logger.info(f'Successfully verified Key Attestation Agreement for session_id: {session_id}')
        return jsonify(final_response), 200

    except ValueError as e: # Catch general ValueErrors not caught by specific blocks
        current_session_id = locals().get("session_id", "unknown_session_agreement_value_error")
        payload_str = locals().get("payload_data_json_str", "{}")
        # Use attestation_properties if available, otherwise empty dict for attestation_data
        raw_att_props = locals().get('attestation_properties') or {}
        sanitized_att_props = convert_bytes_to_hex_str(raw_att_props)
        att_props_str = json.dumps(sanitized_att_props)

        logger.warning(f"ValueError in /verify/agreement for session {current_session_id}: {e}", exc_info=True) # Log stack trace for ValueErrors
        store_ds_key_attestation_result(datastore_client, current_session_id, "failed", f'Agreement verification failed: {e}', payload_str, att_props_str)
        # Clean up session if it still exists and an error occurred
        if get_ds_agreement_key_attestation_session(datastore_client, current_session_id):
            delete_ds_key_attestation_session(datastore_client, current_session_id, AGREEMENT_KEY_ATTESTATION_SESSION_KIND)
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        current_session_id = locals().get("session_id", "unknown_session_agreement_exception")
        payload_str = locals().get("payload_data_json_str", "{}")
        raw_att_props = locals().get('attestation_properties') or {}
        sanitized_att_props = convert_bytes_to_hex_str(raw_att_props)
        att_props_str = json.dumps(sanitized_att_props)

        logger.error(f"Error in /verify/agreement endpoint for session {current_session_id}: {e}", exc_info=True)
        store_ds_key_attestation_result(datastore_client, current_session_id, "failed", "An unexpected error occurred during agreement verification.", payload_str, att_props_str)
        # Clean up session if it still exists and an error occurred
        if get_ds_agreement_key_attestation_session(datastore_client, current_session_id):
            delete_ds_key_attestation_session(datastore_client, current_session_id, AGREEMENT_KEY_ATTESTATION_SESSION_KIND)
        return jsonify({"error": "An unexpected error occurred"}), 500

if __name__ == '__main__':
    # This is used when running locally only.
    # When deploying to Google App Engine, a webserver process such as Gunicorn will serve the app.
    # This can be configured by adding an `entrypoint` to app.yaml.
    # The PORT environment variable is provided by App Engine.
    port = int(os.environ.get('PORT', 8081))
    app.run(host='0.0.0.0', port=port, debug=True)
