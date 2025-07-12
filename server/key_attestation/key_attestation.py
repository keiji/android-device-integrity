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
    Verifies the Key Attestation Agreement (mock implementation).
    Request body: {
        "session_id": "string",
        "encrypted_data": "string (Base64URL Encoded, no padding)",
        "client_public_key": "string (Base64 Encoded)",
        "salt": "string (Base64URL Encoded, no padding)", # New field
        "device_info": {},
        "security_info": {}
    }
    Response body: {
        "session_id": "string",
        "is_verified": false,
        "reason": "string"
    }
    """
    try:
        data = request.get_json()
        if not data:
            logger.warning('Verify Agreement request missing JSON payload.')
            store_ds_key_attestation_result(datastore_client, 'unknown_session_agreement', 'failed', 'Missing JSON payload for agreement', '{}', '{}')
            return jsonify({'error': 'Missing JSON payload'}), 400

        session_id = data.get('session_id')
        encrypted_data_b64url = data.get('encrypted_data')
        client_public_key_b64 = data.get('client_public_key')
        client_salt_b64url = data.get('salt')
        device_info_from_request = data.get('device_info', {})
        security_info_from_request = data.get('security_info', {})

        payload_data_for_datastore = {
            'device_info': device_info_from_request,
            'security_info': security_info_from_request,
            'encrypted_data_provided': bool(encrypted_data_b64url),
            'client_public_key_provided': bool(client_public_key_b64),
            'client_salt_provided': bool(client_salt_b64url)
        }
        payload_data_json_str = json.dumps(payload_data_for_datastore)

        if not session_id:
            logger.warning('Verify Agreement request missing session_id.')
            store_ds_key_attestation_result(datastore_client, 'missing_session_id_agreement', 'failed', 'Missing session_id in agreement request', payload_data_json_str, '{}')
            return jsonify({'error': 'Missing \'session_id\''}), 400

        # Added client_salt_b64url to the check
        if not all([encrypted_data_b64url, client_public_key_b64, client_salt_b64url]):
            logger.warning(f'Verify Agreement request for session \'{session_id}\' missing encrypted_data, client_public_key, or salt.')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', 'Missing encrypted_data, client_public_key, or salt for agreement', payload_data_json_str, '{}')
            return jsonify({'error': 'Missing \'encrypted_data\', \'client_public_key\', or \'salt\''}), 400

        if not isinstance(session_id, str) or \
           not isinstance(encrypted_data_b64url, str) or \
           not isinstance(client_public_key_b64, str) or \
           not isinstance(client_salt_b64url, str): # Added type check for client_salt_b64url
            logger.warning(f'Verify Agreement request for session \'{session_id}\' has type mismatch.')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', 'Type mismatch in agreement request fields.', payload_data_json_str, '{}')
            return jsonify({'error': 'Type mismatch for one or more fields.'}), 400

        if not datastore_client:
            logger.error('Datastore client not available for /verify/agreement endpoint.')
            return jsonify({'error': 'Datastore service not available'}), 503

        # Mock verification logic:
        # In a real scenario, you would:
        # 1. Retrieve the agreement session using session_id (get_agreement_key_attestation_session).
        #    This session contains the server's nonce (previously salt).
        # 2. Decode client_public_key_b64.
        # 3. Retrieve server's private key stored during prepare/agreement.
        # 4. Perform ECDH to derive a shared secret.
        # 5. Use the shared secret, the client_salt_b64url (from request), and server's nonce (from session)
        #    appropriately to derive a decryption key (e.g., HKDF).
        #    The client-generated 'salt' is for the HKDF. The server's 'nonce' is the data that was encrypted.
        # 6. Decode encrypted_data_b64url.
        # 7. Decrypt the data (which should be the server's nonce) using the derived key.
        # 8. Verify the decrypted data matches the server's nonce stored in the session.
        # 9. For this mock, we'll just check if the session exists and then return a mock success.
        #    The new 'salt' field is received but not used in this mock verification.

        agreement_session_entity = get_ds_agreement_key_attestation_session(datastore_client, session_id)
        if not agreement_session_entity:
            logger.warning(f'Agreement Session ID \'{session_id}\' not found, expired, or invalid for verify/agreement.')
            store_ds_key_attestation_result(datastore_client, session_id, 'failed', 'Agreement Session ID not found, expired, or invalid.', payload_data_json_str, '{}')
            return jsonify({'error': 'Agreement Session ID not found, expired, or invalid.'}), 403

        # Mocked AttestationInfo structure
        mock_attestation_info = {
            "attestation_version": 0, # Mock value
            "attestation_security_level": 0, # Mock value (e.g., TEE)
            "keymint_version": 0, # Mock value
            "keymint_security_level": 0, # Mock value
            "attestation_challenge": base64url_encode(b"mock_agreement_challenge"), # Mock challenge (remains challenge for general attestation info)
            "software_enforced_properties": {}, # Empty for mock agreement
            "hardware_enforced_properties": {}  # Empty for mock agreement
        }

        # Use device_info and security_info from request, or provide defaults
        final_device_info = device_info_from_request if device_info_from_request else {
            "brand": "MockBrand", "model": "MockModel", "device": "MockDevice", "product": "MockProduct",
            "manufacturer": "MockManufacturer", "hardware": "MockHardware", "board": "MockBoard",
            "bootloader": "MockBootloader", "version_release": "0", "sdk_int": 0,
            "fingerprint": "MockFingerprint", "security_patch": "1970-01-01"
        }
        final_security_info = security_info_from_request if security_info_from_request else {
            "is_device_lock_enabled": False, "is_biometrics_enabled": False,
            "has_class_3_authenticator": False, "has_strongbox": False
        }

        final_response = {
            "session_id": session_id,
            "is_verified": True, # Mock success
            "reason": "Key agreement verified successfully (mock).",
            "attestation_info": mock_attestation_info,
            "device_info": final_device_info,
            "security_info": final_security_info
        }

        # Storing result in Datastore
        # The attestation_data part can include the mocked attestation_info for consistency
        attestation_data_for_datastore = {
            "attestation_info": mock_attestation_info,
            "verification_type": "agreement_mock",
            "client_public_key_provided": bool(client_public_key_b64),
            "encrypted_data_provided": bool(encrypted_data_b64url)
        }
        attestation_data_json_str_success = json.dumps(attestation_data_for_datastore)

        store_ds_key_attestation_result(
            datastore_client,
            session_id,
            "verified_agreement_mock",
            final_response["reason"],
            payload_data_json_str, # Contains original device_info, security_info from request
            attestation_data_json_str_success
        )
        delete_ds_key_attestation_session(datastore_client, session_id, AGREEMENT_KEY_ATTESTATION_SESSION_KIND)

        logger.info(f'Successfully verified Key Attestation Agreement (mock) for session_id: {session_id}')
        return jsonify(final_response), 200
    except ValueError as e:
        current_session_id = locals().get("session_id", "unknown_session_agreement_value_error")
        payload_str = locals().get("payload_data_json_str", "{}")
        # Include empty attestation_info in error case if schema expects it
        att_props_str = json.dumps({"attestation_info": {}})
        logger.warning(f"ValueError in /verify/agreement for session {current_session_id}: {e}")
        store_ds_key_attestation_result(datastore_client, current_session_id, "failed", str(e), payload_str, att_props_str)
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        current_session_id = locals().get("session_id", "unknown_session_agreement_exception")
        payload_str = locals().get("payload_data_json_str", "{}")
        # Include empty attestation_info in error case if schema expects it
        att_props_str = json.dumps({"attestation_info": {}})
        logger.error(f"Error in /verify/agreement endpoint for session {current_session_id}: {e}", exc_info=True)
        store_ds_key_attestation_result(datastore_client, current_session_id, "failed", "An unexpected error occurred during agreement verification.", payload_str, att_props_str)
        return jsonify({"error": "An unexpected error occurred"}), 500

if __name__ == '__main__':
    # This is used when running locally only.
    # When deploying to Google App Engine, a webserver process such as Gunicorn will serve the app.
    # This can be configured by adding an `entrypoint` to app.yaml.
    # The PORT environment variable is provided by App Engine.
    port = int(os.environ.get('PORT', 8081))
    app.run(host='0.0.0.0', port=port, debug=True)
