import os
import base64
import hashlib
import logging
from flask import Flask, request, jsonify
from google.cloud import datastore
import google.auth

from .datastore_utils import (
    generate_and_store_nonce_with_session,
    get_nonce_entity,
    delete_nonce,
    store_verification_attempt,
    RESULT_SUCCESS,
    RESULT_FAILED,
    RESULT_ERROR
)
from .integrity_api_utils import decode_integrity_token
from .utils import mask_server_url

from werkzeug.exceptions import BadRequest

# Initialize Flask app
app = Flask(__name__)

@app.errorhandler(BadRequest)
def handle_bad_request(e):
    return jsonify({"error": "Bad Request: Malformed JSON or invalid headers."}), 400

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Datastore client
try:
    datastore_client = datastore.Client()
    logger.info('Datastore client initialized successfully.')
except Exception as e:
    logger.critical(f'Failed to initialize Datastore client: {e}', exc_info=True)
    datastore_client = None

# Configuration for Play Integrity API
PLAY_INTEGRITY_PACKAGE_NAME = os.environ.get("PLAY_INTEGRITY_PACKAGE_NAME", "dev.keiji.deviceintegrity")

@app.route('/play-integrity/classic/v1/nonce', methods=['POST'])
def create_nonce_endpoint():
    """
    Generates a nonce for Play Integrity classic API requests.
    """
    if not datastore_client:
        logger.error('Datastore client not available for /nonce endpoint.')
        return jsonify({'error': 'Datastore service not available'}), 503

    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON payload"}), 400

    session_id = data.get('session_id')
    if not session_id or not isinstance(session_id, str) or not session_id.strip():
        return jsonify({"error": "'session_id' must be a non-empty string"}), 400

    try:
        raw_nonce = os.urandom(24)
        nonce, generated_datetime = generate_and_store_nonce_with_session(datastore_client, session_id, raw_nonce)

        response = {
            "nonce": nonce,
            "generated_datetime": generated_datetime
        }
        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Error in create_nonce_endpoint: {e}", exc_info=True)
        return jsonify({"error": "Failed to process nonce request"}), 500


@app.route('/play-integrity/classic/v1/verify', methods=['POST'])
def verify_integrity_classic():
    """
    Verifies a Play Integrity token using the classic (nonce-based) method.
    """
    data = request.get_json()
    session_id = data.get('session_id') if data else None

    def store_and_return(status, reason, http_code, api_response=None, client_response_override=None):
        store_verification_attempt(datastore_client, session_id, data, status, "classic", reason, api_response)
        response = client_response_override if client_response_override else {"error": reason}
        return jsonify(response), http_code

    if not datastore_client:
        return jsonify({'error': 'Datastore service not available'}), 503

    if not data:
        return store_and_return(RESULT_FAILED, "Missing JSON payload", 400)

    integrity_token = data.get('token')
    if not session_id or not isinstance(session_id, str) or not session_id.strip():
        return store_and_return(RESULT_FAILED, "'session_id' must be a non-empty string", 400)
    if not integrity_token:
        return store_and_return(RESULT_FAILED, "Missing 'token' in request", 400)

    nonce_entity = get_nonce_entity(datastore_client, session_id)
    if not nonce_entity:
        return store_and_return(RESULT_FAILED, "Invalid session_id: Session ID not found or nonce expired.", 400)

    stored_nonce = nonce_entity.get('nonce')
    if not stored_nonce:
        return store_and_return(RESULT_ERROR, "Internal server error: Failed to retrieve nonce details.", 500)

    try:
        decoded_response = decode_integrity_token(integrity_token, PLAY_INTEGRITY_PACKAGE_NAME)
    except google.auth.exceptions.DefaultCredentialsError:
        return store_and_return(RESULT_ERROR, "Server authentication configuration error", 500)
    except Exception as e:
        return store_and_return(RESULT_ERROR, "Failed to decode integrity token or process response", 500, client_response_override={"error": "Failed to decode integrity token", "details": mask_server_url(str(e))})

    token_payload = decoded_response.get('tokenPayloadExternal', {})
    request_details = token_payload.get('requestDetails', {})
    api_nonce = request_details.get('nonce')

    if not api_nonce:
        return store_and_return(RESULT_FAILED, "Nonce missing in API response.", 400, api_response=decoded_response)

    if not compare_nonces(api_nonce, stored_nonce):
        logger.error(f"Nonce mismatch for session_id: {session_id}.")
        return store_and_return(RESULT_FAILED, "Nonce mismatch.", 400, api_response=decoded_response)

    delete_nonce(datastore_client, session_id)

    response_payload = {
        "play_integrity_response": decoded_response,
        "device_info": data.get('device_info', {}),
        "security_info": data.get('security_info', {}),
        "google_play_developer_service_info": data.get('google_play_developer_service_info', {})
    }
    return store_and_return(RESULT_SUCCESS, "Verification successful", 200, api_response=decoded_response, client_response_override=response_payload)


@app.route('/play-integrity/standard/v1/verify', methods=['POST'])
def verify_integrity_standard():
    """
    Verifies a Play Integrity token using the standard (content binding) method.
    """
    data = request.get_json()
    session_id = data.get('session_id') if data else None

    def store_and_return(status, reason, http_code, api_response=None, client_response_override=None):
        store_verification_attempt(datastore_client, session_id, data, status, "standard", reason, api_response)
        response = client_response_override if client_response_override else {"error": reason}
        return jsonify(response), http_code

    if not datastore_client:
        return jsonify({'error': 'Datastore service not available'}), 503

    if not data:
        return store_and_return(RESULT_FAILED, "Missing JSON payload", 400)

    integrity_token = data.get('token')
    content_binding = data.get('contentBinding')

    if not session_id or not isinstance(session_id, str) or not session_id.strip():
        return store_and_return(RESULT_FAILED, "'session_id' must be a non-empty string", 400)
    if not integrity_token:
        return store_and_return(RESULT_FAILED, "Missing 'token' in request", 400)

    try:
        decoded_response = decode_integrity_token(integrity_token, PLAY_INTEGRITY_PACKAGE_NAME)
    except google.auth.exceptions.DefaultCredentialsError:
        return store_and_return(RESULT_ERROR, "Server authentication configuration error", 500)
    except Exception as e:
        return store_and_return(RESULT_ERROR, "Failed to decode integrity token or process response", 500, client_response_override={"error": "Failed to decode integrity token", "details": mask_server_url(str(e))})

    token_payload = decoded_response.get('tokenPayloadExternal', {})
    request_details = token_payload.get('requestDetails', {})
    api_request_hash = request_details.get('requestHash')

    if content_binding:
        string_to_hash = session_id + content_binding
        hashed_bytes = hashlib.sha256(string_to_hash.encode('utf-8')).digest()
        server_generated_hash = base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').rstrip('=')

        if not api_request_hash:
             return store_and_return(RESULT_FAILED, "requestHash missing in API response when contentBinding was provided.", 400, api_response=decoded_response)

        if server_generated_hash != api_request_hash:
            logger.error(f"Content binding hash mismatch for session_id: {session_id}.")
            return store_and_return(RESULT_FAILED, "Content binding hash mismatch.", 400, api_response=decoded_response)

    response_payload = {
        "play_integrity_response": decoded_response,
        "device_info": data.get('device_info', {}),
        "security_info": data.get('security_info', {}),
        "google_play_developer_service_info": data.get('google_play_developer_service_info', {})
    }
    return store_and_return(RESULT_SUCCESS, "Verification successful", 200, api_response=decoded_response, client_response_override=response_payload)


def compare_nonces(api_nonce: str, stored_nonce: str) -> bool:
    """
    Canonically compares two base64url encoded nonces.
    This is necessary because the base64 padding might differ.
    """
    try:
        decoded_api_nonce = base64.urlsafe_b64decode(api_nonce.encode('utf-8') + b'==')
        re_encoded_api_nonce = base64.urlsafe_b64encode(decoded_api_nonce).decode('utf-8').rstrip('=')

        decoded_stored_nonce = base64.urlsafe_b64decode(stored_nonce.encode('utf-8') + b'==')
        re_encoded_stored_nonce = base64.urlsafe_b64encode(decoded_stored_nonce).decode('utf-8').rstrip('=')

        return re_encoded_api_nonce == re_encoded_stored_nonce
    except Exception as e:
        logger.error(f"Error during nonce canonicalization: {e}. Comparing directly.", exc_info=True)
        return api_nonce == stored_nonce

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=True)
