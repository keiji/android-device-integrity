import os
import base64
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify
from google.cloud import datastore
from google.oauth2 import service_account
from googleapiclient.discovery import build
import google.auth
import hashlib
import uuid

# Initialize Flask app
app = Flask(__name__)

# Initialize Datastore client
datastore_client = datastore.Client()

# Result status constants
RESULT_SUCCESS = "Success"
RESULT_FAILED = "Failed"
RESULT_ERROR = "Error"

# Configuration for Play Integrity API
PLAY_INTEGRITY_PACKAGE_NAME = "dev.keiji.deviceintegrity"

# Nonce configuration
NONCE_EXPIRY_MINUTES = 10
NONCE_KIND = "NonceSession" # Datastore kind for storing nonce per session

# Verified Payload configuration
VERIFIED_PAYLOAD_KIND = "VerifiedSessionPayload"
# This Kind stores the outcome of a Play Integrity verification attempt.
# Entity Key: generated_id (string, UUID v4) - A unique ID for each verification attempt.
# Properties:
#   - session_id (string): The session ID provided by the client. Can be "UNKNOWN" if not provided or parsing failed early.
#   - payload_data (dict): The client's request JSON, excluding sensitive keys like 'token', 'session_id', 'contentBinding'.
#                          Includes 'device_info' and 'security_info' if provided by the client.
#   - created_at (datetime): Timestamp of when this entity was created (UTC).
#   - verification_type (string): "classic" (nonce) or "standard" (requestHash).
#   - result (string): The outcome of the verification. One of RESULT_SUCCESS, RESULT_FAILED, RESULT_ERROR.
#   - api_response (dict, nullable): The JSON response from the Google Play Integrity API (decodeIntegrityToken).
#                                    This can be null if the API call failed or was not made (e.g., due to missing parameters).

import re

def mask_server_url(error_message: str) -> str:
    """
    Replaces URLs in an error message with the string "API".
    Handles http and https URLs.
    """
    if not isinstance(error_message, str):
        return str(error_message) # Ensure we work with a string

    # Regex to find URLs. It looks for http:// or https:// followed by non-whitespace characters.
    # It tries to be somewhat conservative to avoid accidentally replacing non-URL strings.
    # Common URL terminators like spaces, commas, parentheses, or end of string are considered.
    url_pattern = r'(https?://[^\s"\']+)'
    return re.sub(url_pattern, "API", error_message)

def generate_unique_id():
    """Generates a unique ID using UUID v4."""
    return str(uuid.uuid4())

def generate_and_store_nonce_with_session(session_id):
    """
    Generates a cryptographically secure nonce, associates it with a session_id,
    stores it in Datastore, and returns it.
    If an entity for the session_id already exists, it's overwritten.
    """
    raw_nonce = os.urandom(24)
    encoded_nonce = base64.urlsafe_b64encode(raw_nonce).decode('utf-8').rstrip('=')

    now = datetime.now(timezone.utc)
    generated_datetime_ms = int(now.timestamp() * 1000)
    expiry_datetime = now + timedelta(minutes=NONCE_EXPIRY_MINUTES)

    # Create or update the Datastore entity for the given session_id
    # Using session_id as the key name for the entity for easy lookup and overwrite.
    key = datastore_client.key(NONCE_KIND, session_id)
    entity = datastore.Entity(key=key)
    entity.update({
        'nonce': encoded_nonce,
        'generated_datetime': generated_datetime_ms, # Stored as integer (epoch ms)
        'expiry_datetime': expiry_datetime, # Stored as datetime object
        'session_id': session_id # Also store session_id for potential queries, though it's in the key
    })

    datastore_client.put(entity)
    app.logger.info(f"Stored/Updated nonce for session_id: {session_id}")

    # Periodically clean up expired nonces
    cleanup_expired_nonces()

    return encoded_nonce, generated_datetime_ms

def cleanup_expired_nonces():
    """Removes expired nonce entities from Datastore."""
    try:
        now = datetime.now(timezone.utc)
        query = datastore_client.query(kind=NONCE_KIND)
        query.add_filter('expiry_datetime', '<', now)

        expired_entities = list(query.fetch()) # Fetch all expired entities

        if expired_entities:
            keys_to_delete = [entity.key for entity in expired_entities]
            datastore_client.delete_multi(keys_to_delete)
            app.logger.info(f"Cleaned up {len(keys_to_delete)} expired nonce entities from Datastore.")
        else:
            app.logger.info("No expired nonce entities found in Datastore to cleanup.")

    except Exception as e:
        # Log the error, but don't let cleanup failure break the main functionality
        app.logger.error(f"Error during Datastore cleanup of expired nonces: {e}")

def _store_verification_attempt(session_id, client_request_data, result, decoded_token_response, verification_type_str):
    """
    Stores the result of a verification attempt in Datastore.
    """
    try:
        generated_id = generate_unique_id()
        payload_key = datastore_client.key(VERIFIED_PAYLOAD_KIND, generated_id)
        payload_entity = datastore.Entity(key=payload_key)
        now = datetime.now(timezone.utc)

        payload_to_store = {}
        if client_request_data: # Ensure client_request_data is not None
            # Define keys to exclude from the main part of payload_data
            # These are either sensitive, redundant, or handled separately.
            excluded_keys = {'token', 'session_id', 'contentBinding'} # contentBinding for standard

            # Copy all items from client_request_data to payload_to_store, excluding specified keys.
            payload_to_store = {k: v for k, v in client_request_data.items() if k not in excluded_keys}

            # Ensure device_info and security_info are present, defaulting to empty dicts if not.
            # This is slightly redundant if they are already in client_request_data and not excluded,
            # but ensures they are standardized.
            payload_to_store['device_info'] = client_request_data.get('device_info', {})
            payload_to_store['security_info'] = client_request_data.get('security_info', {})
            payload_to_store['google_play_developer_service_info'] = client_request_data.get('google_play_developer_service_info', {})
        else:
            # If there's no client_request_data (e.g. very early error), ensure these fields exist.
            payload_to_store['device_info'] = {}
            payload_to_store['security_info'] = {}
            payload_to_store['google_play_developer_service_info'] = {}


        entity_data = {
            'session_id': session_id if session_id else "UNKNOWN", # Handle cases where session_id might be missing
            'payload_data': payload_to_store, # Contains client data minus excluded keys
            'created_at': now,
            'verification_type': verification_type_str,
            'result': result if result else RESULT_FAILED, # Default to FAILED if not set
            'api_response': decoded_token_response # This can be None
        }
        payload_entity.update(entity_data)
        datastore_client.put(payload_entity)
        app.logger.info(f"Stored verification attempt with generated_id: {generated_id} (client session_id: {session_id}). Result: {result}. API Response included: {decoded_token_response is not None}")
    except Exception as e:
        # Log extensively if Datastore saving fails, as this is critical for audit.
        app.logger.error(f"CRITICAL: Failed to store verification attempt for session_id '{session_id}'. Result: {result}. Error: {e}. Client Data: {client_request_data}. Decoded Token: {decoded_token_response}")
        # This failure should ideally not prevent the main API from returning its response to the client.

@app.route('/play-integrity/classic/v1/nonce', methods=['POST'])
def create_nonce_endpoint():
    """
    Handles POST requests to /play-integrity/classic/nonce.
    Expects a 'session_id' in the JSON payload.
    Generates a nonce, associates it with the session_id in Datastore, and returns it.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON payload"}), 400

        session_id = data.get('session_id')
        if not session_id:
            return jsonify({"error": "Missing 'session_id' in request"}), 400
        if not isinstance(session_id, str) or not session_id.strip():
            return jsonify({"error": "'session_id' must be a non-empty string"}), 400

        nonce, generated_datetime = generate_and_store_nonce_with_session(session_id)
        response = {
            "nonce": nonce,
            "generated_datetime": generated_datetime
        }
        return jsonify(response), 200
    except Exception as e:
        app.logger.error(f"Error in create_nonce_endpoint: {e}")
        return jsonify({"error": "Failed to process nonce request"}), 500

# --- verify_integrity_classic endpoint ---
@app.route('/play-integrity/classic/v1/verify', methods=['POST'])
def verify_integrity_classic():
    """
    Handles POST requests to /play-integrity/classic/verify.
    It expects a JSON payload with 'session_id' and 'token'.
    It retrieves the nonce associated with 'session_id' from Datastore,
    calls the Google Play Integrity API to decode the token, and verifies the nonce.
    Returns the JSON response from the Play Integrity API.
    """
    data = request.get_json() # Moved data parsing to the beginning
    session_id = data.get('session_id') if data else None
    integrity_token = data.get('token') if data else None

    # Initialize variables for Datastore logging
    result_status = None
    decoded_integrity_token_response = None # Stores the response from decodeIntegrityToken
    error_message_for_client = None

    try:
        if not data:
            result_status = RESULT_FAILED
            error_message_for_client = "Missing JSON payload"
            # Log to Datastore before returning
            _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "classic")
            return jsonify({"error": error_message_for_client}), 400

        # session_id and integrity_token are critical for proceeding.
        if not session_id:
            result_status = RESULT_FAILED
            error_message_for_client = "Missing 'session_id' in request"
            _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "classic")
            return jsonify({"error": error_message_for_client}), 400
        if not isinstance(session_id, str) or not session_id.strip():
            result_status = RESULT_FAILED
            error_message_for_client = "'session_id' must be a non-empty string"
            _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "classic")
            return jsonify({"error": error_message_for_client}), 400
        if not integrity_token:
            result_status = RESULT_FAILED
            error_message_for_client = "Missing 'token' in request"
            _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "classic")
            return jsonify({"error": error_message_for_client}), 400

        # Retrieve nonce from Datastore using session_id
        key = datastore_client.key(NONCE_KIND, session_id)
        entity = datastore_client.get(key)

        if not entity:
            app.logger.warning(f"No nonce found for session_id: {session_id}")
            result_status = RESULT_FAILED
            error_message_for_client = "Invalid session_id: Session ID not found or nonce expired."
            _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "classic")
            return jsonify({"error": error_message_for_client}), 400

        stored_nonce = entity.get('nonce')
        expiry_datetime = entity.get('expiry_datetime')

        if not stored_nonce:
            app.logger.error(f"Nonce value missing in Datastore entity for session_id: {session_id}")
            result_status = RESULT_FAILED # Or ERROR depending on how critical this is
            error_message_for_client = "Internal server error: Failed to retrieve nonce details."
            _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "classic")
            return jsonify({"error": error_message_for_client}), 500

        if expiry_datetime and expiry_datetime < datetime.now(timezone.utc):
            app.logger.warning(f"Nonce for session_id: {session_id} has expired.")
            result_status = RESULT_FAILED
            error_message_for_client = "Invalid session_id: Nonce for session has expired."
            try:
                datastore_client.delete(key)
                app.logger.info(f"Deleted expired nonce for session_id: {session_id} during verification.")
            except Exception as e_del:
                app.logger.error(f"Failed to delete expired nonce for session_id {session_id}: {e_del}")
            _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "classic")
            return jsonify({"error": error_message_for_client}), 400

        # Attempt to decode the integrity token
        try:
            credentials, project = google.auth.default(
                scopes=['https://www.googleapis.com/auth/playintegrity']
            )
            playintegrity = build('playintegrity', 'v1', credentials=credentials, cache_discovery=False)
            request_body = {'integrity_token': integrity_token}
            decoded_integrity_token_response = playintegrity.v1().decodeIntegrityToken(
                packageName=PLAY_INTEGRITY_PACKAGE_NAME,
                body=request_body
            ).execute()
            # Successfully decoded, now verify nonce
            token_payload = decoded_integrity_token_response.get('tokenPayloadExternal', {})
            request_details = token_payload.get('requestDetails', {})
            api_nonce = request_details.get('nonce')

            if not api_nonce:
                app.logger.error("Nonce not found in Play Integrity API response. Full API response: %s", decoded_integrity_token_response)
                result_status = RESULT_FAILED # Or ERROR, as API response is malformed for our needs
                error_message_for_client = "Nonce missing in API response."
                # Store attempt before returning
                _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "classic")
                return jsonify({
                    "error": error_message_for_client,
                    "play_integrity_response": decoded_integrity_token_response
                }), 400 # Or 500

            # Canonicalize and compare nonces
            re_encoded_api_nonce, re_encoded_stored_nonce = None, None
            try:
                decoded_api_nonce_bytes = base64.urlsafe_b64decode(api_nonce.encode('utf-8') + b'==')
                re_encoded_api_nonce = base64.urlsafe_b64encode(decoded_api_nonce_bytes).decode('utf-8').rstrip('=')
                decoded_stored_nonce_bytes = base64.urlsafe_b64decode(stored_nonce.encode('utf-8') + b'==')
                re_encoded_stored_nonce = base64.urlsafe_b64encode(decoded_stored_nonce_bytes).decode('utf-8').rstrip('=')
            except Exception as e_nonce_canon:
                app.logger.error(f"Error during nonce canonicalization for session {session_id}: {e_nonce_canon}. API nonce: {api_nonce}, Stored nonce: {stored_nonce}")
                # Fallback to direct comparison if canonicalization fails

            final_api_nonce_to_compare = re_encoded_api_nonce if re_encoded_api_nonce else api_nonce
            final_stored_nonce_to_compare = re_encoded_stored_nonce if re_encoded_stored_nonce else stored_nonce

            if final_api_nonce_to_compare != final_stored_nonce_to_compare:
                app.logger.error(f"Nonce mismatch for session_id: {session_id}. Stored: {final_stored_nonce_to_compare}, API: {final_api_nonce_to_compare}. Full API response: {decoded_integrity_token_response}")
                result_status = RESULT_FAILED
                error_message_for_client = "Nonce mismatch."
                _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "classic")
                return jsonify({
                    "error": error_message_for_client,
                    "play_integrity_response": decoded_integrity_token_response
                }), 400

            # Nonce matches
            result_status = RESULT_SUCCESS
            try:
                datastore_client.delete(key) # Delete used nonce
                app.logger.info(f"Nonce for session_id: {session_id} used and deleted.")
            except Exception as e_del_used:
                app.logger.error(f"Failed to delete used nonce for session_id {session_id}: {e_del_used}")

        except google.auth.exceptions.DefaultCredentialsError as e_auth:
            app.logger.error(f"Google Cloud Credentials error: {e_auth}")
            result_status = RESULT_ERROR # This is a server-side configuration error
            decoded_integrity_token_response = None # No response from Play Integrity API
            error_message_for_client = "Server authentication configuration error"
            _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "classic")
            return jsonify({"error": error_message_for_client}), 500
        except Exception as e_api: # Catch other exceptions from Play Integrity API call or subsequent processing
            app.logger.error(f"Error decoding integrity token or processing its response for session {session_id}: {e_api}")
            result_status = RESULT_ERROR # Decoding failed or other unexpected error
            # decoded_integrity_token_response might be None or partially filled if error occurred after API call
            # If e_api is from .execute(), decoded_integrity_token_response would not have been set.
            error_message_for_client = "Failed to decode integrity token or process response"
            _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "classic")
            return jsonify({"error": error_message_for_client, "details": mask_server_url(str(e_api))}), 500

        # If we reach here, processing was successful or handled error with a return.
        # For success, result_status is RESULT_SUCCESS.
        _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "classic")

        response_payload = {
            "play_integrity_response": decoded_integrity_token_response,
            "device_info": data.get('device_info', {}),
            "security_info": data.get('security_info', {}),
            "google_play_developer_service_info": data.get('google_play_developer_service_info', {})
        }
        if result_status == RESULT_SUCCESS:
            return jsonify(response_payload), 200
        else:
            # This path should ideally not be reached if errors lead to earlier returns.
            # However, as a fallback, if result_status is not SUCCESS but also not an error that returned:
            app.logger.warning(f"verify_integrity_classic reached end with non-SUCCESS status '{result_status}' without prior return. Session: {session_id}")
            return jsonify({"error": error_message_for_client if error_message_for_client else "Verification failed", "play_integrity_response": decoded_integrity_token_response}), 400


    except Exception as e_global: # Catch-all for any unhandled errors in the main try block
        app.logger.error(f"Global error in verify_integrity_classic for session {session_id}: {e_global}")
        # Ensure storing an attempt even for global errors, if session_id is available
        # If session_id is None here, it means error occurred before session_id was parsed.
        _store_verification_attempt(session_id, data, RESULT_ERROR, None, "classic")
        return jsonify({"error": "An unexpected server error occurred"}), 500

# --- verify_integrity_standard endpoint ---
@app.route('/play-integrity/standard/v1/verify', methods=['POST'])
def verify_integrity_standard():
    # This function requires similar nonce handling (canonicalization, optional server-side session validation)
    # as the classic verify endpoint.
    data = request.get_json() # Moved data parsing to the beginning
    session_id = data.get('session_id') if data else None
    integrity_token = data.get('token') if data else None
    client_content_binding = data.get('contentBinding') if data else None

    # Initialize variables for Datastore logging
    result_status = None
    decoded_integrity_token_response = None # Stores the response from decodeIntegrityToken
    error_message_for_client = None

    try:
        if not data:
            result_status = RESULT_FAILED
            error_message_for_client = "Missing JSON payload"
            _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "standard")
            return jsonify({"error": error_message_for_client}), 400

        if not integrity_token:
            result_status = RESULT_FAILED
            error_message_for_client = "Missing 'token' in request"
            _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "standard")
            return jsonify({"error": error_message_for_client}), 400
        # if not client_content_binding:
        #     result_status = RESULT_FAILED
        #     error_message_for_client = "Missing 'contentBinding' in request"
        #     _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "standard")
        #     return jsonify({"error": error_message_for_client}), 400
        if not session_id:
            result_status = RESULT_FAILED
            error_message_for_client = "Missing 'session_id' in request"
            _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "standard")
            return jsonify({"error": error_message_for_client}), 400
        if not isinstance(session_id, str) or not session_id.strip():
            result_status = RESULT_FAILED
            error_message_for_client = "'session_id' must be a non-empty string"
            _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "standard")
            return jsonify({"error": error_message_for_client}), 400

        # Hash and Base64URL encode the (session_id + client_content_binding)
        server_generated_hash = None # Initialize to ensure it's defined
        if client_content_binding:
            try:
                string_to_hash = session_id + client_content_binding # Ensure session_id is part of the hash input
                hashed_bytes = hashlib.sha256(string_to_hash.encode('utf-8')).digest()
                server_generated_hash = base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').rstrip('=')
                app.logger.info(f"Server generated hash for session_id '{session_id}' and contentBinding '{client_content_binding[:50]}...' is '{server_generated_hash}' from string '{string_to_hash[:100]}...'")
            except Exception as e_hash:
                app.logger.error(f"Error hashing/encoding (session_id + contentBinding) for session_id '{session_id}': {e_hash}")
                result_status = RESULT_FAILED # Consider this a failure in preparing for verification
                error_message_for_client = "Failed to process contentBinding for hash"
                _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "standard")
                return jsonify({"error": error_message_for_client}), 500 # Internal server issue
        else:
            app.logger.info(f"No client_content_binding provided for session_id '{session_id}'. Skipping server hash generation.")

        # Attempt to decode the integrity token
        try:
            credentials, project_id = google.auth.default(
                scopes=['https://www.googleapis.com/auth/playintegrity']
            )
            playintegrity = build('playintegrity', 'v1', credentials=credentials, cache_discovery=False)
            request_body = {'integrity_token': integrity_token}
            decoded_integrity_token_response = playintegrity.v1().decodeIntegrityToken(
                packageName=PLAY_INTEGRITY_PACKAGE_NAME,
                body=request_body
            ).execute()

            token_payload = decoded_integrity_token_response.get('tokenPayloadExternal', {})
            request_details_payload = token_payload.get('requestDetails', {})
            api_request_hash = request_details_payload.get('requestHash')

            if not api_request_hash:
                if client_content_binding: # Only an error if we expected to compare it
                    app.logger.error("requestHash missing in Play Integrity API response, but client_content_binding was provided. Full response: %s", decoded_integrity_token_response)
                    result_status = RESULT_FAILED
                    error_message_for_client = "requestHash missing in API response when contentBinding was provided."
                    _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "standard")
                    return jsonify({
                        "error": error_message_for_client,
                        "play_integrity_response": decoded_integrity_token_response
                    }), 400
                else:
                    # contentBinding was not provided by client, so missing api_request_hash is expected.
                    app.logger.info("requestHash not found in Play Integrity API response, and client_content_binding was not provided. This is expected. Session ID: %s", session_id)
            # Continue to the hash comparison logic which will only run if server_generated_hash is not None (due to client_content_binding being present)
            # and api_request_hash is present (if client_content_binding was present).

            if client_content_binding and server_generated_hash != api_request_hash: # server_generated_hash will exist if client_content_binding did
                # Also, if api_request_hash was missing when client_content_binding was present, we would have returned an error above.
                # So, if we reach here and client_content_binding was provided, both hashes must be present.
                app.logger.error(f"Server contentBinding hash mismatch. Session ID: {session_id}. Server generated: {server_generated_hash}, API: {api_request_hash}. Original client contentBinding: {client_content_binding}")
                result_status = RESULT_FAILED
                error_message_for_client = "Content binding hash mismatch."
                _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "standard")
                return jsonify({
                    "error": error_message_for_client,
                    "client_provided_value_hash_debug": server_generated_hash, # For debugging, consider removing in prod
                    "api_provided_value_hash_debug": api_request_hash,     # For debugging, consider removing in prod
                    "play_integrity_response": decoded_integrity_token_response
                }), 400

            # Hash matches
            result_status = RESULT_SUCCESS

        except google.auth.exceptions.DefaultCredentialsError as e_auth:
            app.logger.error(f"Google Cloud Credentials error (standard): {e_auth}")
            result_status = RESULT_ERROR
            decoded_integrity_token_response = None
            error_message_for_client = "Server authentication configuration error (standard)"
            _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "standard")
            return jsonify({"error": error_message_for_client}), 500
        except Exception as e_api:
            app.logger.error(f"Error decoding/processing integrity token (standard) for session {session_id}: {e_api}")
            result_status = RESULT_ERROR
            error_message_for_client = "Failed to decode integrity token or process response (standard)"
            _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "standard") # decoded_integrity_token_response might be None
            return jsonify({"error": error_message_for_client, "details": str(e_api)}), 500

        # Store the attempt (Success, or Failed/Error if not returned earlier)
        _store_verification_attempt(session_id, data, result_status, decoded_integrity_token_response, "standard")

        response_payload = {
            "play_integrity_response": decoded_integrity_token_response,
            "device_info": data.get('device_info', {}),
            "security_info": data.get('security_info', {}),
            "google_play_developer_service_info": data.get('google_play_developer_service_info', {})
        }

        if result_status == RESULT_SUCCESS:
            return jsonify(response_payload), 200
        else:
            # This path should ideally not be reached if errors lead to earlier returns.
            app.logger.warning(f"verify_integrity_standard reached end with non-SUCCESS status '{result_status}' without prior return. Session: {session_id}")
            return jsonify({"error": error_message_for_client if error_message_for_client else "Verification failed (standard)", "play_integrity_response": decoded_integrity_token_response}), 400

    except Exception as e_global: # Catch-all for any unhandled errors in the main try block
        app.logger.error(f"Global error in verify_integrity_standard for session {session_id}: {e_global}")
        _store_verification_attempt(session_id, data, RESULT_ERROR, None, "standard")
        return jsonify({"error": "An unexpected server error occurred (standard)"}), 500


if __name__ == '__main__':
    import os
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)), debug=True)
