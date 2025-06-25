import os
import base64
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify
from google.cloud import datastore
from google.oauth2 import service_account
from googleapiclient.discovery import build
import google.auth

# Initialize Flask app
app = Flask(__name__)

# Initialize Datastore client
datastore_client = datastore.Client()

# Configuration for Play Integrity API
PLAY_INTEGRITY_PACKAGE_NAME = "dev.keiji.deviceintegrity"

# Nonce configuration
NONCE_EXPIRY_MINUTES = 10
NONCE_KIND = "NonceSession" # Datastore kind for storing nonce per session

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


@app.route('/play-integrity/classic/nonce', methods=['POST'])
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

# --- verify_integrity endpoint ---
@app.route('/play-integrity/classic/verify', methods=['POST'])
def verify_integrity():
    """
    Handles POST requests to /play-integrity/classic/verify.
    It expects a JSON payload with 'nonce' and 'token'.
    It calls the Google Play Integrity API to decode the token and verifies the nonce.
    Returns the JSON response from the Play Integrity API.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON payload"}), 400

        client_nonce = data.get('nonce')
        integrity_token = data.get('token')
        # session_id = data.get('session_id') # Optional: client could send session_id for server-side nonce validation

        if not client_nonce:
            return jsonify({"error": "Missing 'nonce' in request"}), 400
        if not integrity_token:
            return jsonify({"error": "Missing 'token' in request"}), 400

        # Optional: Server-side validation of client_nonce against Datastore using session_id
        # if session_id:
        #     key = datastore_client.key(NONCE_KIND, session_id)
        #     entity = datastore_client.get(key)
        #     if not entity:
        #         app.logger.warning(f"Session not found or nonce expired for session_id: {session_id} during verify.")
        #         return jsonify({"error": "Session not found or nonce expired"}), 400 # Consider if 400 or specific error
        #     if entity['nonce'] != client_nonce:
        #         app.logger.warning(f"Nonce mismatch for session_id: {session_id}. Client: {client_nonce}, Stored: {entity['nonce']}")
        #         return jsonify({"error": "Nonce does not match for session"}), 400
        #     if entity['expiry_datetime'] < datetime.now(timezone.utc):
        #         app.logger.warning(f"Nonce expired for session_id: {session_id}.")
        #         # Potentially delete here if expired, or let cleanup handle it
        #         return jsonify({"error": "Nonce expired for session"}), 400
        #     # If valid, proceed. Consider deleting the nonce after successful token verification by Google.
        # else:
        #     app.logger.info("No session_id provided for server-side nonce validation during verify. Proceeding with API nonce check.")
        #     pass


        credentials, project = google.auth.default(
            scopes=['https://www.googleapis.com/auth/playintegrity']
        )
        playintegrity = build('playintegrity', 'v1', credentials=credentials, cache_discovery=False)
        request_body = {'integrity_token': integrity_token}
        api_response = playintegrity.decodeIntegrityToken(
            packageName=PLAY_INTEGRITY_PACKAGE_NAME,
            body=request_body
        ).execute()

        token_payload = api_response.get('tokenPayloadExternal', {})
        request_details = token_payload.get('requestDetails', {})
        api_nonce = request_details.get('nonce')

        if not api_nonce:
            app.logger.error("Nonce not found in Play Integrity API response.")
            return jsonify({
                "error": "Nonce missing in Play Integrity API response payload",
                "play_integrity_response": api_response
            }), 500 # Or 400, as it implies an issue with the token or its processing

        if api_nonce != client_nonce:
            try:
                # Canonicalize both nonces before comparing to handle potential encoding differences (e.g. padding)
                decoded_api_nonce = base64.urlsafe_b64decode(api_nonce.encode('utf-8') + b'==') # Add padding for robust decoding
                re_encoded_api_nonce = base64.urlsafe_b64encode(decoded_api_nonce).decode('utf-8').rstrip('=')

                decoded_client_nonce = base64.urlsafe_b64decode(client_nonce.encode('utf-8') + b'==')
                re_encoded_client_nonce = base64.urlsafe_b64encode(decoded_client_nonce).decode('utf-8').rstrip('=')

                if re_encoded_api_nonce == re_encoded_client_nonce:
                    app.logger.info(f"Nonce comparison passed after canonicalization. Original API: {api_nonce}, Client: {client_nonce}")
                    pass
                else:
                    app.logger.error(f"Nonce mismatch after canonicalization. Client: {client_nonce} (canonical: {re_encoded_client_nonce}), API: {api_nonce} (canonical: {re_encoded_api_nonce})")
                    return jsonify({
                        "error": "Nonce mismatch",
                        "client_nonce": client_nonce,
                        "api_nonce": api_nonce,
                        "play_integrity_response": api_response # Include for debugging
                    }), 400
            except Exception as e:
                app.logger.error(f"Error during nonce canonicalization: {e}. Client: {client_nonce}, API: {api_nonce}")
                # Fallback to simple mismatch if canonicalization fails for some reason
                return jsonify({
                    "error": "Nonce mismatch (canonicalization failed)",
                    "client_nonce": client_nonce,
                    "api_nonce": api_nonce,
                    "play_integrity_response": api_response
                }), 400

        # If nonce matches (client_nonce vs api_nonce)
        # AND if server-side validation using session_id was done and passed:
        # Consider deleting the nonce from Datastore here to prevent reuse.
        # if session_id and 'entity' in locals() and entity: # Check if 'entity' was fetched and valid
        #    try:
        #        datastore_client.delete(key) # key would be datastore_client.key(NONCE_KIND, session_id)
        #        app.logger.info(f"Nonce for session {session_id} used and deleted from Datastore after successful verification.")
        #    except Exception as e:
        #        app.logger.error(f"Failed to delete used nonce for session {session_id} from Datastore: {e}")


        return jsonify(api_response), 200

    except google.auth.exceptions.DefaultCredentialsError as e:
        app.logger.error(f"Google Cloud Credentials error: {e}")
        return jsonify({"error": "Server authentication configuration error"}), 500
    except Exception as e:
        app.logger.error(f"Error verifying integrity token: {e}")
        return jsonify({"error": "Failed to verify integrity token"}), 500

# --- verify_integrity_standard endpoint ---
@app.route('/play-integrity/standard/verify', methods=['POST'])
def verify_integrity_standard():
    # This function requires similar nonce handling (canonicalization, optional server-side session validation)
    # as the classic verify endpoint.
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON payload"}), 400

        client_nonce = data.get('nonce')
        integrity_token = data.get('token')
        # session_id = data.get('session_id') # Optional for server-side validation

        if not integrity_token:
            return jsonify({"error": "Missing 'token' in request"}), 400
        if not client_nonce:
            return jsonify({"error": "Missing 'nonce' in request"}), 400

        # Optional: Server-side validation of client_nonce against Datastore using session_id
        # (Similar logic as in the classic verify endpoint)

        credentials, project_id = google.auth.default(
            scopes=['https://www.googleapis.com/auth/playintegrity']
        )
        playintegrity = build('playintegrity', 'v1', credentials=credentials, cache_discovery=False)
        request_body = {'integrity_token': integrity_token}
        api_response = playintegrity.decodeIntegrityToken(
            packageName=PLAY_INTEGRITY_PACKAGE_NAME,
            body=request_body
        ).execute()

        token_payload = api_response.get('tokenPayloadExternal', {})
        request_details_payload = token_payload.get('requestDetails', {})
        api_nonce = request_details_payload.get('nonce')

        if not api_nonce:
            app.logger.warning("Nonce not found in Play Integrity API response payload for standard verify.")
            return jsonify({
                "error": "Nonce missing in Play Integrity API response payload (standard)",
                "play_integrity_response": api_response
            }), 400 # Or 500

        if client_nonce and api_nonce != client_nonce:
            try:
                decoded_api_nonce = base64.urlsafe_b64decode(api_nonce.encode('utf-8') + b'==')
                re_encoded_api_nonce = base64.urlsafe_b64encode(decoded_api_nonce).decode('utf-8').rstrip('=')

                decoded_client_nonce = base64.urlsafe_b64decode(client_nonce.encode('utf-8') + b'==')
                re_encoded_client_nonce = base64.urlsafe_b64encode(decoded_client_nonce).decode('utf-8').rstrip('=')

                if re_encoded_api_nonce == re_encoded_client_nonce:
                    app.logger.info(f"Nonce mismatch (standard) resolved after canonicalization. Original API: {api_nonce}, Client: {client_nonce}")
                    pass
                else:
                    app.logger.error(f"Nonce mismatch (standard) after canonicalization. Client: {client_nonce} (canonical: {re_encoded_client_nonce}), API: {api_nonce} (canonical: {re_encoded_api_nonce})")
                    return jsonify({
                        "error": "Nonce mismatch (standard)",
                        "client_nonce": client_nonce,
                        "api_nonce": api_nonce,
                        "play_integrity_response": api_response
                    }), 400
            except Exception as e:
                app.logger.error(f"Error during nonce canonicalization (standard): {e}. Client: {client_nonce}, API: {api_nonce}")
                return jsonify({
                    "error": "Nonce mismatch (canonicalization failed, standard)",
                    "client_nonce": client_nonce,
                    "api_nonce": api_nonce,
                    "play_integrity_response": api_response
                }), 400

        # Optional: If server-side validation using session_id was done, delete nonce from Datastore.

        return jsonify(api_response), 200

    except google.auth.exceptions.DefaultCredentialsError as e:
        app.logger.error(f"Google Cloud Credentials error (standard): {e}")
        return jsonify({"error": "Server authentication configuration error (standard)"}), 500
    except Exception as e:
        app.logger.error(f"Error verifying integrity token (standard): {e}")
        return jsonify({"error": f"Failed to verify integrity token (standard): {str(e)}"}), 500


if __name__ == '__main__':
    import os
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)), debug=True)
