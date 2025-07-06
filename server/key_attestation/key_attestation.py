import base64
import os
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, Blueprint
from google.cloud import datastore
import logging

# Initialize Flask app
app = Flask(__name__)
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Datastore client
try:
    datastore_client = datastore.Client()
    logger.info("Datastore client initialized successfully.")
except Exception as e:
    logger.error(f"Failed to initialize Datastore client: {e}")
    datastore_client = None

# Datastore Kind for Key Attestation Sessions
KEY_ATTESTATION_SESSION_KIND = "KeyAttestationSession"
NONCE_EXPIRY_MINUTES = 10 # Renamed from SESSION_EXPIRY_MINUTES

# --- Helper Functions ---

def generate_random_bytes(length=32):
    """Generates cryptographically secure random bytes."""
    return os.urandom(length)

def base64url_encode(data_bytes):
    """Encodes bytes to a Base64URL string."""
    return base64.urlsafe_b64encode(data_bytes).decode('utf-8').rstrip('=')

def store_key_attestation_session(session_id, nonce_encoded, challenge_encoded):
    """
    Stores the key attestation session data in Datastore.
    The entity key will be the session_id to ensure uniqueness and allow easy lookup.
    """
    if not datastore_client:
        logger.error("Datastore client not available. Cannot store session.")
        raise ConnectionError("Datastore client not initialized.")

    now = datetime.now(timezone.utc)
    # expiry_datetime = now + timedelta(minutes=NONCE_EXPIRY_MINUTES) # Field removed

    key = datastore_client.key(KEY_ATTESTATION_SESSION_KIND, session_id)
    entity = datastore.Entity(key=key)
    entity.update({
        'session_id': session_id,
        'nonce': nonce_encoded,
        'challenge': challenge_encoded,
        'generated_at': now,
    })
    datastore_client.put(entity)
    logger.info(f"Stored key attestation session for session_id: {session_id}")
    # Consider calling cleanup_expired_sessions() here or via a scheduled job
    cleanup_expired_sessions()

def cleanup_expired_sessions():
    """Removes expired key attestation session entities from Datastore."""
    if not datastore_client:
        logger.warning("Datastore client not available. Skipping cleanup of expired sessions.")
        return

    try:
        expiry_time_check = datetime.now(timezone.utc) - timedelta(minutes=NONCE_EXPIRY_MINUTES)
        query = datastore_client.query(kind=KEY_ATTESTATION_SESSION_KIND)
        query.add_filter('generated_at', '<', expiry_time_check) # Filter by generated_at

        expired_entities = list(query.fetch())

        if expired_entities:
            keys_to_delete = [entity.key for entity in expired_entities]
            datastore_client.delete_multi(keys_to_delete)
            logger.info(f"Cleaned up {len(keys_to_delete)} expired key attestation session entities.")
        else:
            logger.info("No expired key attestation session entities found to cleanup.")
    except Exception as e:
        logger.error(f"Error during Datastore cleanup of expired key attestation sessions: {e}")

# --- Endpoints ---

@app.route('/v1/prepare', methods=['POST']) # Changed from Blueprint
def prepare_attestation():
    """
    Prepares for key attestation by generating a nonce and challenge.
    Request body: { "session_id": "string" }
    Response body: { "nonce": "string (Base64URLEncoded)", "challenge": "string (Base64URLEncoded)" }
    """
    if not datastore_client:
        logger.error("Datastore client not available for /prepare endpoint.")
        return jsonify({"error": "Datastore service not available"}), 503

    try:
        data = request.get_json()
        if not data:
            logger.warning("Prepare request missing JSON payload.")
            return jsonify({"error": "Missing JSON payload"}), 400

        session_id = data.get('session_id')
        if not session_id or not isinstance(session_id, str) or not session_id.strip():
            logger.warning(f"Prepare request with invalid session_id: {session_id}")
            return jsonify({"error": "'session_id' must be a non-empty string"}), 400

        # Generate nonce and challenge
        nonce_bytes = generate_random_bytes()
        challenge_bytes = generate_random_bytes()

        nonce_encoded = base64url_encode(nonce_bytes)
        challenge_encoded = base64url_encode(challenge_bytes)

        # Store session data in Datastore
        try:
            store_key_attestation_session(session_id, nonce_encoded, challenge_encoded)
        except ConnectionError as e: # Catch if datastore_client was None during helper call
             logger.error(f"Datastore connection error during store_key_attestation_session: {e}")
             return jsonify({"error": "Failed to store session due to datastore connectivity"}), 503
        except Exception as e:
            logger.error(f"Failed to store key attestation session for sessionId {session_id}: {e}")
            return jsonify({"error": "Failed to store session data"}), 500

        response_data = {
            "nonce": nonce_encoded,
            "challenge": challenge_encoded
        }
        logger.info(f"Successfully prepared attestation for sessionId: {session_id}")
        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error in /prepare endpoint: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500

@app.route('/v1/verify/ec', methods=['POST']) # Changed from Blueprint
def verify_ec_attestation():
    """
    Verifies the EC key attestation (mock implementation).
    Request body: { "session_id": "string", "signature": "string (Base64Encoded)", "nonce_b": "string (Base64Encoded)", "certificate_chain": ["string (Base64Encoded)"] }
    Response body: { "session_id": "string", "is_verified": false, "reason": "Mock implementation", "decoded_certificate_chain": { "mocked_detail": "This is a mock response for decoded certificate chain." }, "attestation_properties": { "mocked_software_enforced": {}, "mocked_tee_enforced": {} } }
    """
    try:
        data = request.get_json()
        if not data:
            logger.warning("Verify EC request missing JSON payload.")
            return jsonify({"error": "Missing JSON payload"}), 400

        # Validate required fields (presence only for this mock)
        session_id = data.get('session_id')
        signature = data.get('signature')
        nonce_b = data.get('nonce_b')
        certificate_chain = data.get('certificate_chain')

        if not all([session_id, signature, nonce_b, certificate_chain]):
            logger.warning(f"Verify EC request for session {session_id} missing one or more required fields.")
            return jsonify({"error": "Missing one or more required fields: session_id, signature, nonce_b, certificate_chain"}), 400

        if not isinstance(session_id, str) or \
           not isinstance(signature, str) or \
           not isinstance(nonce_b, str) or \
           not isinstance(certificate_chain, list):
            logger.warning(f"Verify EC request for session {session_id} has type mismatch for one or more fields.")
            return jsonify({"error": "Type mismatch for one or more fields."}), 400


        # Mock response
        mock_response = {
            "session_id": session_id,
            "is_verified": False,
            "reason": "Mock implementation",
            "decoded_certificate_chain": {
                "mocked_detail": "This is a mock response for decoded certificate chain."
            },
            "attestation_properties": {
                "mocked_software_enforced": {},
                "mocked_tee_enforced": {}
            }
        }
        logger.info(f"Successfully processed mock EC verification for session_id: {session_id}")
        return jsonify(mock_response), 200

    except Exception as e:
        logger.error(f"Error in /verify/ec endpoint: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500


if __name__ == '__main__':
    # This is used when running locally only.
    # When deploying to Google App Engine, a webserver process such as Gunicorn will serve the app.
    # This can be configured by adding an `entrypoint` to app.yaml.
    # The PORT environment variable is provided by App Engine.
    port = int(os.environ.get('PORT', 8081))
    app.run(host='0.0.0.0', port=port, debug=True)
