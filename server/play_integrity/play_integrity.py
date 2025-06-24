import os
import base64
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from google.cloud import datastore
from google.oauth2 import service_account
from googleapiclient.discovery import build
import google.auth

# Initialize Flask app
# GAE expects the Flask app object to be named 'app' by default.
app = Flask(__name__)

# Initialize Datastore client
datastore_client = datastore.Client()

# Configuration for Play Integrity API
PLAY_INTEGRITY_PACKAGE_NAME = "dev.keiji.deviceintegrity"

def generate_and_store_nonce():
    """Generates a cryptographically secure nonce, stores it in Datastore, and returns it."""
    # Generate 24 cryptographically secure random bytes
    raw_nonce = os.urandom(24)

    # Base64 encode the nonce
    encoded_nonce = base64.urlsafe_b64encode(raw_nonce).decode('utf-8').rstrip('=') # Use urlsafe and remove padding

    # Get current time in epoch milliseconds
    # Using timezone.utc to ensure it's a UTC timestamp
    now = datetime.now(timezone.utc)
    generated_datetime_ms = int(now.timestamp() * 1000)

    # Create a new Datastore entity
    kind = "Nonce"
    # Create a unique name/key for the entity if needed, or let Datastore generate an ID
    # For simplicity, we'll let Datastore generate a numeric ID.
    nonce_entity = datastore.Entity(key=datastore_client.key(kind))
    nonce_entity.update({
        'nonce': encoded_nonce,
        'generated_datetime': generated_datetime_ms,
        'created_at': now # Store the full datetime object as well for easier querying/sorting if needed
    })

    # Save the entity to Datastore
    datastore_client.put(nonce_entity)

    return encoded_nonce, generated_datetime_ms

@app.route('/play-integrity/classic/nonce', methods=['POST'])
def create_nonce_endpoint():
    """
    Handles POST requests to /play-integrity/classic/nonce.
    Generates a nonce, saves it to Datastore, and returns it as JSON.
    """
    try:
        nonce, generated_datetime = generate_and_store_nonce()
        response = {
            "nonce": nonce,
            "generated_datetime": generated_datetime
        }
        return jsonify(response), 200
    except Exception as e:
        # Log the error for debugging
        # In a production app, you might want more sophisticated error handling
        app.logger.error(f"Error generating nonce: {e}")
        return jsonify({"error": "Failed to generate nonce"}), 500

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

        if not client_nonce:
            return jsonify({"error": "Missing 'nonce' in request"}), 400
        if not integrity_token:
            return jsonify({"error": "Missing 'token' in request"}), 400

        # https://developer.android.com/google/play/integrity/verdict#retrieve-interpret
        #
        # Authenticate using Application Default Credentials
        # This is the recommended approach for services running on Google Cloud.
        # Ensure the service account has the "Play Integrity API User" role.
        credentials, project = google.auth.default(
            scopes=['https://www.googleapis.com/auth/playintegrity']
        )

        playintegrity = build('playintegrity', 'v1', credentials=credentials, cache_discovery=False)

        # Call the Play Integrity API
        # https://developers.google.com/android-publisher/api-ref/rest/v3/applications.playintegrity/decodeIntegrityToken
        # The method name in the google-api-python-client might not exactly match the REST API path.
        # It's usually something like `applications().playintegrity().decodeIntegrityToken()`
        # or `playintegrity.decodeIntegrityToken()` if the service is built for playintegrity directly.
        # For this specific API (playintegrity.googleapis.com), the method structure is:
        # service.decodeIntegrityToken(packageName=..., body={integrityToken: ...})
        # The actual method provided by the client library is playintegrity.decodeIntegrityToken

        request_body = {'integrity_token': integrity_token} # Field name is integrity_token

        # Corrected API call according to typical client library structure for this API
        api_response = playintegrity.decodeIntegrityToken(
            packageName=PLAY_INTEGRITY_PACKAGE_NAME,
            body=request_body
        ).execute()


        # IMPORTANT: Verify the nonce from the API response matches the client_nonce
        # The nonce is part of the tokenPayload, which is a JSON string within the response.
        # It needs to be parsed.
        # However, the google-api-python-client might parse tokenPayload automatically
        # if the discovery document specifies it as an object.
        # Let's assume api_response['tokenPayloadExternal'] or similar holds the parsed payload.
        # The exact field name can be checked from API documentation or by inspecting a live response.
        # According to documentation: response body includes "tokenPayloadExternal"
        # which contains requestDetails.nonce

        token_payload = api_response.get('tokenPayloadExternal', {})
        request_details = token_payload.get('requestDetails', {})
        api_nonce = request_details.get('nonce')

        if not api_nonce:
            app.logger.error("Nonce not found in Play Integrity API response.")
            # Even if nonce is missing in API response, we might still want to return the API response
            # for the client to inspect, but flag an error.
            # Or, treat as a verification failure. For now, let's be strict.
            return jsonify({
                "error": "Nonce missing in Play Integrity API response payload",
                "play_integrity_response": api_response
            }), 500 # Or 400 if client should retry with a valid token

        if api_nonce != client_nonce:
            app.logger.error(f"Nonce mismatch. Client: {client_nonce}, API: {api_nonce}")
            return jsonify({
                "error": "Nonce mismatch",
                "client_nonce": client_nonce,
                "api_nonce": api_nonce,
                "play_integrity_response": api_response
            }), 400 # Bad request due to nonce mismatch

        # If nonce matches, return the full API response
        return jsonify(api_response), 200

    except google.auth.exceptions.DefaultCredentialsError as e:
        app.logger.error(f"Google Cloud Credentials error: {e}")
        return jsonify({"error": "Server authentication configuration error"}), 500
    except Exception as e:
        app.logger.error(f"Error verifying integrity token: {e}")
        # Consider what information is safe to return to the client
        return jsonify({"error": "Failed to verify integrity token"}), 500

# This is the entry point for GAE when using 'script: auto' or a gunicorn entrypoint.
# It's also useful for local development.
if __name__ == '__main__':
    # This is used when running locally. GAE runs the app via a WSGI server.
    # The host must be 0.0.0.0 to be accessible from outside the container (if running in Docker locally)
    # and GAE uses the PORT environment variable.
    import os
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)), debug=True)

# === Play Integrity Standard API Endpoint ===

@app.route('/play-integrity/standard/verify', methods=['POST'])
def verify_integrity_standard():
    """
    Handles POST requests to /play-integrity/standard/verify.
    It expects a JSON payload with 'nonce' (optional but recommended) and 'token'.
    It calls the Google Play Integrity API (Standard) to decode the token and verifies the nonce if provided.
    Returns the JSON response from the Play Integrity API.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON payload"}), 400

        # Nonce can be optional for Standard API if not used for replay protection,
        # but highly recommended. We will expect it like in the classic version.
        client_nonce = data.get('nonce')
        integrity_token = data.get('token')

        if not integrity_token:
            return jsonify({"error": "Missing 'token' in request"}), 400

        # If client_nonce is expected, enforce its presence
        if not client_nonce:
            # If we decide nonce is mandatory for our server implementation
            return jsonify({"error": "Missing 'nonce' in request"}), 400


        # Authenticate using Application Default Credentials
        credentials, project_id = google.auth.default(
            scopes=['https://www.googleapis.com/auth/playintegrity']
        )

        # The project_id obtained here is the Project ID string, not the Project Number.
        # For Standard API, the Play Integrity API documentation implies that the
        # authentication (service account) should be linked to the Cloud Project in Play Console.
        # The API endpoint itself does not take project_number as a path parameter in the client library.
        # The client library call `playintegrity.decodeIntegrityToken` should work if the
        # service account has the "Play Integrity API User" role on the correct project.

        playintegrity = build('playintegrity', 'v1', credentials=credentials, cache_discovery=False)

        request_body = {'integrity_token': integrity_token}

        # Call the Play Integrity API
        # The method is the same as for the classic API for the client library.
        # The distinction for "Standard" vs "Classic" is more about what features
        # you use from the verdict and how you interpret it, rather than a different API method.
        # However, the backend might behave differently based on project configuration
        # (e.g. if Standard Integrity is enabled and configured for the GCP project).
        api_response = playintegrity.decodeIntegrityToken(
            packageName=PLAY_INTEGRITY_PACKAGE_NAME, # This must be the package name of your app
            body=request_body
        ).execute()

        # Verify the nonce from the API response matches the client_nonce
        token_payload = api_response.get('tokenPayloadExternal', {})
        request_details_payload = token_payload.get('requestDetails', {})

        # In Standard API, the nonce might be in requestDetails.nonce or directly in requestDetails
        # For compatibility and based on typical structure, checking requestDetails.nonce
        api_nonce = request_details_payload.get('nonce')

        if not api_nonce:
            app.logger.warning("Nonce not found in Play Integrity API response payload for standard verify.")
            # Depending on policy, this could be an error or just a warning if nonce is optional.
            # Given we are requiring client_nonce, we should treat a missing api_nonce as an issue.
            return jsonify({
                "error": "Nonce missing in Play Integrity API response payload (standard)",
                "play_integrity_response": api_response
            }), 400 # Or 500 if server-side issue is suspected

        if client_nonce and api_nonce != client_nonce: # Ensure client_nonce was provided
            app.logger.error(f"Nonce mismatch (standard). Client: {client_nonce}, API: {api_nonce}")
            return jsonify({
                "error": "Nonce mismatch (standard)",
                "client_nonce": client_nonce,
                "api_nonce": api_nonce,
                "play_integrity_response": api_response
            }), 400 # Bad request due to nonce mismatch

        # If nonce matches (or if nonce was not required and not provided), return the full API response
        return jsonify(api_response), 200

    except google.auth.exceptions.DefaultCredentialsError as e:
        app.logger.error(f"Google Cloud Credentials error (standard): {e}")
        return jsonify({"error": "Server authentication configuration error (standard)"}), 500
    except Exception as e:
        app.logger.error(f"Error verifying integrity token (standard): {e}")
        return jsonify({"error": f"Failed to verify integrity token (standard): {str(e)}"}), 500
