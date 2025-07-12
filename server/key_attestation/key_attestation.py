from flask import Flask, jsonify, request
import secrets
import base64 # For potential future use

app = Flask(__name__)
app.current_nonce = None # Simplified in-memory storage for the last generated nonce

@app.route('/key-attestation/prepare/agreement', methods=['POST'])
def prepare_agreement():
    """
    Generates a nonce for the key attestation process.
    """
    try:
        nonce = secrets.token_hex(32)  # 32 bytes, hex-encoded string
        app.current_nonce = nonce  # Store the nonce
        return jsonify({"nonce": nonce}), 200
    except Exception as e:
        # Log the exception e if logging is set up
        print(f"Error during nonce generation: {e}")
        return jsonify({"error": "Internal server error during nonce generation."}), 500

@app.route('/key-attestation/verify/agreement', methods=['POST'])
def verify_agreement():
    """
    Verifies the key attestation data provided by the client.
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Invalid request: Missing or non-JSON data"}), 400

        data = request.get_json()
        if not data: # Handles cases like empty JSON {} or null
            return jsonify({"error": "Invalid request: Missing or non-JSON data"}), 400

        client_attestation_data = data.get('attestationData')
        client_salt = data.get('salt')

        if not client_attestation_data or not client_salt:
            return jsonify({"error": "Missing attestationData or salt"}), 400

        stored_nonce = getattr(app, 'current_nonce', None)

        if stored_nonce is None:
            return jsonify({"error": "Verification failed: Server nonce not available", "error_details": "Nonce not prepared or expired"}), 401

        # Placeholder for actual nonce verification against attestationData
        # In a real scenario, the nonce might be embedded in attestationData or used in a crypto operation.
        # For now, we just log that we received it and have a stored nonce.
        print(f"Received for verification: attestationData='{client_attestation_data}', client_salt='{client_salt}', stored_server_nonce='{stored_nonce}'")

        # Placeholder for actual verification logic
        # This is where client_attestation_data would be cryptographically verified
        # using the client_salt and the stored_nonce.

        # Simulate successful verification for now
        return jsonify({"status": "success", "message": "Verification placeholder - data received"}), 200

    except Exception as e:
        # Log the exception e if logging is set up
        print(f"Error during verification: {e}")
        return jsonify({"error": "Internal server error during verification."}), 500

if __name__ == '__main__':
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.
    app.run(host='127.0.0.1', port=8081, debug=True) # Port 8081 for local testing
