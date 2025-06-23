import os
import base64
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from google.cloud import datastore

# Initialize Flask app
# GAE expects the Flask app object to be named 'app' by default.
app = Flask(__name__)

# Initialize Datastore client
datastore_client = datastore.Client()

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
    For now, it just returns a simple string.
    """
    # In a real application, you would:
    # 1. Get the integrity token from the request body (e.g., request.get_json())
    # 2. Call the Google Play Integrity API to verify the token.
    # 3. Based on the verification result, return an appropriate response.

    # For this initial setup, we just return a placeholder string.
    return "Hello Integrity"

# This is the entry point for GAE when using 'script: auto' or a gunicorn entrypoint.
# It's also useful for local development.
if __name__ == '__main__':
    # This is used when running locally. GAE runs the app via a WSGI server.
    # The host must be 0.0.0.0 to be accessible from outside the container (if running in Docker locally)
    # and GAE uses the PORT environment variable.
    import os
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)), debug=True)
