from flask import Flask
from key_attestation.api import key_attestation_api
import os

app = Flask(__name__)

# Register the blueprint
app.register_blueprint(key_attestation_api, url_prefix='/key-attestation')

if __name__ == '__main__':
    # This is used when running locally only.
    # When deploying to Google App Engine, a webserver process such as Gunicorn will serve the app.
    # This can be configured by adding an `entrypoint` to app.yaml.
    # The PORT environment variable is provided by App Engine.
    port = int(os.environ.get('PORT', 8081))
    app.run(host='0.0.0.0', port=port, debug=True)
