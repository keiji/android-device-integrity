# Play Integrity API Server

This directory contains a Python Flask server designed to support backend verification for the Google Play Integrity API. It provides endpoints for generating nonces and verifying integrity tokens.

## API Endpoints

The server exposes the following two endpoints:

1.  **`/play-integrity/classic/nonce` (POST)**
    *   **Description**: Generates a cryptographically secure nonce that should be sent to the client app. The client app will then use this nonce when calling the Play Integrity API on the Android device.
    *   **Request**: No body required.
    *   **Response**:
        *   `200 OK`: JSON object containing `nonce` (string) and `generated_datetime` (int64, epoch milliseconds).
        *   `500 Internal ServerError`: JSON object with an `error` message if nonce generation fails.

2.  **`/play-integrity/classic/verify` (POST)**
    *   **Description**: Verifies an integrity token that the client app receives from the Play Integrity API. This endpoint calls Google's Play Integrity API to decode and verify the token. It also performs a crucial nonce check to ensure the token corresponds to the nonce this server generated.
    *   **Request Body**: JSON object containing:
        *   `nonce` (string): The nonce previously obtained from the `/play-integrity/classic/nonce` endpoint.
        *   `token` (string): The integrity token from the client.
    *   **Response**:
        *   `200 OK`: The JSON response directly from the Google Play Integrity API, indicating successful verification and a matching nonce.
        *   `400 Bad Request`: JSON object with an `error` message. This can occur due to:
            *   Missing JSON payload.
            *   Missing `nonce` or `token` in the request.
            *   Nonce mismatch between the client-provided nonce and the nonce in the integrity token.
        *   `500 Internal Server Error`: JSON object with an `error` message. This can occur due to:
            *   Server authentication configuration issues with Google Cloud.
            *   Other failures during the token verification process.
            *   The nonce being absent in the Play Integrity API's response.

## OpenAPI Specification

The API is documented using the OpenAPI v3 specification. The specification file can be found at [openapi.yaml](./openapi.yaml).

This specification details the request and response schemas, parameters, and status codes for each endpoint. It can be used with various tools to:
*   Visualize the API (e.g., Swagger UI, ReDoc).
*   Generate client libraries.
*   Perform automated testing.

## Setup and Running

This server contains two Google App Engine (GAE) applications: `key_attestation` and `play_integrity`.

### Prerequisites

*   [Google Cloud SDK](https://cloud.google.com/sdk/docs/install) installed and initialized.
*   Python 3.9 or later.
*   `pip` for installing Python dependencies.

### Deployment to App Engine

Each application needs to be deployed separately.

1.  **Install Dependencies:**
    Before deploying, ensure you have installed the necessary dependencies for each application. Navigate to the respective application's directory and run:
    ```bash
    # For key_attestation
    cd server/key_attestation
    pip install -r requirements.txt -t lib # Installs dependencies into the 'lib' folder

    # For play_integrity
    cd server/play_integrity
    pip install -r requirements.txt -t lib # Installs dependencies into the 'lib' folder
    ```
    *Note: App Engine's Python 3 runtime automatically looks for dependencies in a `lib` directory. If you are using a different deployment method or runtime, adjust accordingly.*

2.  **Deploy each application:**
    Use the `gcloud app deploy` command, specifying the `app.yaml` file for each service.

    *   **Deploying `key_attestation` service:**
        Navigate to the `server/key_attestation` directory:
        ```bash
        cd server/key_attestation
        gcloud app deploy app.yaml
        ```
        Alternatively, from the repository root:
        ```bash
        gcloud app deploy server/key_attestation/app.yaml
        ```

    *   **Deploying `play_integrity` service:**
        Navigate to the `server/play_integrity` directory:
        ```bash
        cd server/play_integrity
        gcloud app deploy app.yaml
        ```
        Alternatively, from the repository root:
        ```bash
        gcloud app deploy server/play_integrity/app.yaml
        ```

    *   **Project and Region:**
        If this is the first time deploying to your Google Cloud project, you might be prompted to choose a region for your App Engine application.
        You can also specify the project ID with the `--project` flag:
        ```bash
        gcloud app deploy app.yaml --project YOUR_PROJECT_ID
        ```

3.  **Accessing the services:**
    Once deployed, the services will be accessible via URLs like:
    *   `https://key-attestation-dot-YOUR_PROJECT_ID.REGION_ID.r.appspot.com`
    *   `https://play-integrity-dot-YOUR_PROJECT_ID.REGION_ID.r.appspot.com`

    Replace `YOUR_PROJECT_ID` with your Google Cloud project ID and `REGION_ID` with the region you selected (e.g., `uc.r` for us-central). You can find the URLs in the output of the `gcloud app deploy` command or in the Google Cloud Console under App Engine services.

### Deployment to Cloud Run

Each application (`key_attestation` and `play_integrity`) needs to be containerized and deployed to Cloud Run separately. Ensure you have Docker installed and the Google Cloud SDK configured.

1.  **Build and Push Docker Image:**
    For each application, navigate to its directory (e.g., `server/key_attestation` or `server/play_integrity`) and build the Docker image. Then, tag it and push it to a container registry like Google Artifact Registry or Google Container Registry (GCR).

    Replace `YOUR_PROJECT_ID`, `YOUR_REGION` (e.g., `us-central1`), `YOUR_ARTIFACT_REPO` (if using Artifact Registry), and `SERVICE_NAME` (`key-attestation` or `play-integrity`) with your specific values.

    *   **Using Google Artifact Registry:**
        ```bash
        # Build the image
        docker build -t key-attestation-image . # Or play-integrity-image

        # Tag the image
        docker tag key-attestation-image YOUR_REGION-docker.pkg.dev/YOUR_PROJECT_ID/YOUR_ARTIFACT_REPO/key-attestation-image:latest
        # Or for play-integrity:
        # docker tag play-integrity-image YOUR_REGION-docker.pkg.dev/YOUR_PROJECT_ID/YOUR_ARTIFACT_REPO/play-integrity-image:latest

        # Push the image
        docker push YOUR_REGION-docker.pkg.dev/YOUR_PROJECT_ID/YOUR_ARTIFACT_REPO/key-attestation-image:latest
        # Or for play-integrity:
        # docker push YOUR_REGION-docker.pkg.dev/YOUR_PROJECT_ID/YOUR_ARTIFACT_REPO/play-integrity-image:latest
        ```
        *Make sure your Artifact Registry repository is created and configured.*

    *   **Using Google Container Registry (GCR) (Legacy):**
        ```bash
        # Build the image
        docker build -t gcr.io/YOUR_PROJECT_ID/key-attestation-image:latest . # Or play-integrity-image

        # Push the image
        gcloud auth configure-docker # If you haven't already
        docker push gcr.io/YOUR_PROJECT_ID/key-attestation-image:latest
        # Or for play-integrity:
        # docker push gcr.io/YOUR_PROJECT_ID/play-integrity-image:latest
        ```

    *   **Alternatively, using Cloud Build:**
        You can submit the build directly to Cloud Build, which will also push the image to Artifact Registry or GCR.
        From the application directory (e.g., `server/key_attestation`):
        ```bash
        # For Artifact Registry
        gcloud builds submit --tag YOUR_REGION-docker.pkg.dev/YOUR_PROJECT_ID/YOUR_ARTIFACT_REPO/SERVICE_NAME:latest .

        # For GCR
        gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/SERVICE_NAME:latest .
        ```

2.  **Deploy to Cloud Run:**
    Use the `gcloud run deploy` command to deploy each service.

    *   **Deploying `key-attestation` service:**
        ```bash
        gcloud run deploy key-attestation-service \
            --image YOUR_REGION-docker.pkg.dev/YOUR_PROJECT_ID/YOUR_ARTIFACT_REPO/key-attestation-image:latest \ # Or gcr.io/YOUR_PROJECT_ID/key-attestation-image:latest
            --platform managed \
            --region YOUR_DEPLOY_REGION \ # e.g., us-central1
            --project YOUR_PROJECT_ID \
            --allow-unauthenticated # If the service needs to be publicly accessible
            # Add other flags as needed, e.g., --service-account, --set-env-vars
        ```

    *   **Deploying `play-integrity` service:**
        ```bash
        gcloud run deploy play-integrity-service \
            --image YOUR_REGION-docker.pkg.dev/YOUR_PROJECT_ID/YOUR_ARTIFACT_REPO/play-integrity-image:latest \ # Or gcr.io/YOUR_PROJECT_ID/play-integrity-image:latest
            --platform managed \
            --region YOUR_DEPLOY_REGION \ # e.g., us-central1
            --project YOUR_PROJECT_ID \
            --allow-unauthenticated # If the service needs to be publicly accessible
            # Add other flags as needed.
            # For Datastore access, ensure the runtime service account (default or custom)
            # has 'Cloud Datastore User' role or equivalent permissions.
        ```

3.  **Accessing the Cloud Run services:**
    Once deployed, `gcloud run deploy` will output the URL for each service. It will typically be in the format:
    `https://SERVICE_NAME-UNIQUE_HASH-REGION_CODE.a.run.app`

    You can also find the URLs in the Google Cloud Console under Cloud Run.

### Local Development (Optional)

For local testing, you can run each Flask application directly.

1.  **Install dependencies** (if not already done for deployment):
    ```bash
    # For key_attestation
    cd server/key_attestation
    pip install -r requirements.txt

    # For play_integrity
    cd server/play_integrity
    pip install -r requirements.txt
    ```

2.  **Run the Flask development server:**
    *   **For `key_attestation`:**
        ```bash
        cd server/key_attestation
        flask run -p 8081 # Or any other available port
        ```
        The `key_attestation` service will be available at `http://localhost:8081`.

    *   **For `play_integrity`:**
        ```bash
        cd server/play_integrity
        flask run -p 8082 # Or any other available port
        ```
        The `play_integrity` service will be available at `http://localhost:8082`.

    *Note: Ensure that the `app` variable in `key_attestation.py` and `play_integrity.py` is correctly named if you are using `flask run`. The `entrypoint` in `app.yaml` uses `gunicorn` which might have different expectations for the application variable name (e.g., `key_attestation:app` means it looks for an `app` instance in `key_attestation.py`).*

Refer to `key_attestation/key_attestation.py` and `play_integrity/play_integrity.py` for the Flask application code, and their respective `app.yaml` files for Google App Engine configuration.
Make sure `requirements.txt` in each application directory lists all necessary Python dependencies.
```
## AGENTS.md

- Repositories often contain `AGENTS.md` files. These files can appear anywhere in the file hierarchy, typically in the root directory.
- These files are a way for humans to give you (the agent) instructions or tips for working with the code.
- Some examples might be: coding conventions, info about how code is organized, or instructions for how to run or test code.
- If the `AGENTS.md` includes programmatic checks to verify your work, you MUST run all of them and make a best effort to ensure they pass after all code changes have been made.
- Instructions in `AGENTS.md` files:
  - The scope of an `AGENTS.md` file is the entire directory tree rooted at the folder that contains it.
  - For every file you touch, you must obey instructions in any `AGENTS.md` file whose scope includes that file.
  - More deeply-nested `AGENTS.md` files take precedence in the case of conflicting instructions.
  - The initial problem description and any explicit instructions you receive from the user to deviate from standard procedure take precedence over `AGENTS.md` instructions.

## Guiding principles

- Your first order of business is to come up with a solid plan -- explore the codebase, do research, read files and ask clarifying questions when appropriate. Make sure to read websites if any are specified in the task. Articulate the plan clearly and set it using `set_plan`.
- Repositories often contain `README.md` files with useful information about the project. Similarly, always look for `AGENTS.md` files as described above.
- When practical, practice test-driven development by writing tests first, and then implementing the code to make them pass. Tests are the best way to prove your changes are correct.
- Strive to solve problems autonomously. However, you should ask for help using `request_user_input` in the following situations:
  1) The user's request is ambiguous and you need clarification.
  2) You have tried multiple approaches to solve a problem and are still stuck.
  3) You need to make a decision that would significantly alter the scope of the original request.

## Core directives

- All tool calls must be enclosed in their own `
