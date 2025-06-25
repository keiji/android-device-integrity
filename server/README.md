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

This server contains two Python Flask applications, `key_attestation` and `play_integrity`, designed to be deployed as services on Google Cloud Run.

### Prerequisites

*   [Google Cloud SDK](https://cloud.google.com/sdk/docs/install) installed and initialized.
*   Python 3.9 or later.
*   `pip` for installing Python dependencies.
*   [Docker](https://docs.docker.com/get-docker/) installed.

### Deployment to Cloud Run

There are two primary ways to deploy these applications to Cloud Run:

#### 1. Automated Deployment with GitHub Actions

This repository is configured with a GitHub Actions workflow (`.github/workflows/cloud_run_deploy.yml`) that automatically builds and deploys the `key_attestation` and `play_integrity` applications to Cloud Run when changes are pushed to the `deploy/cloudrun` branch.

**Service Names on Cloud Run:**
*   `key_attestation` will be deployed as `key-attestation-verify`.
*   `play_integrity` will be deployed as `play-integrity-verify`.

**Setup for Automated Deployment:**

To enable this automated workflow, you need to configure the following secrets in your GitHub repository settings (Settings > Secrets and variables > Actions):

*   `GCP_PROJECT_ID`: Your Google Cloud Project ID.
*   `GCP_CLOUD_RUN_REGION`: The Google Cloud region where you want to deploy the services (e.g., `us-central1`).
*   `GCP_SA_KEY`: The JSON key for a Google Cloud service account. This service account needs permissions to:
    *   Push to Google Container Registry (or Artifact Registry).
    *   Deploy to Cloud Run (e.g., "Cloud Run Admin" role).
    *   Act as a service account (e.g., "Service Account User" role if the Cloud Run services run under a specific identity).

Once these secrets are set up, any push to the `deploy/cloudrun` branch will trigger the workflow and deploy the services.

#### 2. Manual Deployment to Cloud Run

Each application (`key_attestation` and `play_integrity`) can also be containerized and deployed to Cloud Run manually. Ensure you have Docker installed and the Google Cloud SDK configured.

**Steps:**

1.  **Build and Push Docker Image:**
    For each application, navigate to its directory (e.g., `server/key_attestation` or `server/play_integrity`) and build the Docker image. Then, tag it and push it to a container registry like Google Artifact Registry or Google Container Registry (GCR).

    Replace `YOUR_PROJECT_ID`, `YOUR_REGION` (e.g., `us-central1`), `YOUR_ARTIFACT_REPO` (if using Artifact Registry), and `SERVICE_NAME` (`keyattestationverify` or `playintegrityverify`) with your specific values.

    *   **Using Google Artifact Registry:**
        ```bash
        # Navigate to the application directory, e.g., server/key_attestation
        cd server/key_attestation

        # Build the image (replace 'keyattestationverify-image' as needed)
        docker build -t keyattestationverify-image .

        # Tag the image
        docker tag keyattestationverify-image YOUR_REGION-docker.pkg.dev/YOUR_PROJECT_ID/YOUR_ARTIFACT_REPO/keyattestationverify-image:latest

        # Push the image
        docker push YOUR_REGION-docker.pkg.dev/YOUR_PROJECT_ID/YOUR_ARTIFACT_REPO/keyattestationverify-image:latest
        ```
        *Repeat for `server/play_integrity`, changing names accordingly.*
        *Make sure your Artifact Registry repository is created and configured.*

    *   **Using Google Container Registry (GCR) (Legacy):**
        ```bash
        # Navigate to the application directory, e.g., server/key_attestation
        cd server/key_attestation

        # Build the image (replace 'keyattestationverify' as needed)
        docker build -t gcr.io/YOUR_PROJECT_ID/keyattestationverify:latest .

        # Push the image
        gcloud auth configure-docker # If you haven't already
        docker push gcr.io/YOUR_PROJECT_ID/keyattestationverify:latest
        ```
        *Repeat for `server/play_integrity`, changing names accordingly.*

    *   **Alternatively, using Cloud Build:**
        You can submit the build directly to Cloud Build, which will also push the image to Artifact Registry or GCR.
        From the application directory (e.g., `server/key_attestation`):
        ```bash
        # For Artifact Registry (replace SERVICE_NAME with keyattestationverify or playintegrityverify)
        gcloud builds submit --tag YOUR_REGION-docker.pkg.dev/YOUR_PROJECT_ID/YOUR_ARTIFACT_REPO/SERVICE_NAME:latest .

        # For GCR (replace SERVICE_NAME with keyattestationverify or playintegrityverify)
        gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/SERVICE_NAME:latest .
        ```

2.  **Deploy to Cloud Run:**
    Use the `gcloud run deploy` command to deploy each service. The service names used by the GitHub Action are `key-attestation-verify` and `play-integrity-verify`.

    *   **Deploying `key-attestation-verify` service:**
        ```bash
        gcloud run deploy key-attestation-verify \
            --image YOUR_REGION-docker.pkg.dev/YOUR_PROJECT_ID/YOUR_ARTIFACT_REPO/keyattestationverify-image:latest \ # Or gcr.io/YOUR_PROJECT_ID/keyattestationverify:latest
            --platform managed \
            --region YOUR_DEPLOY_REGION \ # e.g., us-central1, should match GCP_CLOUD_RUN_REGION
            --project YOUR_PROJECT_ID \
            --allow-unauthenticated # If the service needs to be publicly accessible
            # Add other flags as needed, e.g., --service-account, --set-env-vars
        ```

    *   **Deploying `play-integrity-verify` service:**
        ```bash
        gcloud run deploy play-integrity-verify \
            --image YOUR_REGION-docker.pkg.dev/YOUR_PROJECT_ID/YOUR_ARTIFACT_REPO/playintegrityverify-image:latest \ # Or gcr.io/YOUR_PROJECT_ID/playintegrityverify:latest
            --platform managed \
            --region YOUR_DEPLOY_REGION \ # e.g., us-central1, should match GCP_CLOUD_RUN_REGION
            --project YOUR_PROJECT_ID \
            --allow-unauthenticated # If the service needs to be publicly accessible
            # Add other flags as needed.
        ```

3.  **Accessing the Cloud Run services:**
    Once deployed, `gcloud run deploy` will output the URL for each service. It will typically be in the format:
    `https://SERVICE_NAME-UNIQUE_HASH-REGION_CODE.a.run.app`

    You can also find the URLs in the Google Cloud Console under Cloud Run.

### Local Development (Optional)

For local testing, you can run each Flask application directly.

1.  **Install dependencies:**
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

    *Note: Ensure that the `app` variable in `key_attestation.py` and `play_integrity.py` is correctly named if you are using `flask run`.*

Refer to `key_attestation/key_attestation.py` and `play_integrity/play_integrity.py` for the Flask application code.
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
