# android-device-integrity

This project provides a demonstration of how to verify Android device integrity. It includes an Android client application and a backend server component. The primary goal is to ensure that interactions are occurring on genuine Android devices with unmodified software.

## System Architecture

The system consists of two main parts:

1.  **Android Client Application**: Located in the `android/` directory, this native Android application is responsible for initiating integrity checks and communicating with the backend server.
2.  **Backend Server**: Located in the `server/` directory, this component is built using Python and Flask. It comprises two distinct applications:
    *   **Key Attestation**: Handles hardware-backed key attestation verification.
    *   **Play Integrity**: Manages nonce generation and Play Integrity token verification in conjunction with the Google Play Integrity API.

## Features

### Android Client
- Initiates device integrity checks.
- Communicates with the backend server to send integrity tokens and receive verification results.
- Demonstrates the usage of Play Integrity API on the client-side.

### Backend Server
- **Key Attestation Service**:
    - Provides endpoints for verifying hardware-backed key attestations (details specific to its implementation).
- **Play Integrity Service**:
    - **Nonce Generation**: Offers an endpoint (`/play-integrity/classic/nonce`) to generate secure nonces for the client to use with the Play Integrity API.
    - **Token Verification**: Provides an endpoint (`/play-integrity/classic/verify`) to receive an integrity token from the client, verify it with Google's Play Integrity API, and check the nonce.

## Setup and Usage

Detailed setup instructions for each component can be found in their respective directories.

### Android Client Application (`android/`)

The Android client application is located in the `android/` directory.

-   **Setup and Building**:
    -   Refer to the `AGENTS.md` file in the root directory for comprehensive instructions on setting up the Android SDK, environment variables, and building the project.
    -   Key build commands (executed from the `android/` directory):
        -   Clean project: `./gradlew clean`
        -   Build debug APK: `./gradlew assembleDebug`
        -   Run unit tests: `./gradlew testDebugUnitTest`
-   **Configuration**:
    -   API endpoint configuration for the backend server might be required within the Android application's source code or configuration files (e.g., `server-endpoint-sample.properties`).

### Backend Server (`server/`)

The backend server components (Key Attestation and Play Integrity) are located in the `server/` directory.

-   **Detailed Instructions**: Full setup, deployment, and local execution instructions are available in `server/README.md`.
-   **Deployment (Cloud Run)**:
    -   **Automated**: The project supports automated deployment to Google Cloud Run via GitHub Actions, triggered by pushes to the `deploy/cloudrun` branch. See `server/README.md` for required GitHub secrets (`GCP_PROJECT_ID`, `GCP_CLOUD_RUN_REGION`, `GCP_SA_KEY`).
    -   **Manual**: Instructions for building Docker images and deploying manually to Cloud Run are also provided in `server/README.md`.
        -   Key Attestation service name: `key-attestation-verify`
        -   Play Integrity service name: `play-integrity-verify`
-   **Local Development**:
    -   Each Flask application (`key_attestation`, `play_integrity`) can be run locally. This requires Python, pip, and installing dependencies from their respective `requirements.txt` files. See `server/README.md` for commands.

## API Endpoints (Backend Server)

The backend server exposes several API endpoints. For detailed information on request/response schemas, please refer to `server/README.md` and the OpenAPI specification mentioned below.

### Play Integrity Service
-   **`/play-integrity/classic/nonce` (POST)**:
    -   Generates a nonce for the client app to use with the Play Integrity API.
-   **`/play-integrity/classic/verify` (POST)**:
    -   Verifies an integrity token received from the client app. This involves calling Google's Play Integrity API and checking the nonce.

### Key Attestation Service
-   Endpoints for key attestation are defined within `server/key_attestation/openapi.yaml`. Refer to this file and `server/README.md` for details.

## OpenAPI Specification

The backend server's APIs are documented using the OpenAPI v3 specification.
-   **Play Integrity API**: The specification can be found at `server/play_integrity/openapi.yaml`.
-   **Key Attestation API**: The specification can be found at `server/key_attestation/openapi.yaml`.

These files provide detailed information about request and response schemas, parameters, and status codes for each endpoint.

## Development Guidelines

When contributing to this project or making modifications:

-   **Android Development**: Follow the setup and build instructions in `AGENTS.md`. This file also contains important notes for AI agents regarding the Android development environment.
-   **Server Development**: Adhere to the guidelines and instructions provided in `server/README.md` for the backend services.
-   **Code Editing Rules**: General rules for code editing (e.g., code removal, commit messages) are outlined in the `AGENTS.md` file under the section "コード編集時のルール". Please consult this section before committing changes.
