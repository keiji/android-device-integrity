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

(Instructions for setting up and running the server, e.g., Python version, dependencies, environment variables, GAE deployment, would go here. This is a placeholder as the current task is focused on OpenAPI documentation.)

Refer to `main.py` for the Flask application code and `app.yaml` for Google App Engine configuration.
Make sure `requirements.txt` lists all necessary Python dependencies.
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
