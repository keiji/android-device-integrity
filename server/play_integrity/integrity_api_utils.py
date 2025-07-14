import logging
from typing import Dict, Any
import google.auth
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Configure logging
logger = logging.getLogger(__name__)

def decode_integrity_token(
    integrity_token: str,
    package_name: str
) -> Dict[str, Any]:
    """
    Calls the Google Play Integrity API to decode the provided integrity token.

    Args:
        integrity_token: The integrity token received from the client.
        package_name: The package name of the Android app.

    Returns:
        The JSON response from the Play Integrity API as a dictionary.

    Raises:
        google.auth.exceptions.DefaultCredentialsError: If Google Cloud credentials are not set up correctly.
        HttpError: For other API-related errors (e.g., invalid token, network issues).
        Exception: For other unexpected errors during the API call.
    """
    try:
        credentials, _ = google.auth.default(
            scopes=['https://www.googleapis.com/auth/playintegrity']
        )
        playintegrity = build('playintegrity', 'v1', credentials=credentials, cache_discovery=False)

        request_body = {'integrity_token': integrity_token}

        response = playintegrity.v1().decodeIntegrityToken(
            packageName=package_name,
            body=request_body
        ).execute()

        return response

    except google.auth.exceptions.DefaultCredentialsError as e_auth:
        logger.error(f"Google Cloud Credentials error: {e_auth}")
        raise  # Re-raise to be handled by the caller
    except HttpError as e_http:
        logger.error(f"Play Integrity API HttpError: {e_http.status_code} - {e_http.reason}. Content: {e_http.content}")
        raise # Re-raise to be handled by the caller
    except Exception as e:
        logger.error(f"An unexpected error occurred while calling the Play Integrity API: {e}", exc_info=True)
        raise # Re-raise to be handled by the caller
