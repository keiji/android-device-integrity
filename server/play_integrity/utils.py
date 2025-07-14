import re
import uuid

def mask_server_url(error_message: str) -> str:
    """
    Replaces URLs in an error message with the string "API".
    Handles http and https URLs.
    """
    if not isinstance(error_message, str):
        return str(error_message)

    url_pattern = r'(https?://[^\s"\']+)'
    return re.sub(url_pattern, "API", error_message)

def generate_unique_id():
    """Generates a unique ID using UUID v4."""
    return str(uuid.uuid4())
