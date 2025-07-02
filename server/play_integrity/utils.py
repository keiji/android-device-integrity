import re

def mask_server_url(error_message: str) -> str:
    """
    Replaces URLs in an error message with the string "API".
    Handles http and https URLs.
    """
    if not isinstance(error_message, str):
        return str(error_message) # Ensure we work with a string

    # Regex to find URLs. It looks for http:// or https:// followed by non-whitespace characters.
    # It tries to be somewhat conservative to avoid accidentally replacing non-URL strings.
    # Common URL terminators like spaces, commas, parentheses, or end of string are considered.
    url_pattern = r'https?://[^\s()<>]+(?:\([^\s()<>]*\)|[^\s`!()\[\]{};:\'".,<>?«»“”‘’])'
    return re.sub(url_pattern, "API", error_message)
