import base64
import os

def generate_random_bytes(length: int = 32) -> bytes:
    """Generates cryptographically secure random bytes."""
    return os.urandom(length)

def base64url_encode(data_bytes: bytes) -> str:
    """Encodes bytes to a Base64URL string (RFC 4648 Section 5)."""
    return base64.urlsafe_b64encode(data_bytes).decode('utf-8').rstrip('=')

def base64url_decode(base64url_string: str) -> bytes:
    """Decodes a Base64URL string (RFC 4648 Section 5) to bytes."""
    # Add padding if necessary, as Python's urlsafe_b64decode requires it.
    padding = '=' * (4 - (len(base64url_string) % 4))
    return base64.urlsafe_b64decode(base64url_string + padding)

def convert_bytes_to_hex_str(data):
    """
    Recursively converts bytes in a dictionary or list to hex strings.
    Useful for serializing attestation properties that may contain bytes.
    """
    if isinstance(data, dict):
        return {k: convert_bytes_to_hex_str(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [convert_bytes_to_hex_str(i) for i in data]
    elif isinstance(data, bytes):
        return data.hex()
    else:
        # For types that are already JSON serializable (int, str, bool, etc.)
        return data
