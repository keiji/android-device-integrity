import base64
import os
import json # Added for serializing data for Datastore
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify # Removed Blueprint as it's not used
from google.cloud import datastore
import logging
import hmac # For constant-time comparison
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding as asym_padding
from cryptography.exceptions import InvalidSignature
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type import univ
from pyasn1.error import PyAsn1Error

# Initialize Flask app
app = Flask(__name__)
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Datastore client
try:
    datastore_client = datastore.Client()
    logger.info('Datastore client initialized successfully.') # Standardized to single quote
except Exception as e:
    logger.error(f'Failed to initialize Datastore client: {e}') # Already f-string
    datastore_client = None

# Datastore Kind for Key Attestation Sessions
KEY_ATTESTATION_SESSION_KIND = 'SignatureKeyAttestationSession' # Standardized to single quote
AGREEMENT_KEY_ATTESTATION_SESSION_KIND = 'AgreementKeyAttestationSession' # Standardized to single quote
KEY_ATTESTATION_RESULT_KIND = 'KeyAttestationResult' # New Datastore Kind, standardized
NONCE_EXPIRY_MINUTES = 10 # Renamed from SESSION_EXPIRY_MINUTES

# --- Helper Functions ---

def generate_random_bytes(length=32):
    """Generates cryptographically secure random bytes."""
    return os.urandom(length)

def base64url_encode(data_bytes):
    """Encodes bytes to a Base64URL string."""
    return base64.urlsafe_b64encode(data_bytes).decode('utf-8').rstrip('=')

def base64url_decode(base64url_string):
    """Decodes a Base64URL string to bytes."""
    padding = '=' * (4 - (len(base64url_string) % 4))
    return base64.urlsafe_b64decode(base64url_string + padding)

def convert_bytes_to_hex_str(data):
    """
    Recursively converts bytes in a dictionary or list to hex strings.
    """
    if isinstance(data, dict):
        return {k: convert_bytes_to_hex_str(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [convert_bytes_to_hex_str(i) for i in data]
    elif isinstance(data, bytes):
        return data.hex()
    else:
        return data

def store_key_attestation_session(session_id, nonce_encoded, challenge_encoded):
    """
    Stores the key attestation session data in Datastore.
    The entity key will be the session_id to ensure uniqueness and allow easy lookup.
    """
    if not datastore_client:
        logger.error('Datastore client not available. Cannot store session.') # Standardized
        raise ConnectionError('Datastore client not initialized.') # Standardized

    now = datetime.now(timezone.utc)
    # expiry_datetime = now + timedelta(minutes=NONCE_EXPIRY_MINUTES) # Field removed - Retaining this removal

    key = datastore_client.key(KEY_ATTESTATION_SESSION_KIND, session_id)
    entity = datastore.Entity(key=key)
    entity.update({
        'session_id': session_id,
        'nonce': nonce_encoded,
        'challenge': challenge_encoded,
        'generated_at': now,
    })
    datastore_client.put(entity)
    logger.info(f'Stored key attestation session for session_id: {session_id}') # Already f-string
    # Consider calling cleanup_expired_sessions() here or via a scheduled job - Retaining this useful comment
    cleanup_expired_sessions()

# First definition of store_agreement_key_attestation_session removed (lines 90-110 of original)
# The second, more complete definition is kept.

def store_agreement_key_attestation_session(session_id, salt_encoded, challenge_encoded, public_key_encoded=None, private_key_encoded=None): # Added public_key_encoded and private_key_encoded
    """
    Stores the agreement key attestation session data in Datastore.
    The entity key will be the session_id to ensure uniqueness and allow easy lookup.
    """
    if not datastore_client:
        logger.error('Datastore client not available. Cannot store session.') # Standardized
        raise ConnectionError('Datastore client not initialized.') # Standardized

    now = datetime.now(timezone.utc)

    key = datastore_client.key(AGREEMENT_KEY_ATTESTATION_SESSION_KIND, session_id)
    entity = datastore.Entity(key=key)
    entity.update({
        'session_id': session_id,
        'salt': salt_encoded, # Changed from nonce - Retaining this useful comment
        'challenge': challenge_encoded,
        'generated_at': now,
    })
    if public_key_encoded:
        entity['public_key'] = public_key_encoded
    if private_key_encoded:
        entity['private_key'] = private_key_encoded

    datastore_client.put(entity)
    logger.info(f'Stored agreement key attestation session for session_id: {session_id}') # Already f-string
    # Consider calling cleanup_expired_agreement_sessions() here or via a scheduled job - Retaining this useful comment
    cleanup_expired_agreement_sessions()


def get_key_attestation_session(session_id):
    """
    Retrieves and validates key attestation session data from Datastore.
    Returns the session entity if valid and not expired, otherwise None.
    """
    if not datastore_client:
        logger.error('Datastore client not available. Cannot retrieve session.') # Standardized
        # Consider raising an exception here if this is an unrecoverable state - Retaining this useful comment
        return None

    key = datastore_client.key(KEY_ATTESTATION_SESSION_KIND, session_id)
    entity = datastore_client.get(key)

    if not entity:
        logger.warning(f'Session not found for session_id: {session_id}') # Already f-string
        return None

    # Check for expiration - Retaining this useful comment
    generated_at = entity.get('generated_at')
    if not generated_at: # Should not happen if stored correctly - Retaining this useful comment
        logger.error(f'Session {session_id} is missing \'generated_at\' timestamp.') # Standardized, was f-string
        return None

    # Ensure generated_at is offset-aware for comparison - Retaining this useful comment
    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=timezone.utc)

    expiry_datetime = generated_at + timedelta(minutes=NONCE_EXPIRY_MINUTES)
    if datetime.now(timezone.utc) > expiry_datetime:
        logger.warning(f'Session expired for session_id: {session_id}. Generated at: {generated_at}, Expired at: {expiry_datetime}') # Already f-string
        # Optionally delete the expired entity here or rely on cleanup_expired_sessions - Retaining
        # datastore_client.delete(key) # This was actual commented-out code, will remove
        return None

    logger.info(f'Successfully retrieved and validated session for session_id: {session_id}') # Already f-string
    return entity

def get_agreement_key_attestation_session(session_id):
    """
    Retrieves and validates agreement key attestation session data from Datastore.
    Returns the session entity if valid and not expired, otherwise None.
    """
    if not datastore_client:
        logger.error('Datastore client not available. Cannot retrieve session.') # Standardized
        return None

    key = datastore_client.key(AGREEMENT_KEY_ATTESTATION_SESSION_KIND, session_id)
    entity = datastore_client.get(key)

    if not entity:
        logger.warning(f'Agreement session not found for session_id: {session_id}') # Already f-string
        return None

    generated_at = entity.get('generated_at')
    if not generated_at:
        logger.error(f'Agreement session {session_id} is missing \'generated_at\' timestamp.') # Standardized, was f-string
        return None

    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=timezone.utc)

    expiry_datetime = generated_at + timedelta(minutes=NONCE_EXPIRY_MINUTES) # Using NONCE_EXPIRY_MINUTES for salt too - Retaining
    if datetime.now(timezone.utc) > expiry_datetime:
        logger.warning(f'Agreement session expired for session_id: {session_id}. Generated at: {generated_at}, Expired at: {expiry_datetime}') # Already f-string
        return None

    logger.info(f'Successfully retrieved and validated agreement session for session_id: {session_id}') # Already f-string
    return entity

def decode_certificate_chain(certificate_chain_b64):
    """
    Decodes a list of Base64 encoded certificate strings into a list of X509Certificate objects.
    """
    decoded_certs = []
    for i, cert_b64 in enumerate(certificate_chain_b64):
        try:
            cert_bytes = base64.b64decode(cert_b64) # Rely on b64decode to handle padding - Retaining
            cert = x509.load_der_x509_certificate(cert_bytes)
            decoded_certs.append(cert)
        except ValueError as e: # Handles errors from b64decode if input is invalid (e.g. bad chars, incorrect padding if strict) - Retaining
            logger.error(f'Failed to decode Base64 certificate at index {i}: {e}') # Standardized, was f-string
            raise ValueError(f'Invalid Base64 certificate string at index {i}') # Standardized
        except TypeError as e: # Handles errors from b64decode if input is not string-like - Retaining
            logger.error(f'Type error during Base64 decoding for certificate at index {i}: {e}') # Standardized
            raise ValueError(f'Invalid type for Base64 certificate string at index {i}') # Standardized
        except Exception as e: # Catch other cryptography parsing errors or unexpected issues - Retaining
            logger.error(f'Error loading certificate at index {i} into X509 object: {e}') # Standardized
            raise ValueError(f'Cannot parse certificate at index {i} into X509 object') # Standardized
    if not decoded_certs:
        raise ValueError('Certificate chain is empty after decoding.') # Standardized
    return decoded_certs

def validate_attestation_signature(leaf_certificate, nonce_from_store_b64, nonce_b_b64, signature_b64):
    """
    Validates the attestation signature.
    - Decodes nonces and signature.
    - Constructs the data that was signed (nonce_from_store || nonce_b).
    - Verifies the signature using the public key from the leaf certificate.
    """
    try:
        nonce_from_store_bytes = base64url_decode(nonce_from_store_b64)
        nonce_b_bytes = base64url_decode(nonce_b_b64)
        signature_bytes = base64url_decode(signature_b64)
    except Exception as e:
        logger.error(f'Failed to base64url_decode one of the signature components: {e}') # Standardized
        raise ValueError('Invalid base64url encoding for nonce, nonce_b, or signature.') # Standardized

    signed_data_bytes = nonce_from_store_bytes + nonce_b_bytes
    public_key = leaf_certificate.public_key()

    try:
        # Assuming EC public key, as per "verify/ec" - Retaining
        # For EC keys, verify() expects the raw signature bytes (r and s concatenated). - Retaining
        # The hash algorithm is typically SHA256 for Android Key Attestation with EC. - Retaining
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature_bytes,
                signed_data_bytes,
                ec.ECDSA(hashes.SHA256()) # Assuming SHA256, common for attestation - Retaining
            )
            logger.info('Attestation signature validated successfully.') # Standardized
            return True
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature_bytes,
                signed_data_bytes,
                asym_padding.PKCS1v15(), # Or PSS, depending on what client uses - Retaining
                hashes.SHA256()
            )
            logger.info('Attestation signature validated successfully (RSA).') # Standardized
            return True
        else:
            logger.error(f'Unsupported public key type for signature verification: {type(public_key)}') # Standardized
            raise ValueError('Unsupported public key type in leaf certificate for signature verification.') # Standardized
    except InvalidSignature:
        logger.warning('Attestation signature verification failed: InvalidSignature.') # Standardized
        raise ValueError('Attestation signature verification failed.') # Standardized
    except Exception as e:
        logger.error(f'Error during attestation signature verification: {e}') # Standardized
        raise ValueError(f'An unexpected error occurred during signature verification: {e}') # Standardized

def verify_certificate_chain(certificates):
    """
    Verifies the certificate chain.
    - Each certificate (except the last) is signed by the next certificate in the chain.
    - Does not verify the root against a trust store (as per requirements).
    """
    if len(certificates) < 1: # Should have been caught by decode_certificate_chain - Retaining
        raise ValueError('Certificate chain is empty, cannot verify.') # Standardized
    if len(certificates) == 1:
        # Single certificate in chain (self-signed or needs external trust anchor). - Retaining
        # For attestation, usually there's at least a leaf and an attestation CA. - Retaining
        # Depending on policy, a single cert might be acceptable if it's a known attestation root, - Retaining
        # but the requirement is to verify chain signatures if multiple certs exist. - Retaining
        # For now, we consider a single cert chain as "verified" in terms of its internal links. - Retaining
        logger.info('Certificate chain has only one certificate. No internal chain validation to perform.') # Standardized
        return True

    for i in range(len(certificates) - 1):
        subject_cert = certificates[i]
        issuer_cert = certificates[i+1]
        issuer_public_key = issuer_cert.public_key()

        try:
            # The signature hash algorithm is part of the subject_cert.signature_hash_algorithm - Retaining
            # The public key algorithm from issuer_public_key and signature algorithm from subject_cert - Retaining
            # are used by the verify() method. - Retaining
            if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                issuer_public_key.verify(
                    subject_cert.signature,
                    subject_cert.tbs_certificate_bytes,
                    ec.ECDSA(subject_cert.signature_hash_algorithm) # Use hash algorithm from subject cert - Retaining
                )
            elif isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(
                    subject_cert.signature,
                    subject_cert.tbs_certificate_bytes,
                    asym_padding.PKCS1v15(), # Assuming PKCS1v15 for cert signatures - Retaining
                    subject_cert.signature_hash_algorithm
                )
            else:
                logger.error(f'Unsupported public key type in issuer certificate for chain validation: {type(issuer_public_key)}') # Standardized
                raise ValueError(f'Certificate chain validation failed: Unsupported public key type in issuer certificate at index {i+1}.') # Standardized

            logger.info(f'Verified certificate {i}\'s signature with certificate {i+1}\'s public key.') # Standardized
        except InvalidSignature:
            logger.warning(f'Certificate chain validation failed: Cert {i} not signed by cert {i+1}.') # Standardized
            raise ValueError(f'Certificate chain validation failed: Certificate at index {i} is not signed by certificate at index {i+1}.') # Standardized
        except Exception as e:
            logger.error(f'Error during certificate chain validation (cert {i} by cert {i+1}): {e}') # Standardized
            raise ValueError(f'An unexpected error occurred during certificate chain validation: {e}') # Standardized

    logger.info('Certificate chain verified successfully.') # Standardized
    return True

# --- ASN.1 Constants and Parsing --- - Retaining
# OID for Android Key Attestation extension - Retaining
OID_ANDROID_KEY_ATTESTATION = x509.ObjectIdentifier('1.3.6.1.4.1.11129.2.1.17') # Standardized

# AuthorizationList tags (from Keymaster/KeyMint documentation) - Retaining
# https://source.android.com/docs/security/features/keystore/attestation?hl=ja#schema - Retaining
TAG_PURPOSE = 1
TAG_ALGORITHM = 2
TAG_KEY_SIZE = 3
TAG_DIGEST = 5
TAG_PADDING = 6
TAG_EC_CURVE = 10

TAG_RSA_PUBLIC_EXPONENT = 200
TAG_MGF_DIGEST = 203

TAG_ROLLBACK_RESISTANCE = 303
TAG_EARLY_BOOT_ONLY = 305

TAG_ACTIVE_DATETIME = 400
TAG_ORIGINATION_EXPIRE_DATETIME = 401
TAG_USAGE_EXPIRE_DATETIME = 402
TAG_USAGE_COUNT_LIMIT = 405

TAG_NO_AUTH_REQUIRED = 503
TAG_USER_AUTH_TYPE = 504
TAG_AUTH_TIMEOUT = 505
TAG_ALLOW_WHILE_ON_BODY = 506
TAG_TRUSTED_USER_PRESENCE_REQUIRED = 507
TAG_TRUSTED_CONFIRMATION_REQUIRED = 508
TAG_UNLOCKED_DEVICE_REQUIRED = 509

TAG_CREATION_DATETIME = 701
TAG_ORIGIN = 702
TAG_ROOT_OF_TRUST = 704
TAG_OS_VERSION = 705
TAG_OS_PATCH_LEVEL = 706
TAG_ATTESTATION_APPLICATION_ID = 709  # v2+ - Retaining
TAG_ATTESTATION_ID_BRAND = 710  # v2+ - Retaining
TAG_ATTESTATION_ID_DEVICE = 711  # v2+ - Retaining
TAG_ATTESTATION_ID_PRODUCT = 712
TAG_ATTESTATION_ID_SERIAL = 713
TAG_ATTESTATION_ID_IMEI = 714
TAG_ATTESTATION_ID_MEID = 715
TAG_ATTESTATION_ID_MANUFACTURER = 716
TAG_ATTESTATION_ID_MODEL = 717
TAG_VENDOR_PATCH_LEVEL = 718
TAG_BOOT_PATCH_LEVEL = 719
TAG_DEVICE_UNIQUE_ATTESTATION = 720
# Duplicated TAG_ATTESTATION_ID_IMEI and TAG_ATTESTATION_ID_MEID removed
TAG_ATTESTATION_ID_SECOND_IMEI = 723
TAG_MODULE_HASH = 724
# ... and many more - Retaining this comment

def parse_root_of_trust(root_of_trust_sequence):
    """Parses the RootOfTrust ASN.1 sequence.""" # Added docstring
    parsed_data = {}
    if not isinstance(root_of_trust_sequence, univ.Sequence):
        return parsed_data
    parsed_data['verified_boot_key'] = bytes(root_of_trust_sequence[0]).hex()
    parsed_data['device_locked'] = bool(root_of_trust_sequence[1])
    parsed_data['verified_boot_state'] = int(root_of_trust_sequence[2])
    parsed_data['verified_boot_hash'] = bytes(root_of_trust_sequence[3]).hex()
    return parsed_data

def parse_attestation_application_id(attestation_application_id_bytes):
    """Parses the AttestationApplicationId ASN.1 structure.""" # Added docstring
    try:
        attestation_application_id_sequence, _ = der_decoder.decode(attestation_application_id_bytes)
    except PyAsn1Error as e:
        logger.error(f'Failed to decode AttestationApplicationId ASN.1 sequence with pyasn1: {e}') # Standardized
        raise ValueError('Malformed AttestationApplicationId sequence.') # Standardized

    parsed_data = {}
    if not isinstance(attestation_application_id_sequence, univ.SequenceOf): # This should be SequenceOf according to spec
        return parsed_data

    # Assuming the structure: SequenceOf (size 1..*) of PackageInfo
    # And PackageInfo is a Sequence of (packageName (UTF8String), version (INTEGER))
    # And this is followed by a SetOf (size 1..*) of OctetString (signatures)
    # The pyasn1 decoded structure might be nested.
    # Example from spec: attestationApplicationId ::= SEQUENCE {
    #    packageInfos SET (SIZE (1..MAX)) OF PackageInfo,
    #    signatureDigests SET (SIZE (1..MAX)) OF OCTET_STRING }
    # PackageInfo ::= SEQUENCE { packageName UTF8String, version INTEGER }
    # This parsing seems to be based on a different interpretation or a specific profile.
    # For now, I will keep the existing logic but note the schema discrepancy for potential future review.

    # The original code had complex indexing [0][0] which implies specific nesting.
    # Let's assume the first element of SequenceOf is the target Sequence for package info
    if not attestation_application_id_sequence: # Check if empty
        return parsed_data

    # The original code implies a structure like:
    # Outer Sequence (AttestationApplicationId)
    #   -> [0] Sequence (PackageInfo)
    #       -> [0] packageName
    #       -> [1] versionCode
    #   -> [1] SetOf (Signatures)
    # This structure does not exactly match typical ASN.1 for AttestationApplicationId.
    # However, I will stick to refactoring the existing logic.

    # The user's code structure for attestation_application_id_sequence:
    # attestation_application_id_sequence[0] -> package_info_set (which it expects to be a sequence)
    # attestation_application_id_sequence[0][0] -> package_info_sequence (actual package info)
    # attestation_application_id_sequence[1] -> signature_set
    # This is highly specific and might be based on a particular device's output.

    try: # Adding try-except for robust indexing
        package_info_outer_set = attestation_application_id_sequence[0]
        if not isinstance(package_info_outer_set, univ.SetOf) or not package_info_outer_set:
             logger.warning('Expected SetOf for packageInfos, or it is empty.')
             return parsed_data # Or handle error appropriately

        # Assuming only one PackageInfo in the SET for this implementation
        package_info_sequence = package_info_outer_set[0]
        if not isinstance(package_info_sequence, univ.Sequence):
            logger.warning('Expected Sequence for PackageInfo.')
            return parsed_data

        signature_set = attestation_application_id_sequence[1]
        if not isinstance(signature_set, univ.SetOf):
            logger.warning('Expected SetOf for signatureDigests.')
            return parsed_data # Or handle as error

    except (IndexError, TypeError):
        logger.error('Unexpected structure in AttestationApplicationId sequence.')
        return parsed_data


    # Parsing PackageInfo from package_info_sequence
    if len(package_info_sequence) > 0:
        parsed_data['package_name'] = str(package_info_sequence[0]) # Assuming first is name
    if len(package_info_sequence) > 1:
        parsed_data['version_code'] = int(package_info_sequence[1]) # Assuming second is version

    signatures = []
    for sig_item in signature_set:
        signatures.append(bytes(sig_item).hex())
    parsed_data['signature_digests'] = signatures # Changed key to match typical naming

    return parsed_data


def parse_authorization_list(auth_list_sequence, attestation_version):
    """
    Parses an AuthorizationList SEQUENCE using pyasn1.
    Returns a dictionary of parsed properties.
    """
    parsed_props = {}
    if not isinstance(auth_list_sequence, univ.Sequence):
        return parsed_props

    for item_value_pair in auth_list_sequence: # Iterating directly over sequence components
        try:
            # Each component in AuthorizationList is explicitly tagged
            # The tag number is directly available from the component itself.
            if not hasattr(item_value_pair, 'tagSet') or not item_value_pair.tagSet:
                 logger.warning(f'Skipping item in AuthorizationList without a proper tagSet: {item_value_pair}')
                 continue

            tag_number = item_value_pair.tagSet.tagId
            value_component = item_value_pair # The component itself is the value container for explicit tags

        except (AttributeError, IndexError, TypeError):
            logger.warning(f'Could not get tag or value from auth list item: {item_value_pair}')
            continue

        # Simplified logic for parsing based on tag (original logic was mostly correct)
        # Ensuring all string conversions and logging use single quotes and f-strings
        try:
            if tag_number == TAG_ATTESTATION_APPLICATION_ID: # This tag holds OCTET STRING which is further decoded
                app_id_bytes = bytes(value_component.getComponent()) # Get the OCTET STRING payload
                parsed_props['attestation_application_id'] = parse_attestation_application_id(app_id_bytes)
            elif tag_number == TAG_OS_VERSION:
                parsed_props['os_version'] = int(value_component.getComponent())
            elif tag_number == TAG_OS_PATCH_LEVEL:
                parsed_props['os_patch_level'] = int(value_component.getComponent())
            elif tag_number == TAG_DIGEST: # SET OF INTEGER
                parsed_props['digests'] = [int(p) for p in value_component.getComponent()]
            elif tag_number == TAG_PURPOSE:  # SET OF INTEGER
                parsed_props['purpose'] = [int(p) for p in value_component.getComponent()]
            elif tag_number == TAG_ALGORITHM: # INTEGER
                parsed_props['algorithm'] = int(value_component.getComponent())
            elif tag_number == TAG_EC_CURVE: # INTEGER
                parsed_props['ec_curve'] = int(value_component.getComponent())
            elif tag_number == TAG_RSA_PUBLIC_EXPONENT: # INTEGER
                parsed_props['rsa_public_exponent'] = int(value_component.getComponent())
            elif tag_number == TAG_MGF_DIGEST: # SET OF INTEGER
                 parsed_props['mgf_digest'] = [int(p) for p in value_component.getComponent()]
            elif tag_number == TAG_KEY_SIZE: # INTEGER
                parsed_props['key_size'] = int(value_component.getComponent())
            elif tag_number == TAG_NO_AUTH_REQUIRED:  # NULL
                parsed_props['no_auth_required'] = True
            elif tag_number == TAG_CREATION_DATETIME: # INTEGER
                parsed_props['creation_datetime'] = int(value_component.getComponent())
            elif tag_number == TAG_ORIGIN: # INTEGER
                parsed_props['origin'] = int(value_component.getComponent())
            elif tag_number == TAG_VENDOR_PATCH_LEVEL: # INTEGER
                parsed_props['vendor_patch_level'] = int(value_component.getComponent())
            elif tag_number == TAG_BOOT_PATCH_LEVEL: # INTEGER
                parsed_props['boot_patch_level'] = int(value_component.getComponent())
            elif tag_number == TAG_ATTESTATION_ID_BRAND: # OCTET_STRING
                parsed_props['attestation_id_brand'] = bytes(value_component.getComponent()).decode('utf-8', errors='replace')
            elif tag_number == TAG_ATTESTATION_ID_DEVICE: # OCTET_STRING
                parsed_props['attestation_id_device'] = bytes(value_component.getComponent()).decode('utf-8', errors='replace')
            elif tag_number == TAG_ATTESTATION_ID_PRODUCT: # OCTET_STRING
                parsed_props['attestation_id_product'] = bytes(value_component.getComponent()).decode('utf-8', errors='replace')
            elif tag_number == TAG_ATTESTATION_ID_SERIAL: # OCTET_STRING
                parsed_props['attestation_id_serial'] = bytes(value_component.getComponent()).decode('utf-8', errors='replace')
            elif tag_number == TAG_ATTESTATION_ID_MANUFACTURER: # OCTET_STRING
                parsed_props['attestation_id_manufacturer'] = bytes(value_component.getComponent()).decode('utf-8', errors='replace')
            elif tag_number == TAG_ATTESTATION_ID_MODEL: # OCTET_STRING
                parsed_props['attestation_id_model'] = bytes(value_component.getComponent()).decode('utf-8', errors='replace')
            elif tag_number == TAG_MODULE_HASH: # OCTET_STRING
                parsed_props['module_hash'] = base64.urlsafe_b64encode(bytes(value_component.getComponent())).decode()
            elif tag_number == TAG_ROOT_OF_TRUST: # SEQUENCE
                parsed_props['root_of_trust'] = parse_root_of_trust(value_component.getComponent())
            elif tag_number == TAG_PADDING: # SET OF INTEGER
                parsed_props['padding'] = [int(p) for p in value_component.getComponent()]
            elif tag_number == TAG_ROLLBACK_RESISTANCE: # NULL
                parsed_props['rollback_resistance'] = True
            elif tag_number == TAG_EARLY_BOOT_ONLY: # NULL
                parsed_props['early_boot_only'] = True
            elif tag_number == TAG_ACTIVE_DATETIME: # INTEGER
                parsed_props['active_datetime'] = int(value_component.getComponent())
            elif tag_number == TAG_ORIGINATION_EXPIRE_DATETIME: # INTEGER
                parsed_props['origination_expire_datetime'] = int(value_component.getComponent())
            elif tag_number == TAG_USAGE_EXPIRE_DATETIME: # INTEGER
                parsed_props['usage_expire_datetime'] = int(value_component.getComponent())
            elif tag_number == TAG_USAGE_COUNT_LIMIT: # INTEGER
                parsed_props['usage_count_limit'] = int(value_component.getComponent())
            elif tag_number == TAG_USER_AUTH_TYPE: # INTEGER (Bitmask)
                parsed_props['user_auth_type'] = int(value_component.getComponent())
            elif tag_number == TAG_AUTH_TIMEOUT: # INTEGER
                parsed_props['auth_timeout'] = int(value_component.getComponent())
            elif tag_number == TAG_ALLOW_WHILE_ON_BODY: # NULL
                parsed_props['allow_while_on_body'] = True
            elif tag_number == TAG_TRUSTED_USER_PRESENCE_REQUIRED: # NULL
                parsed_props['trusted_user_presence_required'] = True
            elif tag_number == TAG_TRUSTED_CONFIRMATION_REQUIRED: # NULL
                parsed_props['trusted_confirmation_required'] = True
            elif tag_number == TAG_UNLOCKED_DEVICE_REQUIRED: # NULL
                parsed_props['unlocked_device_required'] = True
            elif tag_number == TAG_ATTESTATION_ID_IMEI: # OCTET_STRING
                parsed_props['attestation_id_imei'] = bytes(value_component.getComponent()).decode('utf-8', errors='replace')
            elif tag_number == TAG_ATTESTATION_ID_MEID: # OCTET_STRING
                parsed_props['attestation_id_meid'] = bytes(value_component.getComponent()).decode('utf-8', errors='replace')
            elif tag_number == TAG_DEVICE_UNIQUE_ATTESTATION: # NULL
                parsed_props['device_unique_attestation'] = True
            elif tag_number == TAG_ATTESTATION_ID_SECOND_IMEI: # OCTET_STRING
                parsed_props['attestation_id_second_imei'] = bytes(value_component.getComponent()).decode('utf-8', errors='replace')
            else:
                logger.warning(f'Unknown tag in AuthorizationList: {tag_number}, value: {value_component.getComponent()}')
        except (PyAsn1Error, ValueError, TypeError) as e: # Added TypeError
            logger.warning(f'Error parsing tag {tag_number} in AuthorizationList: {e}. Value component: {value_component}')
    return parsed_props


def parse_key_description(key_desc_bytes):
    """
    Parses the KeyDescription SEQUENCE from the attestation extension using pyasn1.
    Returns a dictionary containing key properties.
    """
    try:
        key_desc_sequence, _ = der_decoder.decode(key_desc_bytes)
    except PyAsn1Error as e:
        logger.error(f'Failed to decode KeyDescription ASN.1 sequence with pyasn1: {e}') # Standardized
        raise ValueError('Malformed KeyDescription sequence.') # Standardized

    if not isinstance(key_desc_sequence, univ.Sequence):
        raise ValueError('Decoded KeyDescription is not an ASN.1 SEQUENCE.') # Standardized

    parsed_data = {}
    try:
        parsed_data['attestation_version'] = int(key_desc_sequence[0])
        parsed_data['attestation_security_level'] = int(key_desc_sequence[1])
        parsed_data['keymint_or_keymaster_version'] = int(key_desc_sequence[2])
        parsed_data['keymint_or_keymaster_security_level'] = int(key_desc_sequence[3])
        # Ensure the challenge is stored as bytes. - Retaining comment
        parsed_data['attestation_challenge'] = bytes(key_desc_sequence[4])

        idx = 5 # Start index for optional fields
        if len(key_desc_sequence) > idx and isinstance(key_desc_sequence[idx], univ.OctetString):
            parsed_data['unique_id'] = bytes(key_desc_sequence[idx]).hex()
            idx += 1
        else:
            parsed_data['unique_id'] = None # Explicitly set to None if not present

        if len(key_desc_sequence) > idx and isinstance(key_desc_sequence[idx], univ.Sequence): # Software enforced
            sw_enforced_seq = key_desc_sequence[idx]
            parsed_data['software_enforced'] = parse_authorization_list(sw_enforced_seq, parsed_data.get('attestation_version'))
            idx += 1
        else:
            parsed_data['software_enforced'] = {} # Default to empty dict

        if len(key_desc_sequence) > idx and isinstance(key_desc_sequence[idx], univ.Sequence): # Hardware enforced
            hw_enforced_seq = key_desc_sequence[idx]
            parsed_data['hardware_enforced'] = parse_authorization_list(hw_enforced_seq, parsed_data.get('attestation_version'))
            idx += 1
        else:
            parsed_data['hardware_enforced'] = {} # Default to empty dict

        # For Key Attestation v4 (attestation_version == 4), there's an optional `device_unique_attestation` field.
        # This field was added in Android S (KeyMint version 200).
        # The schema indicates it's a NULL type if present.
        if parsed_data.get('attestation_version') >= 4 and len(key_desc_sequence) > idx: # Check if field could exist
             if isinstance(key_desc_sequence[idx], univ.Null): # Check if it IS the NULL field
                parsed_data['device_unique_attestation'] = True
                # idx += 1 # Increment index if you expect more fields after this.
             # Else, if it's not Null, it might be an error or an unexpected field, or just not present.
             # The original code only set it if it was Null, which is correct.
    except (IndexError, ValueError, PyAsn1Error, TypeError) as e: # Added TypeError
        logger.error(f'Error processing parsed KeyDescription sequence: {e}. Structure might be unexpected.') # Standardized
        raise ValueError('Malformed or unexpected KeyDescription structure.') # Standardized
    return parsed_data

def get_attestation_extension_properties(certificate):
    """
    Finds and parses the Android Key Attestation extension from a certificate.
    Returns a dictionary of properties or None if not found/parsed.
    """
    try:
        ext = certificate.extensions.get_extension_for_oid(OID_ANDROID_KEY_ATTESTATION)
        if not ext:
            logger.warning('Android Key Attestation extension not found in certificate.') # Standardized
            return None
    except x509.ExtensionNotFound:
        logger.warning(f'Android Key Attestation extension (OID {OID_ANDROID_KEY_ATTESTATION}) not found.') # Standardized
        return None

    # The following logic for accessing ext.value.value or ext.value seems correct
    # based on how cryptography library handles recognized vs unrecognized extensions.
    if isinstance(ext.value, x509.UnrecognizedExtension):
        key_description_bytes = ext.value.value
    elif isinstance(ext.value, bytes): # Should be for recognized but DER-encoded extensions
        key_description_bytes = ext.value
    else:
        logger.error(f'Unexpected type for attestation extension value: {type(ext.value)}') # Standardized
        raise ValueError('Unexpected type for attestation extension value.') # Standardized

    if not key_description_bytes:
        logger.error('Attestation extension found but its value is empty.') # Standardized
        return None

    logger.info(f'KeyDescription length: {len(key_description_bytes)} bytes') # Was %i, now f-string
    try:
        attestation_properties = parse_key_description(key_description_bytes)
        return attestation_properties
    except ValueError as e: # This will catch errors from parse_key_description
        logger.error(f'Failed to parse KeyDescription from attestation extension: {e}') # Standardized
        raise # Re-raise to be handled by the caller

def cleanup_expired_sessions():
    """Removes expired key attestation session entities from Datastore."""
    if not datastore_client:
        logger.warning('Datastore client not available. Skipping cleanup of expired sessions.') # Standardized
        return
    try:
        expiry_time_check = datetime.now(timezone.utc) - timedelta(minutes=NONCE_EXPIRY_MINUTES)
        query = datastore_client.query(kind=KEY_ATTESTATION_SESSION_KIND)
        query.add_filter('generated_at', '<', expiry_time_check) # Filter by generated_at - Retaining
        expired_entities = list(query.fetch())
        if expired_entities:
            keys_to_delete = [entity.key for entity in expired_entities]
            datastore_client.delete_multi(keys_to_delete)
            logger.info(f'Cleaned up {len(keys_to_delete)} expired key attestation session entities.') # Standardized
        else:
            logger.info('No expired key attestation session entities found to cleanup.') # Standardized
    except Exception as e:
        logger.error(f'Error during Datastore cleanup of expired key attestation sessions: {e}') # Standardized

def cleanup_expired_agreement_sessions():
    """Removes expired agreement key attestation session entities from Datastore."""
    if not datastore_client:
        logger.warning('Datastore client not available. Skipping cleanup of expired agreement sessions.') # Standardized
        return
    try:
        expiry_time_check = datetime.now(timezone.utc) - timedelta(minutes=NONCE_EXPIRY_MINUTES)
        query = datastore_client.query(kind=AGREEMENT_KEY_ATTESTATION_SESSION_KIND)
        query.add_filter('generated_at', '<', expiry_time_check)
        expired_entities = list(query.fetch())
        if expired_entities:
            keys_to_delete = [entity.key for entity in expired_entities]
            datastore_client.delete_multi(keys_to_delete)
            logger.info(f'Cleaned up {len(keys_to_delete)} expired agreement key attestation session entities.') # Standardized
        else:
            logger.info('No expired agreement key attestation session entities found to cleanup.') # Standardized
    except Exception as e:
        logger.error(f'Error during Datastore cleanup of expired agreement key attestation sessions: {e}') # Standardized

def delete_key_attestation_session(session_id):
    """Deletes a specific key attestation session entity from Datastore."""
    if not datastore_client:
        logger.warning(f'Datastore client not available. Cannot delete session {session_id}.') # Standardized
        return # Or raise an error, depending on desired behavior - Retaining
    try:
        key = datastore_client.key(KEY_ATTESTATION_SESSION_KIND, session_id)
        datastore_client.delete(key)
        logger.info(f'Successfully deleted key attestation session for session_id: {session_id}') # Standardized
    except Exception as e:
        logger.error(f'Error deleting key attestation session {session_id} from Datastore: {e}') # Standardized
        # Optionally re-raise or handle more gracefully - Retaining

def delete_agreement_key_attestation_session(session_id):
    """Deletes a specific agreement key attestation session entity from Datastore."""
    if not datastore_client:
        logger.warning(f'Datastore client not available. Cannot delete agreement session {session_id}.') # Standardized
        return
    try:
        key = datastore_client.key(AGREEMENT_KEY_ATTESTATION_SESSION_KIND, session_id)
        datastore_client.delete(key)
        logger.info(f'Successfully deleted agreement key attestation session for session_id: {session_id}') # Standardized
    except Exception as e:
        logger.error(f'Error deleting agreement key attestation session {session_id} from Datastore: {e}') # Standardized

def store_key_attestation_result(session_id, result, reason, payload_data_json_str, attestation_data_json_str):
    """Stores the key attestation verification result in Datastore."""
    if not datastore_client:
        logger.error('Datastore client not available. Cannot store attestation result.') # Standardized
        # Depending on policy, might raise an error or just log and return - Retaining
        return
    try:
        # Use session_id as the key name for the entity for easy lookup if needed, - Retaining
        # or generate a unique ID if session_id might not be unique across all results - Retaining
        # (e.g., if a session can have multiple verification attempts). - Retaining
        # For simplicity, assuming session_id is sufficient for now. - Retaining
        key = datastore_client.key(KEY_ATTESTATION_RESULT_KIND, session_id)
        entity = datastore.Entity(key=key)
        entity.update({
            'session_id': session_id,
            'created_at': datetime.now(timezone.utc),
            'result': result,  # e.g., "verified", "failed" - Retaining
            'reason': reason,  # Detailed reason for failure, or success message - Retaining
            'payload_data': payload_data_json_str, # JSON string - Retaining
            'attestation_data': attestation_data_json_str # JSON string - Retaining
        })
        datastore_client.put(entity)
        logger.info(f'Stored key attestation result for session_id: {session_id}') # Standardized
    except Exception as e:
        logger.error(f'Failed to store key attestation result for session_id {session_id}: {e}') # Standardized

# --- Endpoints --- - Retaining

@app.route('/v1/prepare/signature', methods=['POST'])
def prepare_signature_attestation():
    """
    Prepares for key attestation signature by generating a nonce and challenge.
    Request body: { "session_id": "string" }
    Response body: { "nonce": "string (Base64URLEncoded)", "challenge": "string (Base64URLEncoded)" }
    """
    if not datastore_client:
        logger.error('Datastore client not available for /prepare endpoint.') # Standardized
        return jsonify({'error': 'Datastore service not available'}), 503

    try:
        data = request.get_json()
        if not data:
            logger.warning('Prepare request missing JSON payload.') # Standardized
            return jsonify({'error': 'Missing JSON payload'}), 400

        session_id = data.get('session_id')
        if not session_id or not isinstance(session_id, str) or not session_id.strip():
            logger.warning(f'Prepare request with invalid session_id: {session_id}') # Standardized
            return jsonify({'error': '\'session_id\' must be a non-empty string'}), 400

        nonce_bytes = generate_random_bytes()
        challenge_bytes = generate_random_bytes()
        nonce_encoded = base64url_encode(nonce_bytes)
        challenge_encoded = base64url_encode(challenge_bytes)

        try:
            store_key_attestation_session(session_id, nonce_encoded, challenge_encoded)
        except ConnectionError as e: # Catch if datastore_client was None during helper call - Retaining
             logger.error(f'Datastore connection error during store_key_attestation_session: {e}') # Standardized
             return jsonify({'error': 'Failed to store session due to datastore connectivity'}), 503
        except Exception as e:
            logger.error(f'Failed to store key attestation session for sessionId {session_id}: {e}') # Standardized
            return jsonify({'error': 'Failed to store session data'}), 500

        response_data = {
            'nonce': nonce_encoded,
            'challenge': challenge_encoded
        }
        logger.info(f'Successfully prepared attestation for sessionId: {session_id}') # Standardized
        return jsonify(response_data), 200
    except Exception as e:
        logger.error(f'Error in /prepare endpoint: {e}') # Standardized
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/v1/prepare/agreement', methods=['POST'])
def prepare_agreement_attestation():
    """
    Prepares for key attestation agreement by generating a salt and challenge.
    Request body: { "session_id": "string" }
    Response body: { "salt": "string (Base64URLEncoded)", "challenge": "string (Base64URLEncoded)", "public_key": "string (Base64URLEncoded, optional)" }
    """
    if not datastore_client:
        logger.error('Datastore client not available for /prepare/agreement endpoint.') # Standardized
        return jsonify({'error': 'Datastore service not available'}), 503

    try:
        data = request.get_json()
        if not data:
            logger.warning('Prepare agreement request missing JSON payload.') # Standardized
            return jsonify({'error': 'Missing JSON payload'}), 400

        session_id = data.get('session_id')
        if not session_id or not isinstance(session_id, str) or not session_id.strip():
            logger.warning(f'Prepare agreement request with invalid session_id: {session_id}') # Standardized
            return jsonify({'error': '\'session_id\' must be a non-empty string'}), 400

        salt_bytes = generate_random_bytes()
        challenge_bytes = generate_random_bytes()
        salt_encoded = base64url_encode(salt_bytes)
        challenge_encoded = base64url_encode(challenge_bytes)

        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo # Standard X.509 format - Retaining
        )
        public_key_encoded = base64url_encode(public_key_bytes)
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_encoded = base64url_encode(private_key_bytes)

        try:
            store_agreement_key_attestation_session(session_id, salt_encoded, challenge_encoded, public_key_encoded, private_key_encoded)
        except ConnectionError as e:
             logger.error(f'Datastore connection error during store_agreement_key_attestation_session: {e}') # Standardized
             return jsonify({'error': 'Failed to store session due to datastore connectivity'}), 503
        except Exception as e:
            logger.error(f'Failed to store agreement key attestation session for sessionId {session_id}: {e}') # Standardized
            return jsonify({'error': 'Failed to store session data'}), 500

        response_data = {
            'salt': salt_encoded,
            'challenge': challenge_encoded,
            'public_key': public_key_encoded
        }
        logger.info(f'Successfully prepared agreement attestation for sessionId: {session_id}') # Standardized
        return jsonify(response_data), 200
    except Exception as e:
        logger.error(f'Error in /prepare/agreement endpoint: {e}') # Standardized
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/v1/verify/signature', methods=['POST'])
def verify_signature_attestation():
    """
    Verifies the Key Attestation Signature. (Removed "(mock implementation)" as it is becoming real)
    Request body: { "session_id": "string", "signature": "string (Base64Encoded)", "client_nonce": "string (Base64Encoded)", "certificate_chain": ["string (Base64Encoded)"] }
    Response body: (details successful verification structure, errors are standard JSON)
    """
    try:
        data = request.get_json()
        if not data:
            logger.warning('Verify Signature request missing JSON payload.') # Standardized
            store_key_attestation_result('unknown_session', 'failed', 'Missing JSON payload', '{}', '{}')
            return jsonify({'error': 'Missing JSON payload'}), 400

        session_id = data.get('session_id')
        signature_b64 = data.get('signature')
        client_nonce_b64 = data.get('client_nonce')
        certificate_chain_b64 = data.get('certificate_chain')
        device_info_from_request = data.get('device_info', {})
        security_info_from_request = data.get('security_info', {})

        payload_data_for_datastore = {
            'device_info': device_info_from_request,
            'security_info': security_info_from_request
        }
        payload_data_json_str = json.dumps(payload_data_for_datastore)

        if not session_id:
            logger.warning('Verify Signature request missing session_id.') # Standardized
            store_key_attestation_result('missing_session_id', 'failed', 'Missing session_id in request', payload_data_json_str, '{}')
            return jsonify({'error': 'Missing \'session_id\''}), 400

        if not all([signature_b64, client_nonce_b64, certificate_chain_b64]):
            logger.warning(f'Verify Signature request for session \'{session_id}\' missing one or more required fields (signature, client_nonce, certificate_chain).') # Standardized
            store_key_attestation_result(session_id, 'failed', 'Missing one or more required fields: signature, client_nonce, certificate_chain', payload_data_json_str, '{}')
            return jsonify({'error': 'Missing one or more required fields: signature, client_nonce, certificate_chain'}), 400

        if not isinstance(session_id, str) or \
           not isinstance(signature_b64, str) or \
           not isinstance(client_nonce_b64, str) or \
           not isinstance(certificate_chain_b64, list) or \
           not all(isinstance(cert, str) for cert in certificate_chain_b64):
            logger.warning(f'Verify Signature request for session \'{session_id}\' has type mismatch for one or more fields.') # Standardized
            store_key_attestation_result(session_id, 'failed', 'Type mismatch for one or more fields.', payload_data_json_str, '{}')
            return jsonify({'error': 'Type mismatch for one or more fields. Ensure session_id, signature, client_nonce are strings and certificate_chain is a list of strings.'}), 400

        if not datastore_client:
            logger.error('Datastore client not available for /verify/signature endpoint.') # Standardized
            return jsonify({'error': 'Datastore service not available'}), 503

        session_entity = get_key_attestation_session(session_id)
        if not session_entity:
            logger.warning(f'Session ID \'{session_id}\' not found, expired, or invalid.') # Standardized
            store_key_attestation_result(session_id, 'failed', 'Session ID not found, expired, or invalid.', payload_data_json_str, '{}')
            return jsonify({'error': 'Session ID not found, expired, or invalid.'}), 403

        nonce_from_store_b64 = session_entity.get('nonce')
        challenge_from_store_b64 = session_entity.get('challenge')

        if not nonce_from_store_b64 or not challenge_from_store_b64:
            logger.error(f'Session \'{session_id}\' is missing nonce or challenge in Datastore.') # Standardized
            store_key_attestation_result(session_id, 'failed', 'Corrupted session data in Datastore.', payload_data_json_str, '{}')
            return jsonify({'error': 'Corrupted session data.'}), 500

        logger.info(f'Session validation successful for session_id: {session_id}') # Standardized
        attestation_properties = None

        try:
            certificates = decode_certificate_chain(certificate_chain_b64)
            logger.info(f'Successfully decoded certificate chain for session_id: {session_id}. Chain length: {len(certificates)}') # Standardized
        except ValueError as e:
            logger.warning(f'Failed to decode certificate chain for session {session_id}: {e}') # Standardized
            store_key_attestation_result(session_id, 'failed', f'Invalid certificate chain: {e}', payload_data_json_str, '{}')
            delete_key_attestation_session(session_id)
            return jsonify({'error': f'Invalid certificate chain: {e}'}), 400

        try:
            validate_attestation_signature(certificates[0], nonce_from_store_b64, client_nonce_b64, signature_b64) # Leaf certificate is certs[0]
            logger.info(f'Attestation signature validated successfully for session_id: {session_id}') # Standardized
        except ValueError as e:
            logger.warning(f'Attestation signature validation failed for session {session_id}: {e}') # Standardized
            store_key_attestation_result(session_id, 'failed', f'Attestation signature validation failed: {e}', payload_data_json_str, '{}')
            delete_key_attestation_session(session_id)
            return jsonify({'error': f'Attestation signature validation failed: {e}'}), 400

        try:
            verify_certificate_chain(certificates)
            logger.info(f'Certificate chain verified successfully for session_id: {session_id}') # Standardized
        except ValueError as e:
            logger.warning(f'Certificate chain verification failed for session {session_id}: {e}') # Standardized
            store_key_attestation_result(session_id, 'failed', f'Certificate chain verification failed: {e}', payload_data_json_str, '{}')
            delete_key_attestation_session(session_id)
            return jsonify({'error': f'Certificate chain verification failed: {e}'}), 400

        try:
            attestation_properties = get_attestation_extension_properties(certificates[0])
            if not attestation_properties or 'attestation_challenge' not in attestation_properties:
                logger.warning(f'Failed to parse attestation extension or missing challenge for session {session_id}.') # Standardized
                sanitized_att_props = convert_bytes_to_hex_str(attestation_properties or {})
                attestation_data_json_str = json.dumps(sanitized_att_props)
                store_key_attestation_result(session_id, 'failed', 'Failed to parse key attestation extension or attestation challenge not found.', payload_data_json_str, attestation_data_json_str)
                # delete_key_attestation_session(session_id) # User feedback was to keep session on this specific error
                return jsonify({'error': 'Failed to parse key attestation extension or attestation challenge not found.'}), 400
            logger.info(f'Successfully parsed attestation extension for session_id: {session_id}. Version: {attestation_properties.get("attestation_version")}') # Standardized
        except ValueError as e:
            logger.warning(f'ASN.1 parsing of attestation extension failed for session {session_id}: {e}') # Standardized
            sanitized_att_props = convert_bytes_to_hex_str(attestation_properties or {})
            attestation_data_json_str = json.dumps(sanitized_att_props)
            store_key_attestation_result(session_id, 'failed', f'ASN.1 parsing failed: {e}', payload_data_json_str, attestation_data_json_str)
            # delete_key_attestation_session(session_id) # User feedback was to keep session on this specific error
            return jsonify({'error': f'ASN.1 parsing failed: {e}'}), 400

        sanitized_att_props_for_error = convert_bytes_to_hex_str(attestation_properties or {})
        attestation_data_json_str_for_error = json.dumps(sanitized_att_props_for_error)

        try:
            challenge_from_store_bytes = base64url_decode(challenge_from_store_b64)
        except Exception as e:
            logger.error(f'Failed to base64url_decode challenge_from_store_b64 for session {session_id}: {e}') # Standardized
            store_key_attestation_result(session_id, 'failed', 'Internal server error: Could not decode stored challenge.', payload_data_json_str, attestation_data_json_str_for_error)
            return jsonify({'error': 'Internal server error: Could not decode stored challenge.'}), 500

        client_attestation_challenge_bytes = attestation_properties.get('attestation_challenge')

        if not client_attestation_challenge_bytes or \
           not hmac.compare_digest(challenge_from_store_bytes, client_attestation_challenge_bytes):
            logger.warning(f'Challenge mismatch for session {session_id}. Store (bytes_hex): \'{challenge_from_store_bytes.hex()}\', Cert (bytes_hex): \'{client_attestation_challenge_bytes.hex() if client_attestation_challenge_bytes else "None"}\'') # Standardized
            store_key_attestation_result(session_id, 'failed', 'Attestation challenge mismatch.', payload_data_json_str, attestation_data_json_str_for_error)
            delete_key_attestation_session(session_id)
            return jsonify({'error': 'Attestation challenge mismatch.'}), 400

        logger.info(f'Attestation challenge matched successfully for session_id: {session_id}') # Standardized
        attestation_challenge_b64url = base64url_encode(client_attestation_challenge_bytes)
        software_enforced_serializable = convert_bytes_to_hex_str(attestation_properties.get('software_enforced', {}))
        hardware_enforced_from_props = attestation_properties.get('hardware_enforced')
        hardware_enforced_serializable = convert_bytes_to_hex_str(hardware_enforced_from_props if hardware_enforced_from_props is not None else {})

        final_response = {
            'session_id': session_id,
            'is_verified': True,
            'reason': 'Key attestation verified successfully.',
            'attestation_info': {
                'attestation_version': attestation_properties.get('attestation_version'),
                'attestation_security_level': attestation_properties.get('attestation_security_level'),
                'keymint_version': attestation_properties.get('keymint_or_keymaster_version'),
                'keymint_security_level': attestation_properties.get('keymint_or_keymaster_security_level'),
                'attestation_challenge': attestation_challenge_b64url,
                'software_enforced_properties': software_enforced_serializable,
                'hardware_enforced_properties': hardware_enforced_serializable
            },
            'device_info': device_info_from_request,
            'security_info': security_info_from_request
        }

        attestation_data_for_datastore = {'attestation_info': final_response['attestation_info']}
        attestation_data_json_str_success = json.dumps(attestation_data_for_datastore)

        store_key_attestation_result(session_id, 'verified', final_response['reason'], payload_data_json_str, attestation_data_json_str_success)
        delete_key_attestation_session(session_id)

        logger.info(f'Successfully verified Key Attestation Signature for session_id: {session_id}') # Standardized
        return jsonify(final_response), 200
    except ValueError as e:
        current_session_id = locals().get('session_id', 'unknown_session_value_error')
        payload_str = locals().get('payload_data_json_str', '{}')
        raw_att_props = locals().get('attestation_properties') or {}
        sanitized_att_props = convert_bytes_to_hex_str(raw_att_props)
        att_props_str = json.dumps(sanitized_att_props)
        logger.warning(f'ValueError in /verify/signature for session {current_session_id}: {e}') # Standardized
        store_key_attestation_result(current_session_id, 'failed', str(e), payload_str, att_props_str)
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_session_id = locals().get('session_id', 'unknown_session_exception')
        payload_str = locals().get('payload_data_json_str', '{}')
        raw_att_props = locals().get('attestation_properties') or {}
        sanitized_att_props = convert_bytes_to_hex_str(raw_att_props)
        att_props_str = json.dumps(sanitized_att_props)
        logger.error(f'Error in /verify/signature endpoint for session {current_session_id}: {e}', exc_info=True) # Standardized
        store_key_attestation_result(current_session_id, 'failed', 'An unexpected error occurred.', payload_str, att_props_str)
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/v1/verify/agreement', methods=['POST'])
def verify_agreement_attestation():
    """
    Verifies the Key Attestation Agreement (mock implementation).
    Request body: {
        "session_id": "string",
        "encrypted_data": "string (Base64URL Encoded, no padding)",
        "client_public_key": "string (Base64 Encoded)",
        "device_info": {},
        "security_info": {}
    }
    Response body: {
        "session_id": "string",
        "is_verified": false,
        "reason": "string"
    }
    """
    try:
        data = request.get_json()
        if not data:
            logger.warning('Verify Agreement request missing JSON payload.') # Standardized
            store_key_attestation_result('unknown_session_agreement', 'failed', 'Missing JSON payload for agreement', '{}', '{}')
            return jsonify({'error': 'Missing JSON payload'}), 400

        session_id = data.get('session_id')
        encrypted_data_b64url = data.get('encrypted_data')
        client_public_key_b64 = data.get('client_public_key')
        device_info_from_request = data.get('device_info', {})
        security_info_from_request = data.get('security_info', {})

        payload_data_for_datastore = {
            'device_info': device_info_from_request,
            'security_info': security_info_from_request,
            'encrypted_data_provided': bool(encrypted_data_b64url),
            'client_public_key_provided': bool(client_public_key_b64)
        }
        payload_data_json_str = json.dumps(payload_data_for_datastore)

        if not session_id:
            logger.warning('Verify Agreement request missing session_id.') # Standardized
            store_key_attestation_result('missing_session_id_agreement', 'failed', 'Missing session_id in agreement request', payload_data_json_str, '{}')
            return jsonify({'error': 'Missing \'session_id\''}), 400

        if not all([encrypted_data_b64url, client_public_key_b64]):
            logger.warning(f'Verify Agreement request for session \'{session_id}\' missing encrypted_data or client_public_key.') # Standardized
            store_key_attestation_result(session_id, 'failed', 'Missing encrypted_data or client_public_key for agreement', payload_data_json_str, '{}')
            return jsonify({'error': 'Missing \'encrypted_data\' or \'client_public_key\''}), 400

        if not isinstance(session_id, str) or \
           not isinstance(encrypted_data_b64url, str) or \
           not isinstance(client_public_key_b64, str):
            logger.warning(f'Verify Agreement request for session \'{session_id}\' has type mismatch.') # Standardized
            store_key_attestation_result(session_id, 'failed', 'Type mismatch in agreement request fields.', payload_data_json_str, '{}')
            return jsonify({'error': 'Type mismatch for one or more fields.'}), 400

        if not datastore_client:
            logger.error('Datastore client not available for /verify/agreement endpoint.') # Standardized
            return jsonify({'error': 'Datastore service not available'}), 503

        # Mock verification logic: - Retaining this block of comments as it's informative
        # In a real scenario, you would:
        # 1. Retrieve the agreement session using session_id (get_agreement_key_attestation_session).
        # 2. Decode client_public_key_b64.
        # 3. Retrieve server's private key stored during prepare/agreement.
        # 4. Perform ECDH to derive a shared secret.
        # 5. Use the shared secret and salt (from session) to derive a decryption key (e.g., HKDF).
        # 6. Decode encrypted_data_b64url.
        # 7. Decrypt the data using the derived key.
        # 8. Verify the decrypted data (e.g., by checking a MAC or expected structure).
        # 9. For this mock, we'll just check if the session exists and then return a mock success.

        agreement_session_entity = get_agreement_key_attestation_session(session_id)
        if not agreement_session_entity:
            logger.warning(f'Agreement Session ID \'{session_id}\' not found, expired, or invalid for verify/agreement.') # Standardized
            store_key_attestation_result(session_id, 'failed', 'Agreement Session ID not found, expired, or invalid.', payload_data_json_str, '{}')
            return jsonify({'error': 'Agreement Session ID not found, expired, or invalid.'}), 403

        final_response = {
            'session_id': session_id,
            'is_verified': True,
            'reason': 'Key agreement verified successfully (mock).'
        }

        mock_internal_verification_details = {
            'verification_type': 'agreement_mock',
            'client_public_key_provided': bool(client_public_key_b64),
            'encrypted_data_provided': bool(encrypted_data_b64url)
        }
        attestation_data_json_str_success = json.dumps(mock_internal_verification_details)

        store_key_attestation_result(session_id, 'verified_agreement_mock', final_response['reason'], payload_data_json_str, attestation_data_json_str_success)
        delete_agreement_key_attestation_session(session_id)

        logger.info(f'Successfully verified Key Attestation Agreement (mock) for session_id: {session_id}') # Standardized
        return jsonify(final_response), 200
    except ValueError as e:
        current_session_id = locals().get('session_id', 'unknown_session_agreement_value_error')
        payload_str = locals().get('payload_data_json_str', '{}')
        logger.warning(f'ValueError in /verify/agreement for session {current_session_id}: {e}') # Standardized
        store_key_attestation_result(current_session_id, 'failed', str(e), payload_str, '{}')
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_session_id = locals().get('session_id', 'unknown_session_agreement_exception')
        payload_str = locals().get('payload_data_json_str', '{}')
        logger.error(f'Error in /verify/agreement endpoint for session {current_session_id}: {e}', exc_info=True) # Standardized
        store_key_attestation_result(current_session_id, 'failed', 'An unexpected error occurred during agreement verification.', payload_str, '{}')
        return jsonify({'error': 'An unexpected error occurred'}), 500

if __name__ == '__main__':
    # This is used when running locally only.
    # When deploying to Google App Engine, a webserver process such as Gunicorn will serve the app.
    # This can be configured by adding an `entrypoint` to app.yaml.
    # The PORT environment variable is provided by App Engine.
    port = int(os.environ.get('PORT', 8081))
    app.run(host='0.0.0.0', port=port, debug=True)
