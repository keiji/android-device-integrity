import base64
import os
import json
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify
from google.cloud import datastore
import logging
import hmac
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding as asym_padding
from cryptography.exceptions import InvalidSignature
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type import univ
from pyasn1.error import PyAsn1Error

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    datastore_client = datastore.Client()
    logger.info('Datastore client initialized successfully.')
except Exception as e:
    logger.error(f'Failed to initialize Datastore client: {e}')
    datastore_client = None

KEY_ATTESTATION_SESSION_KIND = 'SignatureKeyAttestationSession'
AGREEMENT_KEY_ATTESTATION_SESSION_KIND = 'AgreementKeyAttestationSession'
KEY_ATTESTATION_RESULT_KIND = 'KeyAttestationResult'
NONCE_EXPIRY_MINUTES = 10

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
        logger.error('Datastore client not available. Cannot store session.')
        raise ConnectionError('Datastore client not initialized.')

    now = datetime.now(timezone.utc)

    key = datastore_client.key(KEY_ATTESTATION_SESSION_KIND, session_id)
    entity = datastore.Entity(key=key)
    entity.update({
        'session_id': session_id,
        'nonce': nonce_encoded,
        'challenge': challenge_encoded,
        'generated_at': now,
    })
    datastore_client.put(entity)
    logger.info(f'Stored key attestation session for session_id: {session_id}')
    # Consider calling cleanup_expired_sessions() here or via a scheduled job
    cleanup_expired_sessions()

def store_agreement_key_attestation_session(session_id, salt_encoded, challenge_encoded, public_key_encoded=None, private_key_encoded=None):
    """
    Stores the agreement key attestation session data in Datastore.
    The entity key will be the session_id to ensure uniqueness and allow easy lookup.
    """
    if not datastore_client:
        logger.error('Datastore client not available. Cannot store session.')
        raise ConnectionError('Datastore client not initialized.')

    now = datetime.now(timezone.utc)

    key = datastore_client.key(AGREEMENT_KEY_ATTESTATION_SESSION_KIND, session_id)
    entity = datastore.Entity(key=key)
    entity.update({
        'session_id': session_id,
        'salt': salt_encoded,
        'challenge': challenge_encoded,
        'generated_at': now,
    })
    if public_key_encoded:
        entity['public_key'] = public_key_encoded
    if private_key_encoded:
        entity['private_key'] = private_key_encoded

    datastore_client.put(entity)
    logger.info(f'Stored agreement key attestation session for session_id: {session_id}')
    # Consider calling cleanup_expired_agreement_sessions() here or via a scheduled job
    cleanup_expired_agreement_sessions()


def get_key_attestation_session(session_id):
    """
    Retrieves and validates key attestation session data from Datastore.
    Returns the session entity if valid and not expired, otherwise None.
    """
    if not datastore_client:
        logger.error('Datastore client not available. Cannot retrieve session.')
        # Consider raising an exception here if this is an unrecoverable state
        return None

    key = datastore_client.key(KEY_ATTESTATION_SESSION_KIND, session_id)
    entity = datastore_client.get(key)

    if not entity:
        logger.warning(f'Session not found for session_id: {session_id}')
        return None

    # Check for expiration
    generated_at = entity.get('generated_at')
    if not generated_at: # Should not happen if stored correctly
        logger.error(f'Session {session_id} is missing \'generated_at\' timestamp.')
        return None

    # Ensure generated_at is offset-aware for comparison
    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=timezone.utc)

    expiry_datetime = generated_at + timedelta(minutes=NONCE_EXPIRY_MINUTES)
    if datetime.now(timezone.utc) > expiry_datetime:
        logger.warning(f'Session expired for session_id: {session_id}. Generated at: {generated_at}, Expired at: {expiry_datetime}')
        # Optionally delete the expired entity here or rely on cleanup_expired_sessions
        return None

    logger.info(f'Successfully retrieved and validated session for session_id: {session_id}')
    return entity

def get_agreement_key_attestation_session(session_id):
    """
    Retrieves and validates agreement key attestation session data from Datastore.
    Returns the session entity if valid and not expired, otherwise None.
    """
    if not datastore_client:
        logger.error('Datastore client not available. Cannot retrieve session.')
        return None

    key = datastore_client.key(AGREEMENT_KEY_ATTESTATION_SESSION_KIND, session_id)
    entity = datastore_client.get(key)

    if not entity:
        logger.warning(f'Agreement session not found for session_id: {session_id}')
        return None

    generated_at = entity.get('generated_at')
    if not generated_at:
        logger.error(f'Agreement session {session_id} is missing \'generated_at\' timestamp.')
        return None

    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=timezone.utc)

    expiry_datetime = generated_at + timedelta(minutes=NONCE_EXPIRY_MINUTES) # Using NONCE_EXPIRY_MINUTES for salt too
    if datetime.now(timezone.utc) > expiry_datetime:
        logger.warning(f'Agreement session expired for session_id: {session_id}. Generated at: {generated_at}, Expired at: {expiry_datetime}')
        return None

    logger.info(f'Successfully retrieved and validated agreement session for session_id: {session_id}')
    return entity

def decode_certificate_chain(certificate_chain_b64):
    """
    Decodes a list of Base64 encoded certificate strings into a list of X509Certificate objects.
    """
    decoded_certs = []
    for i, cert_b64 in enumerate(certificate_chain_b64):
        try:
            cert_bytes = base64.b64decode(cert_b64) # Rely on b64decode to handle padding
            cert = x509.load_der_x509_certificate(cert_bytes)
            decoded_certs.append(cert)
        except ValueError as e: # Handles errors from b64decode if input is invalid
            logger.error(f'Failed to decode Base64 certificate at index {i}: {e}')
            raise ValueError(f'Invalid Base64 certificate string at index {i}')
        except TypeError as e: # Handles errors from b64decode if input is not string-like
            logger.error(f'Type error during Base64 decoding for certificate at index {i}: {e}')
            raise ValueError(f'Invalid type for Base64 certificate string at index {i}')
        except Exception as e: # Catch other cryptography parsing errors or unexpected issues
            logger.error(f'Error loading certificate at index {i} into X509 object: {e}')
            raise ValueError(f'Cannot parse certificate at index {i} into X509 object')
    if not decoded_certs:
        raise ValueError('Certificate chain is empty after decoding.')
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
        logger.error(f'Failed to base64url_decode one of the signature components: {e}')
        raise ValueError('Invalid base64url encoding for nonce, nonce_b, or signature.')

    signed_data_bytes = nonce_from_store_bytes + nonce_b_bytes
    public_key = leaf_certificate.public_key()

    try:
        # Assuming EC public key
        # For EC keys, verify() expects the raw signature bytes (r and s concatenated).
        # The hash algorithm is typically SHA256 for Android Key Attestation with EC.
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature_bytes,
                signed_data_bytes,
                ec.ECDSA(hashes.SHA256()) # Assuming SHA256, common for attestation
            )
            logger.info('Attestation signature validated successfully.')
            return True
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature_bytes,
                signed_data_bytes,
                asym_padding.PKCS1v15(), # Or PSS, depending on what client uses
                hashes.SHA256()
            )
            logger.info('Attestation signature validated successfully (RSA).')
            return True
        else:
            logger.error(f'Unsupported public key type for signature verification: {type(public_key)}')
            raise ValueError('Unsupported public key type in leaf certificate for signature verification.')
    except InvalidSignature:
        logger.warning('Attestation signature verification failed: InvalidSignature.')
        raise ValueError('Attestation signature verification failed.')
    except Exception as e:
        logger.error(f'Error during attestation signature verification: {e}')
        raise ValueError(f'An unexpected error occurred during signature verification: {e}')

def verify_certificate_chain(certificates):
    """
    Verifies the certificate chain.
    - Each certificate (except the last) is signed by the next certificate in the chain.
    - Does not verify the root against a trust store (as per requirements).
    """
    if len(certificates) < 1: # Should have been caught by decode_certificate_chain
        raise ValueError('Certificate chain is empty, cannot verify.')
    if len(certificates) == 1:
        # Single certificate in chain (self-signed or needs external trust anchor).
        # For attestation, usually there's at least a leaf and an attestation CA.
        # Depending on policy, a single cert might be acceptable if it's a known attestation root,
        # but the requirement is to verify chain signatures if multiple certs exist.
        # For now, we consider a single cert chain as "verified" in terms of its internal links.
        logger.info('Certificate chain has only one certificate. No internal chain validation to perform.')
        return True

    for i in range(len(certificates) - 1):
        subject_cert = certificates[i]
        issuer_cert = certificates[i+1]
        issuer_public_key = issuer_cert.public_key()

        try:
            # The signature hash algorithm is part of the subject_cert.signature_hash_algorithm
            # The public key algorithm from issuer_public_key and signature algorithm from subject_cert
            # are used by the verify() method.
            if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                issuer_public_key.verify(
                    subject_cert.signature,
                    subject_cert.tbs_certificate_bytes,
                    ec.ECDSA(subject_cert.signature_hash_algorithm) # Use hash algorithm from subject cert
                )
            elif isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(
                    subject_cert.signature,
                    subject_cert.tbs_certificate_bytes,
                    asym_padding.PKCS1v15(), # Assuming PKCS1v15 for cert signatures
                    subject_cert.signature_hash_algorithm
                )
            else:
                logger.error(f'Unsupported public key type in issuer certificate for chain validation: {type(issuer_public_key)}')
                raise ValueError(f'Certificate chain validation failed: Unsupported public key type in issuer certificate at index {i+1}.')

            logger.info(f'Verified certificate {i}\'s signature with certificate {i+1}\'s public key.')
        except InvalidSignature:
            logger.warning(f'Certificate chain validation failed: Cert {i} not signed by cert {i+1}.')
            raise ValueError(f'Certificate chain validation failed: Certificate at index {i} is not signed by certificate at index {i+1}.')
        except Exception as e:
            logger.error(f'Error during certificate chain validation (cert {i} by cert {i+1}): {e}')
            raise ValueError(f'An unexpected error occurred during certificate chain validation: {e}')

    logger.info('Certificate chain verified successfully.')
    return True

# --- ASN.1 Constants and Parsing ---
# OID for Android Key Attestation extension
OID_ANDROID_KEY_ATTESTATION = x509.ObjectIdentifier('1.3.6.1.4.1.11129.2.1.17')

# AuthorizationList tags (from Keymaster/KeyMint documentation)
# https://source.android.com/docs/security/features/keystore/attestation?hl=ja#schema
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
TAG_ATTESTATION_APPLICATION_ID = 709  # KeyMint v2+
TAG_ATTESTATION_ID_BRAND = 710  # KeyMint v2+
TAG_ATTESTATION_ID_DEVICE = 711  # KeyMint v2+
TAG_ATTESTATION_ID_PRODUCT = 712
TAG_ATTESTATION_ID_SERIAL = 713
TAG_ATTESTATION_ID_IMEI = 714
TAG_ATTESTATION_ID_MEID = 715
TAG_ATTESTATION_ID_MANUFACTURER = 716
TAG_ATTESTATION_ID_MODEL = 717
TAG_VENDOR_PATCH_LEVEL = 718
TAG_BOOT_PATCH_LEVEL = 719
TAG_DEVICE_UNIQUE_ATTESTATION = 720
TAG_ATTESTATION_ID_SECOND_IMEI = 723
TAG_MODULE_HASH = 724
# ... and many more

def parse_root_of_trust(root_of_trust_sequence):
    """Parses the RootOfTrust ASN.1 sequence."""
    parsed_data = {}
    if not isinstance(root_of_trust_sequence, univ.Sequence):
        return parsed_data
    parsed_data['verified_boot_key'] = bytes(root_of_trust_sequence[0]).hex()
    parsed_data['device_locked'] = bool(root_of_trust_sequence[1])
    parsed_data['verified_boot_state'] = int(root_of_trust_sequence[2])
    parsed_data['verified_boot_hash'] = bytes(root_of_trust_sequence[3]).hex()
    return parsed_data

def parse_attestation_application_id(attestation_application_id_bytes):
    """
    Parses the AttestationApplicationId field from an OCTET STRING.
    The OCTET STRING itself contains an ASN.1 encoded structure.
    ref: https://source.android.com/docs/security/features/keystore/attestation#attestation-app-id
    AttestationApplicationId ::= SEQUENCE {
        packageInfos  SET OF PackageInfo,
        signatureDigests SET OF OCTET_STRING,
    }
    PackageInfo ::= SEQUENCE {
        packageName  UTF8String,
        version  INTEGER,
    }
    """
    try:
        # The input attestation_application_id_bytes is the payload of TAG_ATTESTATION_APPLICATION_ID (an OCTET STRING)
        # This payload itself needs to be decoded as a SEQUENCE (AttestationApplicationId)
        app_id_seq, _ = der_decoder.decode(attestation_application_id_bytes)
    except PyAsn1Error as e:
        logger.error(f'Failed to decode AttestationApplicationId inner sequence: {e}')
        raise ValueError('Malformed AttestationApplicationId inner sequence.')

    if not isinstance(app_id_seq, univ.Sequence) or len(app_id_seq) < 2:
        logger.error('AttestationApplicationId is not a SEQUENCE or has too few elements.')
        raise ValueError('AttestationApplicationId not a valid SEQUENCE.')

    parsed_data = {'package_infos': [], 'signature_digests': []}

    package_infos_set = app_id_seq[0]
    if isinstance(package_infos_set, univ.SetOf):
        for package_info_seq in package_infos_set:
            if isinstance(package_info_seq, univ.Sequence) and len(package_info_seq) == 2:
                pkg_name = str(package_info_seq[0])
                pkg_version = int(package_info_seq[1])
                parsed_data['package_infos'].append({'package_name': pkg_name, 'version': pkg_version})
            else:
                logger.warning(f'Malformed PackageInfo entry in AttestationApplicationId: {package_info_seq}')
    else:
        logger.warning('packageInfos is not a SetOf in AttestationApplicationId.')

    signature_digests_set = app_id_seq[1]
    if isinstance(signature_digests_set, univ.SetOf):
        for sig_digest_octet_str in signature_digests_set:
            if isinstance(sig_digest_octet_str, univ.OctetString):
                parsed_data['signature_digests'].append(bytes(sig_digest_octet_str).hex())
            else:
                 logger.warning(f'Malformed signatureDigest entry in AttestationApplicationId: {sig_digest_octet_str}')
    else:
        logger.warning('signatureDigests is not a SetOf in AttestationApplicationId.')

    return parsed_data


def parse_authorization_list(auth_list_sequence, attestation_version):
    """
    Parses an AuthorizationList SEQUENCE using pyasn1.
    Returns a dictionary of parsed properties.
    """
    parsed_props = {}
    if not isinstance(auth_list_sequence, univ.Sequence):
        return parsed_props

    for item_value_pair in auth_list_sequence:
        try:
            if not hasattr(item_value_pair, 'tagSet') or not item_value_pair.tagSet:
                 logger.warning(f'Skipping item in AuthorizationList without a proper tagSet: {item_value_pair}')
                 continue
            tag_number = item_value_pair.tagSet.tagId
            value_component = item_value_pair
        except (AttributeError, IndexError, TypeError):
            logger.warning(f'Could not get tag or value from auth list item: {item_value_pair}')
            continue

        try:
            if tag_number == TAG_ATTESTATION_APPLICATION_ID:
                app_id_bytes = bytes(value_component.getComponent())
                parsed_props['attestation_application_id'] = parse_attestation_application_id(app_id_bytes)
            elif tag_number == TAG_OS_VERSION:
                parsed_props['os_version'] = int(value_component.getComponent())
            elif tag_number == TAG_OS_PATCH_LEVEL:
                parsed_props['os_patch_level'] = int(value_component.getComponent())
            elif tag_number == TAG_DIGEST:
                parsed_props['digests'] = [int(p) for p in value_component.getComponent()]
            elif tag_number == TAG_PURPOSE:
                parsed_props['purpose'] = [int(p) for p in value_component.getComponent()]
            elif tag_number == TAG_ALGORITHM:
                parsed_props['algorithm'] = int(value_component.getComponent())
            elif tag_number == TAG_EC_CURVE:
                parsed_props['ec_curve'] = int(value_component.getComponent())
            elif tag_number == TAG_RSA_PUBLIC_EXPONENT:
                parsed_props['rsa_public_exponent'] = int(value_component.getComponent())
            elif tag_number == TAG_MGF_DIGEST:
                 parsed_props['mgf_digest'] = [int(p) for p in value_component.getComponent()]
            elif tag_number == TAG_KEY_SIZE:
                parsed_props['key_size'] = int(value_component.getComponent())
            elif tag_number == TAG_NO_AUTH_REQUIRED:
                parsed_props['no_auth_required'] = True
            elif tag_number == TAG_CREATION_DATETIME:
                parsed_props['creation_datetime'] = int(value_component.getComponent())
            elif tag_number == TAG_ORIGIN:
                parsed_props['origin'] = int(value_component.getComponent())
            elif tag_number == TAG_VENDOR_PATCH_LEVEL:
                parsed_props['vendor_patch_level'] = int(value_component.getComponent())
            elif tag_number == TAG_BOOT_PATCH_LEVEL:
                parsed_props['boot_patch_level'] = int(value_component.getComponent())
            elif tag_number == TAG_ATTESTATION_ID_BRAND:
                parsed_props['attestation_id_brand'] = bytes(value_component.getComponent()).decode('utf-8', errors='replace')
            elif tag_number == TAG_ATTESTATION_ID_DEVICE:
                parsed_props['attestation_id_device'] = bytes(value_component.getComponent()).decode('utf-8', errors='replace')
            elif tag_number == TAG_ATTESTATION_ID_PRODUCT:
                parsed_props['attestation_id_product'] = bytes(value_component.getComponent()).decode('utf-8', errors='replace')
            elif tag_number == TAG_ATTESTATION_ID_SERIAL:
                parsed_props['attestation_id_serial'] = bytes(value_component.getComponent()).decode('utf-8', errors='replace')
            elif tag_number == TAG_ATTESTATION_ID_MANUFACTURER:
                parsed_props['attestation_id_manufacturer'] = bytes(value_component.getComponent()).decode('utf-8', errors='replace')
            elif tag_number == TAG_ATTESTATION_ID_MODEL:
                parsed_props['attestation_id_model'] = bytes(value_component.getComponent()).decode('utf-8', errors='replace')
            elif tag_number == TAG_MODULE_HASH:
                parsed_props['module_hash'] = base64.urlsafe_b64encode(bytes(value_component.getComponent())).decode()
            elif tag_number == TAG_ROOT_OF_TRUST:
                parsed_props['root_of_trust'] = parse_root_of_trust(value_component.getComponent())
            elif tag_number == TAG_PADDING:
                parsed_props['padding'] = [int(p) for p in value_component.getComponent()]
            elif tag_number == TAG_ROLLBACK_RESISTANCE:
                parsed_props['rollback_resistance'] = True
            elif tag_number == TAG_EARLY_BOOT_ONLY:
                parsed_props['early_boot_only'] = True
            elif tag_number == TAG_ACTIVE_DATETIME:
                parsed_props['active_datetime'] = int(value_component.getComponent())
            elif tag_number == TAG_ORIGINATION_EXPIRE_DATETIME:
                parsed_props['origination_expire_datetime'] = int(value_component.getComponent())
            elif tag_number == TAG_USAGE_EXPIRE_DATETIME:
                parsed_props['usage_expire_datetime'] = int(value_component.getComponent())
            elif tag_number == TAG_USAGE_COUNT_LIMIT:
                parsed_props['usage_count_limit'] = int(value_component.getComponent())
            elif tag_number == TAG_USER_AUTH_TYPE:
                parsed_props['user_auth_type'] = int(value_component.getComponent())
            elif tag_number == TAG_AUTH_TIMEOUT:
                parsed_props['auth_timeout'] = int(value_component.getComponent())
            elif tag_number == TAG_ALLOW_WHILE_ON_BODY:
                parsed_props['allow_while_on_body'] = True
            elif tag_number == TAG_TRUSTED_USER_PRESENCE_REQUIRED:
                parsed_props['trusted_user_presence_required'] = True
            elif tag_number == TAG_TRUSTED_CONFIRMATION_REQUIRED:
                parsed_props['trusted_confirmation_required'] = True
            elif tag_number == TAG_UNLOCKED_DEVICE_REQUIRED:
                parsed_props['unlocked_device_required'] = True
            elif tag_number == TAG_ATTESTATION_ID_IMEI:
                parsed_props['attestation_id_imei'] = bytes(value_component.getComponent()).decode('utf-8', errors='replace')
            elif tag_number == TAG_ATTESTATION_ID_MEID:
                parsed_props['attestation_id_meid'] = bytes(value_component.getComponent()).decode('utf-8', errors='replace')
            elif tag_number == TAG_DEVICE_UNIQUE_ATTESTATION:
                parsed_props['device_unique_attestation'] = True
            elif tag_number == TAG_ATTESTATION_ID_SECOND_IMEI:
                parsed_props['attestation_id_second_imei'] = bytes(value_component.getComponent()).decode('utf-8', errors='replace')
            else:
                logger.warning(f'Unknown tag in AuthorizationList: {tag_number}, value: {value_component.getComponent()}')
        except (PyAsn1Error, ValueError, TypeError) as e:
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
        logger.error(f'Failed to decode KeyDescription ASN.1 sequence with pyasn1: {e}')
        raise ValueError('Malformed KeyDescription sequence.')

    if not isinstance(key_desc_sequence, univ.Sequence):
        raise ValueError('Decoded KeyDescription is not an ASN.1 SEQUENCE.')

    parsed_data = {}
    try:
        parsed_data['attestation_version'] = int(key_desc_sequence[0])
        parsed_data['attestation_security_level'] = int(key_desc_sequence[1])
        parsed_data['keymint_or_keymaster_version'] = int(key_desc_sequence[2])
        parsed_data['keymint_or_keymaster_security_level'] = int(key_desc_sequence[3])
        # Ensure the challenge is stored as bytes.
        parsed_data['attestation_challenge'] = bytes(key_desc_sequence[4])

        idx = 5
        if len(key_desc_sequence) > idx and isinstance(key_desc_sequence[idx], univ.OctetString):
            parsed_data['unique_id'] = bytes(key_desc_sequence[idx]).hex()
            idx += 1
        else:
            parsed_data['unique_id'] = None

        if len(key_desc_sequence) > idx and isinstance(key_desc_sequence[idx], univ.Sequence):
            sw_enforced_seq = key_desc_sequence[idx]
            parsed_data['software_enforced'] = parse_authorization_list(sw_enforced_seq, parsed_data.get('attestation_version'))
            idx += 1
        else:
            parsed_data['software_enforced'] = {}

        if len(key_desc_sequence) > idx and isinstance(key_desc_sequence[idx], univ.Sequence):
            hw_enforced_seq = key_desc_sequence[idx]
            parsed_data['hardware_enforced'] = parse_authorization_list(hw_enforced_seq, parsed_data.get('attestation_version'))
            idx += 1
        else:
            parsed_data['hardware_enforced'] = {}

        if parsed_data.get('attestation_version') >= 4 and len(key_desc_sequence) > idx:
             if isinstance(key_desc_sequence[idx], univ.Null):
                parsed_data['device_unique_attestation'] = True
    except (IndexError, ValueError, PyAsn1Error, TypeError) as e:
        logger.error(f'Error processing parsed KeyDescription sequence: {e}. Structure might be unexpected.')
        raise ValueError('Malformed or unexpected KeyDescription structure.')
    return parsed_data

def get_attestation_extension_properties(certificate):
    """
    Finds and parses the Android Key Attestation extension from a certificate.
    Returns a dictionary of properties or None if not found/parsed.
    """
    try:
        ext = certificate.extensions.get_extension_for_oid(OID_ANDROID_KEY_ATTESTATION)
        if not ext:
            logger.warning('Android Key Attestation extension not found in certificate.')
            return None
    except x509.ExtensionNotFound:
        logger.warning(f'Android Key Attestation extension (OID {OID_ANDROID_KEY_ATTESTATION}) not found.')
        return None

    if isinstance(ext.value, x509.UnrecognizedExtension):
        key_description_bytes = ext.value.value
    elif isinstance(ext.value, bytes):
        key_description_bytes = ext.value
    else:
        logger.error(f'Unexpected type for attestation extension value: {type(ext.value)}')
        raise ValueError('Unexpected type for attestation extension value.')

    if not key_description_bytes:
        logger.error('Attestation extension found but its value is empty.')
        return None

    logger.info(f'KeyDescription length: {len(key_description_bytes)} bytes')
    try:
        attestation_properties = parse_key_description(key_description_bytes)
        return attestation_properties
    except ValueError as e:
        logger.error(f'Failed to parse KeyDescription from attestation extension: {e}')
        raise

def cleanup_expired_sessions():
    """Removes expired key attestation session entities from Datastore."""
    if not datastore_client:
        logger.warning('Datastore client not available. Skipping cleanup of expired sessions.')
        return
    try:
        expiry_time_check = datetime.now(timezone.utc) - timedelta(minutes=NONCE_EXPIRY_MINUTES)
        query = datastore_client.query(kind=KEY_ATTESTATION_SESSION_KIND)
        query.add_filter('generated_at', '<', expiry_time_check)
        expired_entities = list(query.fetch())
        if expired_entities:
            keys_to_delete = [entity.key for entity in expired_entities]
            datastore_client.delete_multi(keys_to_delete)
            logger.info(f'Cleaned up {len(keys_to_delete)} expired key attestation session entities.')
        else:
            logger.info('No expired key attestation session entities found to cleanup.')
    except Exception as e:
        logger.error(f'Error during Datastore cleanup of expired key attestation sessions: {e}')

def cleanup_expired_agreement_sessions():
    """Removes expired agreement key attestation session entities from Datastore."""
    if not datastore_client:
        logger.warning('Datastore client not available. Skipping cleanup of expired agreement sessions.')
        return
    try:
        expiry_time_check = datetime.now(timezone.utc) - timedelta(minutes=NONCE_EXPIRY_MINUTES)
        query = datastore_client.query(kind=AGREEMENT_KEY_ATTESTATION_SESSION_KIND)
        query.add_filter('generated_at', '<', expiry_time_check)
        expired_entities = list(query.fetch())
        if expired_entities:
            keys_to_delete = [entity.key for entity in expired_entities]
            datastore_client.delete_multi(keys_to_delete)
            logger.info(f'Cleaned up {len(keys_to_delete)} expired agreement key attestation session entities.')
        else:
            logger.info('No expired agreement key attestation session entities found to cleanup.')
    except Exception as e:
        logger.error(f'Error during Datastore cleanup of expired agreement key attestation sessions: {e}')

def delete_key_attestation_session(session_id):
    """Deletes a specific key attestation session entity from Datastore."""
    if not datastore_client:
        logger.warning(f'Datastore client not available. Cannot delete session {session_id}.')
        return # Or raise an error, depending on desired behavior
    try:
        key = datastore_client.key(KEY_ATTESTATION_SESSION_KIND, session_id)
        datastore_client.delete(key)
        logger.info(f'Successfully deleted key attestation session for session_id: {session_id}')
    except Exception as e:
        logger.error(f'Error deleting key attestation session {session_id} from Datastore: {e}')
        # Optionally re-raise or handle more gracefully

def delete_agreement_key_attestation_session(session_id):
    """Deletes a specific agreement key attestation session entity from Datastore."""
    if not datastore_client:
        logger.warning(f'Datastore client not available. Cannot delete agreement session {session_id}.')
        return
    try:
        key = datastore_client.key(AGREEMENT_KEY_ATTESTATION_SESSION_KIND, session_id)
        datastore_client.delete(key)
        logger.info(f'Successfully deleted agreement key attestation session for session_id: {session_id}')
    except Exception as e:
        logger.error(f'Error deleting agreement key attestation session {session_id} from Datastore: {e}')

def store_key_attestation_result(session_id, result, reason, payload_data_json_str, attestation_data_json_str):
    """Stores the key attestation verification result in Datastore."""
    if not datastore_client:
        logger.error('Datastore client not available. Cannot store attestation result.')
        # Depending on policy, might raise an error or just log and return
        return
    try:
        # Use session_id as the key name for the entity for easy lookup if needed,
        # or generate a unique ID if session_id might not be unique across all results
        # (e.g., if a session can have multiple verification attempts).
        # For simplicity, assuming session_id is sufficient for now.
        key = datastore_client.key(KEY_ATTESTATION_RESULT_KIND, session_id)
        entity = datastore.Entity(key=key)
        entity.update({
            'session_id': session_id,
            'created_at': datetime.now(timezone.utc),
            'result': result,  # e.g., "verified", "failed"
            'reason': reason,  # Detailed reason for failure, or success message
            'payload_data': payload_data_json_str, # JSON string
            'attestation_data': attestation_data_json_str # JSON string
        })
        datastore_client.put(entity)
        logger.info(f'Stored key attestation result for session_id: {session_id}')
    except Exception as e:
        logger.error(f'Failed to store key attestation result for session_id {session_id}: {e}')

# --- Endpoints ---

@app.route('/v1/prepare/signature', methods=['POST'])
def prepare_signature_attestation():
    """
    Prepares for key attestation signature by generating a nonce and challenge.
    Request body: { "session_id": "string" }
    Response body: { "nonce": "string (Base64URLEncoded)", "challenge": "string (Base64URLEncoded)" }
    """
    if not datastore_client:
        logger.error('Datastore client not available for /prepare endpoint.')
        return jsonify({'error': 'Datastore service not available'}), 503

    try:
        data = request.get_json()
        if not data:
            logger.warning('Prepare request missing JSON payload.')
            return jsonify({'error': 'Missing JSON payload'}), 400

        session_id = data.get('session_id')
        if not session_id or not isinstance(session_id, str) or not session_id.strip():
            logger.warning(f'Prepare request with invalid session_id: {session_id}')
            return jsonify({'error': '\'session_id\' must be a non-empty string'}), 400

        nonce_bytes = generate_random_bytes()
        challenge_bytes = generate_random_bytes()
        nonce_encoded = base64url_encode(nonce_bytes)
        challenge_encoded = base64url_encode(challenge_bytes)

        try:
            store_key_attestation_session(session_id, nonce_encoded, challenge_encoded)
        except ConnectionError as e: # Catch if datastore_client was None during helper call
             logger.error(f'Datastore connection error during store_key_attestation_session: {e}')
             return jsonify({'error': 'Failed to store session due to datastore connectivity'}), 503
        except Exception as e:
            logger.error(f'Failed to store key attestation session for sessionId {session_id}: {e}')
            return jsonify({'error': 'Failed to store session data'}), 500

        response_data = {
            'nonce': nonce_encoded,
            'challenge': challenge_encoded
        }
        logger.info(f'Successfully prepared attestation for sessionId: {session_id}')
        return jsonify(response_data), 200
    except Exception as e:
        logger.error(f'Error in /prepare endpoint: {e}')
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/v1/prepare/agreement', methods=['POST'])
def prepare_agreement_attestation():
    """
    Prepares for key attestation agreement by generating a salt and challenge.
    Request body: { "session_id": "string" }
    Response body: { "salt": "string (Base64URLEncoded)", "challenge": "string (Base64URLEncoded)", "public_key": "string (Base64URLEncoded, optional)" }
    """
    if not datastore_client:
        logger.error('Datastore client not available for /prepare/agreement endpoint.')
        return jsonify({'error': 'Datastore service not available'}), 503

    try:
        data = request.get_json()
        if not data:
            logger.warning('Prepare agreement request missing JSON payload.')
            return jsonify({'error': 'Missing JSON payload'}), 400

        session_id = data.get('session_id')
        if not session_id or not isinstance(session_id, str) or not session_id.strip():
            logger.warning(f'Prepare agreement request with invalid session_id: {session_id}')
            return jsonify({'error': '\'session_id\' must be a non-empty string'}), 400

        salt_bytes = generate_random_bytes()
        challenge_bytes = generate_random_bytes()
        salt_encoded = base64url_encode(salt_bytes)
        challenge_encoded = base64url_encode(challenge_bytes)

        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo # Standard X.509 format
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
             logger.error(f'Datastore connection error during store_agreement_key_attestation_session: {e}')
             return jsonify({'error': 'Failed to store session due to datastore connectivity'}), 503
        except Exception as e:
            logger.error(f'Failed to store agreement key attestation session for sessionId {session_id}: {e}')
            return jsonify({'error': 'Failed to store session data'}), 500

        response_data = {
            'salt': salt_encoded,
            'challenge': challenge_encoded,
            'public_key': public_key_encoded
        }
        logger.info(f'Successfully prepared agreement attestation for sessionId: {session_id}')
        return jsonify(response_data), 200
    except Exception as e:
        logger.error(f'Error in /prepare/agreement endpoint: {e}')
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/v1/verify/signature', methods=['POST'])
def verify_signature_attestation():
    """
    Verifies the Key Attestation Signature.
    Request body: { "session_id": "string", "signature": "string (Base64Encoded)", "client_nonce": "string (Base64Encoded)", "certificate_chain": ["string (Base64Encoded)"] }
    Response body: (details successful verification structure, errors are standard JSON)
    """
    try:
        data = request.get_json()
        if not data:
            logger.warning('Verify Signature request missing JSON payload.')
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
            logger.warning('Verify Signature request missing session_id.')
            store_key_attestation_result('missing_session_id', 'failed', 'Missing session_id in request', payload_data_json_str, '{}')
            return jsonify({'error': 'Missing \'session_id\''}), 400

        if not all([signature_b64, client_nonce_b64, certificate_chain_b64]):
            logger.warning(f'Verify Signature request for session \'{session_id}\' missing one or more required fields (signature, client_nonce, certificate_chain).')
            store_key_attestation_result(session_id, 'failed', 'Missing one or more required fields: signature, client_nonce, certificate_chain', payload_data_json_str, '{}')
            return jsonify({'error': 'Missing one or more required fields: signature, client_nonce, certificate_chain'}), 400

        if not isinstance(session_id, str) or \
           not isinstance(signature_b64, str) or \
           not isinstance(client_nonce_b64, str) or \
           not isinstance(certificate_chain_b64, list) or \
           not all(isinstance(cert, str) for cert in certificate_chain_b64):
            logger.warning(f'Verify Signature request for session \'{session_id}\' has type mismatch for one or more fields.')
            store_key_attestation_result(session_id, 'failed', 'Type mismatch for one or more fields.', payload_data_json_str, '{}')
            return jsonify({'error': 'Type mismatch for one or more fields. Ensure session_id, signature, client_nonce are strings and certificate_chain is a list of strings.'}), 400

        if not datastore_client:
            logger.error('Datastore client not available for /verify/signature endpoint.')
            return jsonify({'error': 'Datastore service not available'}), 503

        session_entity = get_key_attestation_session(session_id)
        if not session_entity:
            logger.warning(f'Session ID \'{session_id}\' not found, expired, or invalid.')
            store_key_attestation_result(session_id, 'failed', 'Session ID not found, expired, or invalid.', payload_data_json_str, '{}')
            return jsonify({'error': 'Session ID not found, expired, or invalid.'}), 403

        nonce_from_store_b64 = session_entity.get('nonce')
        challenge_from_store_b64 = session_entity.get('challenge')

        if not nonce_from_store_b64 or not challenge_from_store_b64:
            logger.error(f'Session \'{session_id}\' is missing nonce or challenge in Datastore.')
            store_key_attestation_result(session_id, 'failed', 'Corrupted session data in Datastore.', payload_data_json_str, '{}')
            return jsonify({'error': 'Corrupted session data.'}), 500

        logger.info(f'Session validation successful for session_id: {session_id}')
        attestation_properties = None

        try:
            certificates = decode_certificate_chain(certificate_chain_b64)
            logger.info(f'Successfully decoded certificate chain for session_id: {session_id}. Chain length: {len(certificates)}')
        except ValueError as e:
            logger.warning(f'Failed to decode certificate chain for session {session_id}: {e}')
            store_key_attestation_result(session_id, 'failed', f'Invalid certificate chain: {e}', payload_data_json_str, '{}')
            delete_key_attestation_session(session_id)
            return jsonify({'error': f'Invalid certificate chain: {e}'}), 400

        try:
            validate_attestation_signature(certificates[0], nonce_from_store_b64, client_nonce_b64, signature_b64)
            logger.info(f'Attestation signature validated successfully for session_id: {session_id}')
        except ValueError as e:
            logger.warning(f'Attestation signature validation failed for session {session_id}: {e}')
            store_key_attestation_result(session_id, 'failed', f'Attestation signature validation failed: {e}', payload_data_json_str, '{}')
            delete_key_attestation_session(session_id)
            return jsonify({'error': f'Attestation signature validation failed: {e}'}), 400

        try:
            verify_certificate_chain(certificates)
            logger.info(f'Certificate chain verified successfully for session_id: {session_id}')
        except ValueError as e:
            logger.warning(f'Certificate chain verification failed for session {session_id}: {e}')
            store_key_attestation_result(session_id, 'failed', f'Certificate chain verification failed: {e}', payload_data_json_str, '{}')
            delete_key_attestation_session(session_id)
            return jsonify({'error': f'Certificate chain verification failed: {e}'}), 400

        try:
            attestation_properties = get_attestation_extension_properties(certificates[0])
            if not attestation_properties or 'attestation_challenge' not in attestation_properties:
                logger.warning(f'Failed to parse attestation extension or missing challenge for session {session_id}.')
                sanitized_att_props = convert_bytes_to_hex_str(attestation_properties or {})
                attestation_data_json_str = json.dumps(sanitized_att_props)
                store_key_attestation_result(session_id, 'failed', 'Failed to parse key attestation extension or attestation challenge not found.', payload_data_json_str, attestation_data_json_str)
                return jsonify({'error': 'Failed to parse key attestation extension or attestation challenge not found.'}), 400
            logger.info(f'Successfully parsed attestation extension for session_id: {session_id}. Version: {attestation_properties.get("attestation_version")}')
        except ValueError as e:
            logger.warning(f'ASN.1 parsing of attestation extension failed for session {session_id}: {e}')
            sanitized_att_props = convert_bytes_to_hex_str(attestation_properties or {})
            attestation_data_json_str = json.dumps(sanitized_att_props)
            store_key_attestation_result(session_id, 'failed', f'ASN.1 parsing failed: {e}', payload_data_json_str, attestation_data_json_str)
            return jsonify({'error': f'ASN.1 parsing failed: {e}'}), 400

        sanitized_att_props_for_error = convert_bytes_to_hex_str(attestation_properties or {})
        attestation_data_json_str_for_error = json.dumps(sanitized_att_props_for_error)

        try:
            challenge_from_store_bytes = base64url_decode(challenge_from_store_b64)
        except Exception as e:
            logger.error(f'Failed to base64url_decode challenge_from_store_b64 for session {session_id}: {e}')
            store_key_attestation_result(session_id, 'failed', 'Internal server error: Could not decode stored challenge.', payload_data_json_str, attestation_data_json_str_for_error)
            return jsonify({'error': 'Internal server error: Could not decode stored challenge.'}), 500

        client_attestation_challenge_bytes = attestation_properties.get('attestation_challenge')

        if not client_attestation_challenge_bytes or \
           not hmac.compare_digest(challenge_from_store_bytes, client_attestation_challenge_bytes):
            logger.warning(f'Challenge mismatch for session {session_id}. Store (bytes_hex): \'{challenge_from_store_bytes.hex()}\', Cert (bytes_hex): \'{client_attestation_challenge_bytes.hex() if client_attestation_challenge_bytes else "None"}\'')
            store_key_attestation_result(session_id, 'failed', 'Attestation challenge mismatch.', payload_data_json_str, attestation_data_json_str_for_error)
            delete_key_attestation_session(session_id)
            return jsonify({'error': 'Attestation challenge mismatch.'}), 400

        logger.info(f'Attestation challenge matched successfully for session_id: {session_id}')
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

        logger.info(f'Successfully verified Key Attestation Signature for session_id: {session_id}')
        return jsonify(final_response), 200
    except ValueError as e:
        current_session_id = locals().get('session_id', 'unknown_session_value_error')
        payload_str = locals().get('payload_data_json_str', '{}')
        raw_att_props = locals().get('attestation_properties') or {}
        sanitized_att_props = convert_bytes_to_hex_str(raw_att_props)
        att_props_str = json.dumps(sanitized_att_props)
        logger.warning(f'ValueError in /verify/signature for session {current_session_id}: {e}')
        store_key_attestation_result(current_session_id, 'failed', str(e), payload_str, att_props_str)
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_session_id = locals().get('session_id', 'unknown_session_exception')
        payload_str = locals().get('payload_data_json_str', '{}')
        raw_att_props = locals().get('attestation_properties') or {}
        sanitized_att_props = convert_bytes_to_hex_str(raw_att_props)
        att_props_str = json.dumps(sanitized_att_props)
        logger.error(f'Error in /verify/signature endpoint for session {current_session_id}: {e}', exc_info=True)
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
            logger.warning('Verify Agreement request missing JSON payload.')
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
            logger.warning('Verify Agreement request missing session_id.')
            store_key_attestation_result('missing_session_id_agreement', 'failed', 'Missing session_id in agreement request', payload_data_json_str, '{}')
            return jsonify({'error': 'Missing \'session_id\''}), 400

        if not all([encrypted_data_b64url, client_public_key_b64]):
            logger.warning(f'Verify Agreement request for session \'{session_id}\' missing encrypted_data or client_public_key.')
            store_key_attestation_result(session_id, 'failed', 'Missing encrypted_data or client_public_key for agreement', payload_data_json_str, '{}')
            return jsonify({'error': 'Missing \'encrypted_data\' or \'client_public_key\''}), 400

        if not isinstance(session_id, str) or \
           not isinstance(encrypted_data_b64url, str) or \
           not isinstance(client_public_key_b64, str):
            logger.warning(f'Verify Agreement request for session \'{session_id}\' has type mismatch.')
            store_key_attestation_result(session_id, 'failed', 'Type mismatch in agreement request fields.', payload_data_json_str, '{}')
            return jsonify({'error': 'Type mismatch for one or more fields.'}), 400

        if not datastore_client:
            logger.error('Datastore client not available for /verify/agreement endpoint.')
            return jsonify({'error': 'Datastore service not available'}), 503

        # Mock verification logic:
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
            logger.warning(f'Agreement Session ID \'{session_id}\' not found, expired, or invalid for verify/agreement.')
            store_key_attestation_result(session_id, 'failed', 'Agreement Session ID not found, expired, or invalid.', payload_data_json_str, '{}')
            return jsonify({'error': 'Agreement Session ID not found, expired, or invalid.'}), 403

        # Mocked AttestationInfo structure
        mock_attestation_info = {
            "attestation_version": 0, # Mock value
            "attestation_security_level": 0, # Mock value (e.g., TEE)
            "keymint_version": 0, # Mock value
            "keymint_security_level": 0, # Mock value
            "attestation_challenge": base64url_encode(b"mock_agreement_challenge"), # Mock challenge
            "software_enforced_properties": {}, # Empty for mock agreement
            "hardware_enforced_properties": {}  # Empty for mock agreement
        }

        # Use device_info and security_info from request, or provide defaults
        final_device_info = device_info_from_request if device_info_from_request else {
            "brand": "MockBrand", "model": "MockModel", "device": "MockDevice", "product": "MockProduct",
            "manufacturer": "MockManufacturer", "hardware": "MockHardware", "board": "MockBoard",
            "bootloader": "MockBootloader", "version_release": "0", "sdk_int": 0,
            "fingerprint": "MockFingerprint", "security_patch": "1970-01-01"
        }
        final_security_info = security_info_from_request if security_info_from_request else {
            "is_device_lock_enabled": False, "is_biometrics_enabled": False,
            "has_class_3_authenticator": False, "has_strongbox": False
        }

        final_response = {
            "session_id": session_id,
            "is_verified": True, # Mock success
            "reason": "Key agreement verified successfully (mock).",
            "attestation_info": mock_attestation_info,
            "device_info": final_device_info,
            "security_info": final_security_info
        }

        # Storing result in Datastore
        # The attestation_data part can include the mocked attestation_info for consistency
        attestation_data_for_datastore = {
            "attestation_info": mock_attestation_info,
            "verification_type": "agreement_mock",
            "client_public_key_provided": bool(client_public_key_b64),
            "encrypted_data_provided": bool(encrypted_data_b64url)
        }
        attestation_data_json_str_success = json.dumps(attestation_data_for_datastore)

        store_key_attestation_result(
            session_id,
            "verified_agreement_mock",
            final_response["reason"],
            payload_data_json_str, # Contains original device_info, security_info from request
            attestation_data_json_str_success
        )
        delete_agreement_key_attestation_session(session_id)

        logger.info(f'Successfully verified Key Attestation Agreement (mock) for session_id: {session_id}')
        return jsonify(final_response), 200
    except ValueError as e:
        current_session_id = locals().get("session_id", "unknown_session_agreement_value_error")
        payload_str = locals().get("payload_data_json_str", "{}")
        # Include empty attestation_info in error case if schema expects it
        att_props_str = json.dumps({"attestation_info": {}})
        logger.warning(f"ValueError in /verify/agreement for session {current_session_id}: {e}")
        store_key_attestation_result(current_session_id, "failed", str(e), payload_str, att_props_str)
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        current_session_id = locals().get("session_id", "unknown_session_agreement_exception")
        payload_str = locals().get("payload_data_json_str", "{}")
        # Include empty attestation_info in error case if schema expects it
        att_props_str = json.dumps({"attestation_info": {}})
        logger.error(f"Error in /verify/agreement endpoint for session {current_session_id}: {e}", exc_info=True)
        store_key_attestation_result(current_session_id, "failed", "An unexpected error occurred during agreement verification.", payload_str, att_props_str)
        return jsonify({"error": "An unexpected error occurred"}), 500

if __name__ == '__main__':
    # This is used when running locally only.
    # When deploying to Google App Engine, a webserver process such as Gunicorn will serve the app.
    # This can be configured by adding an `entrypoint` to app.yaml.
    # The PORT environment variable is provided by App Engine.
    port = int(os.environ.get('PORT', 8081))
    app.run(host='0.0.0.0', port=port, debug=True)
