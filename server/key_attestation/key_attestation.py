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

def generate_random_bytes(length=32):
    return os.urandom(length)

def base64url_encode(data_bytes):
    return base64.urlsafe_b64encode(data_bytes).decode('utf-8').rstrip('=')

def base64url_decode(base64url_string):
    padding = '=' * (4 - (len(base64url_string) % 4))
    return base64.urlsafe_b64decode(base64url_string + padding)

def convert_bytes_to_hex_str(data):
    if isinstance(data, dict):
        return {k: convert_bytes_to_hex_str(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [convert_bytes_to_hex_str(i) for i in data]
    elif isinstance(data, bytes):
        return data.hex()
    else:
        return data

def store_key_attestation_session(session_id, nonce_encoded, challenge_encoded):
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
    cleanup_expired_sessions()

def store_agreement_key_attestation_session(session_id, salt_encoded, challenge_encoded, public_key_encoded=None, private_key_encoded=None):
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
    cleanup_expired_agreement_sessions()

def get_key_attestation_session(session_id):
    if not datastore_client:
        logger.error('Datastore client not available. Cannot retrieve session.')
        return None

    key = datastore_client.key(KEY_ATTESTATION_SESSION_KIND, session_id)
    entity = datastore_client.get(key)

    if not entity:
        logger.warning(f'Session not found for session_id: {session_id}')
        return None

    generated_at = entity.get('generated_at')
    if not generated_at:
        logger.error(f'Session {session_id} is missing \'generated_at\' timestamp.')
        return None

    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=timezone.utc)

    expiry_datetime = generated_at + timedelta(minutes=NONCE_EXPIRY_MINUTES)
    if datetime.now(timezone.utc) > expiry_datetime:
        logger.warning(f'Session expired for session_id: {session_id}. Generated at: {generated_at}, Expired at: {expiry_datetime}')
        return None

    logger.info(f'Successfully retrieved and validated session for session_id: {session_id}')
    return entity

def get_agreement_key_attestation_session(session_id):
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

    expiry_datetime = generated_at + timedelta(minutes=NONCE_EXPIRY_MINUTES)
    if datetime.now(timezone.utc) > expiry_datetime:
        logger.warning(f'Agreement session expired for session_id: {session_id}. Generated at: {generated_at}, Expired at: {expiry_datetime}')
        return None

    logger.info(f'Successfully retrieved and validated agreement session for session_id: {session_id}')
    return entity

def decode_certificate_chain(certificate_chain_b64):
    decoded_certs = []
    for i, cert_b64 in enumerate(certificate_chain_b64):
        try:
            cert_bytes = base64.b64decode(cert_b64)
            cert = x509.load_der_x509_certificate(cert_bytes)
            decoded_certs.append(cert)
        except ValueError as e:
            logger.error(f'Failed to decode Base64 certificate at index {i}: {e}')
            raise ValueError(f'Invalid Base64 certificate string at index {i}')
        except TypeError as e:
            logger.error(f'Type error during Base64 decoding for certificate at index {i}: {e}')
            raise ValueError(f'Invalid type for Base64 certificate string at index {i}')
        except Exception as e:
            logger.error(f'Error loading certificate at index {i} into X509 object: {e}')
            raise ValueError(f'Cannot parse certificate at index {i} into X509 object')
    if not decoded_certs:
        raise ValueError('Certificate chain is empty after decoding.')
    return decoded_certs

def validate_attestation_signature(leaf_certificate, nonce_from_store_b64, nonce_b_b64, signature_b64):
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
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature_bytes,
                signed_data_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            logger.info('Attestation signature validated successfully.')
            return True
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature_bytes,
                signed_data_bytes,
                asym_padding.PKCS1v15(),
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
    if len(certificates) < 1:
        raise ValueError('Certificate chain is empty, cannot verify.')
    if len(certificates) == 1:
        logger.info('Certificate chain has only one certificate. No internal chain validation to perform.')
        return True

    for i in range(len(certificates) - 1):
        subject_cert = certificates[i]
        issuer_cert = certificates[i+1]
        issuer_public_key = issuer_cert.public_key()

        try:
            if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                issuer_public_key.verify(
                    subject_cert.signature,
                    subject_cert.tbs_certificate_bytes,
                    ec.ECDSA(subject_cert.signature_hash_algorithm)
                )
            elif isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(
                    subject_cert.signature,
                    subject_cert.tbs_certificate_bytes,
                    asym_padding.PKCS1v15(),
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

OID_ANDROID_KEY_ATTESTATION = x509.ObjectIdentifier('1.3.6.1.4.1.11129.2.1.17')

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
TAG_ATTESTATION_APPLICATION_ID = 709
TAG_ATTESTATION_ID_BRAND = 710
TAG_ATTESTATION_ID_DEVICE = 711
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

def parse_root_of_trust(root_of_trust_sequence):
    parsed_data = {}
    if not isinstance(root_of_trust_sequence, univ.Sequence):
        return parsed_data
    parsed_data['verified_boot_key'] = bytes(root_of_trust_sequence[0]).hex()
    parsed_data['device_locked'] = bool(root_of_trust_sequence[1])
    parsed_data['verified_boot_state'] = int(root_of_trust_sequence[2])
    parsed_data['verified_boot_hash'] = bytes(root_of_trust_sequence[3]).hex()
    return parsed_data

def parse_attestation_application_id(attestation_application_id_bytes):
    try:
        attestation_application_id_sequence, _ = der_decoder.decode(attestation_application_id_bytes)
    except PyAsn1Error as e:
        logger.error(f'Failed to decode KeyDescription ASN.1 sequence with pyasn1: {e}')
        raise ValueError('Malformed KeyDescription sequence.')

    parsed_data = {}
    if not isinstance(attestation_application_id_sequence, univ.SequenceOf):
        return parsed_data

    package_info_sequence = attestation_application_id_sequence[0][0]
    if not isinstance(package_info_sequence, univ.Sequence):
        return parsed_data

    signature_set = attestation_application_id_sequence[1]
    if not isinstance(signature_set, univ.SetOf):
        return parsed_data

    items = package_info_sequence.items()
    for index, item_value_pair in enumerate(items): # Renamed item to item_value_pair for clarity
        try:
            value_component = item_value_pair[1]
        except (AttributeError, IndexError):
            logger.warning(f'Could not get value component from item: {item_value_pair}')
            continue
        if index == 0:
            parsed_data['attestation_application_id'] = str(value_component)
        elif index == 1:
            parsed_data['attestation_application_version_code'] = int(value_component)

    signatures = []
    for sig_item in signature_set: # Renamed item to sig_item for clarity
        signatures.append(bytes(sig_item).hex())
    parsed_data['application_signatures'] = signatures
    return parsed_data

def parse_authorization_list(auth_list_sequence, attestation_version):
    parsed_props = {}
    if not isinstance(auth_list_sequence, univ.Sequence):
        return parsed_props

    for item_value_pair in auth_list_sequence.items(): # Renamed item to item_value_pair
        try:
            # Assuming item_value_pair is the actual value component with tags
            tag_set = item_value_pair[1].tagSet
            tag_number = tag_set.superTags[1].tagId
            value_component = item_value_pair[1]
        except (AttributeError, IndexError, TypeError): # Added TypeError
            logger.warning(f'Could not get tag or value from item: {item_value_pair}')
            continue
        try:
            if tag_number == TAG_ATTESTATION_APPLICATION_ID:
                parsed_props['attestation_application_id'] = parse_attestation_application_id(bytes(value_component))
            elif tag_number == TAG_OS_VERSION:
                parsed_props['os_version'] = int(value_component)
            elif tag_number == TAG_OS_PATCH_LEVEL:
                parsed_props['os_patch_level'] = int(value_component)
            elif tag_number == TAG_DIGEST:
                parsed_props['digests'] = [int(p) for p in value_component]
            elif tag_number == TAG_PURPOSE:
                parsed_props['purpose'] = [int(p) for p in value_component]
            elif tag_number == TAG_ALGORITHM:
                parsed_props['algorithm'] = int(value_component)
            elif tag_number == TAG_EC_CURVE:
                parsed_props['ec_curve'] = int(value_component)
            elif tag_number == TAG_RSA_PUBLIC_EXPONENT:
                parsed_props['rsa_public_exponent'] = int(value_component)
            elif tag_number == TAG_MGF_DIGEST:
                parsed_props['mgf_digest'] = [int(p) for p in value_component]
            elif tag_number == TAG_KEY_SIZE:
                parsed_props['key_size'] = int(value_component)
            elif tag_number == TAG_NO_AUTH_REQUIRED:
                parsed_props['no_auth_required'] = True
            elif tag_number == TAG_CREATION_DATETIME:
                parsed_props['creation_datetime'] = int(value_component)
            elif tag_number == TAG_ORIGIN:
                parsed_props['origin'] = int(value_component)
            elif tag_number == TAG_VENDOR_PATCH_LEVEL:
                parsed_props['vendor_patch_level'] = int(value_component)
            elif tag_number == TAG_BOOT_PATCH_LEVEL:
                parsed_props['boot_patch_level'] = int(value_component)
            elif tag_number == TAG_ATTESTATION_ID_BRAND:
                parsed_props['attestation_id_brand'] = str(value_component)
            elif tag_number == TAG_ATTESTATION_ID_DEVICE:
                parsed_props['attestation_id_device'] = str(value_component)
            elif tag_number == TAG_ATTESTATION_ID_PRODUCT:
                parsed_props['attestation_id_product'] = str(value_component)
            elif tag_number == TAG_ATTESTATION_ID_SERIAL:
                parsed_props['attestation_id_serial'] = str(value_component)
            elif tag_number == TAG_ATTESTATION_ID_MANUFACTURER:
                parsed_props['attestation_id_manufacturer'] = str(value_component)
            elif tag_number == TAG_ATTESTATION_ID_MODEL:
                parsed_props['attestation_id_model'] = str(value_component)
            elif tag_number == TAG_MODULE_HASH:
                parsed_props['module_hash'] = base64.urlsafe_b64encode(bytes(value_component)).decode()
            elif tag_number == TAG_ROOT_OF_TRUST:
                parsed_props['root_of_trust'] = parse_root_of_trust(value_component)
            elif tag_number == TAG_PADDING:
                parsed_props['padding'] = [int(p) for p in value_component]
            elif tag_number == TAG_ROLLBACK_RESISTANCE:
                parsed_props['rollback_resistance'] = True
            elif tag_number == TAG_EARLY_BOOT_ONLY:
                parsed_props['early_boot_only'] = True
            elif tag_number == TAG_ACTIVE_DATETIME:
                parsed_props['active_datetime'] = int(value_component)
            elif tag_number == TAG_ORIGINATION_EXPIRE_DATETIME:
                parsed_props['origination_expire_datetime'] = int(value_component)
            elif tag_number == TAG_USAGE_EXPIRE_DATETIME:
                parsed_props['usage_expire_datetime'] = int(value_component)
            elif tag_number == TAG_USAGE_COUNT_LIMIT:
                parsed_props['usage_count_limit'] = int(value_component)
            elif tag_number == TAG_USER_AUTH_TYPE:
                parsed_props['user_auth_type'] = int(value_component)
            elif tag_number == TAG_AUTH_TIMEOUT:
                parsed_props['auth_timeout'] = int(value_component)
            elif tag_number == TAG_ALLOW_WHILE_ON_BODY:
                parsed_props['allow_while_on_body'] = True
            elif tag_number == TAG_TRUSTED_USER_PRESENCE_REQUIRED:
                parsed_props['trusted_user_presence_required'] = True
            elif tag_number == TAG_TRUSTED_CONFIRMATION_REQUIRED:
                parsed_props['trusted_confirmation_required'] = True
            elif tag_number == TAG_UNLOCKED_DEVICE_REQUIRED:
                parsed_props['unlocked_device_required'] = True
            elif tag_number == TAG_ATTESTATION_ID_IMEI:
                parsed_props['attestation_id_imei'] = str(value_component)
            elif tag_number == TAG_ATTESTATION_ID_MEID:
                parsed_props['attestation_id_meid'] = str(value_component)
            elif tag_number == TAG_DEVICE_UNIQUE_ATTESTATION:
                parsed_props['device_unique_attestation'] = True
            elif tag_number == TAG_ATTESTATION_ID_SECOND_IMEI:
                parsed_props['attestation_id_second_imei'] = str(value_component)
            else:
                logger.warning(f'Unknown tag:{tag_number}, {value_component}')
        except (PyAsn1Error, ValueError) as e:
            logger.warning(
                f'Error parsing tag {tag_number} in AuthorizationList: {e}. Value component: {value_component}')
    return parsed_props

def parse_key_description(key_desc_bytes):
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
        parsed_data['attestation_challenge'] = bytes(key_desc_sequence[4])

        idx = 5
        if len(key_desc_sequence) > idx and isinstance(key_desc_sequence[idx], univ.OctetString):
            parsed_data['unique_id'] = bytes(key_desc_sequence[idx]).hex()
            idx += 1
        else:
            parsed_data['unique_id'] = None

        if len(key_desc_sequence) > idx:
            sw_enforced_seq = key_desc_sequence[idx]
            parsed_data['software_enforced'] = parse_authorization_list(
                sw_enforced_seq,
                parsed_data.get('attestation_version')
            )
            idx += 1
        else:
            parsed_data['software_enforced'] = {}

        if len(key_desc_sequence) > idx:
            hw_enforced_seq = key_desc_sequence[idx]
            parsed_data['hardware_enforced'] = parse_authorization_list(
                hw_enforced_seq,
                parsed_data.get('attestation_version')
            )
            idx += 1
        else:
            parsed_data['hardware_enforced'] = {}

        if parsed_data.get('attestation_version') == 4 and len(key_desc_sequence) > idx:
            if isinstance(key_desc_sequence[idx], univ.Null):
                parsed_data['device_unique_attestation'] = True
    except (IndexError, ValueError, PyAsn1Error) as e:
        logger.error(f'Error processing parsed KeyDescription sequence: {e}. Structure might be unexpected.')
        raise ValueError('Malformed or unexpected KeyDescription structure.')
    return parsed_data

def get_attestation_extension_properties(certificate):
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
    if not datastore_client:
        logger.warning(f'Datastore client not available. Cannot delete session {session_id}.')
        return
    try:
        key = datastore_client.key(KEY_ATTESTATION_SESSION_KIND, session_id)
        datastore_client.delete(key)
        logger.info(f'Successfully deleted key attestation session for session_id: {session_id}')
    except Exception as e:
        logger.error(f'Error deleting key attestation session {session_id} from Datastore: {e}')

def delete_agreement_key_attestation_session(session_id):
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
    if not datastore_client:
        logger.error('Datastore client not available. Cannot store attestation result.')
        return
    try:
        key = datastore_client.key(KEY_ATTESTATION_RESULT_KIND, session_id)
        entity = datastore.Entity(key=key)
        entity.update({
            'session_id': session_id,
            'created_at': datetime.now(timezone.utc),
            'result': result,
            'reason': reason,
            'payload_data': payload_data_json_str,
            'attestation_data': attestation_data_json_str
        })
        datastore_client.put(entity)
        logger.info(f'Stored key attestation result for session_id: {session_id}')
    except Exception as e:
        logger.error(f'Failed to store key attestation result for session_id {session_id}: {e}')

@app.route('/v1/prepare/signature', methods=['POST'])
def prepare_signature_attestation():
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
        except ConnectionError as e:
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
            format=serialization.PublicFormat.SubjectPublicKeyInfo
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

        agreement_session_entity = get_agreement_key_attestation_session(session_id)
        if not agreement_session_entity:
            logger.warning(f'Agreement Session ID \'{session_id}\' not found, expired, or invalid for verify/agreement.')
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

        logger.info(f'Successfully verified Key Attestation Agreement (mock) for session_id: {session_id}')
        return jsonify(final_response), 200
    except ValueError as e:
        current_session_id = locals().get('session_id', 'unknown_session_agreement_value_error')
        payload_str = locals().get('payload_data_json_str', '{}')
        logger.warning(f'ValueError in /verify/agreement for session {current_session_id}: {e}')
        store_key_attestation_result(current_session_id, 'failed', str(e), payload_str, '{}')
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_session_id = locals().get('session_id', 'unknown_session_agreement_exception')
        payload_str = locals().get('payload_data_json_str', '{}')
        logger.error(f'Error in /verify/agreement endpoint for session {current_session_id}: {e}', exc_info=True)
        store_key_attestation_result(current_session_id, 'failed', 'An unexpected error occurred during agreement verification.', payload_str, '{}')
        return jsonify({'error': 'An unexpected error occurred'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8081))
    app.run(host='0.0.0.0', port=port, debug=True)
