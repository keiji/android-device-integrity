import base64
import logging
from cryptography import x509
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type import univ
from pyasn1.error import PyAsn1Error

logger = logging.getLogger(__name__)

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
TAG_MGF_DIGEST = 203 # Keymaster v4.1 / KeyMint v1
TAG_ROLLBACK_RESISTANCE = 303
TAG_EARLY_BOOT_ONLY = 305 # Keymaster v4.1 / KeyMint v1
TAG_ACTIVE_DATETIME = 400
TAG_ORIGINATION_EXPIRE_DATETIME = 401
TAG_USAGE_EXPIRE_DATETIME = 402
TAG_USAGE_COUNT_LIMIT = 405 # Keymaster v4.1 / KeyMint v1
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
TAG_VENDOR_PATCH_LEVEL = 718 # Keymaster v4 / KeyMint v1 (Android S)
TAG_BOOT_PATCH_LEVEL = 719   # Keymaster v4 / KeyMint v1 (Android S)
TAG_DEVICE_UNIQUE_ATTESTATION = 720 # KeyMint v2 (Android T)
TAG_ATTESTATION_ID_SECOND_IMEI = 723 # KeyMint v2
TAG_MODULE_HASH = 724 # KeyMint v? (Not explicitly versioned in main attestation docs, but related to StrongBox)


def parse_root_of_trust(root_of_trust_sequence):
    """Parses the RootOfTrust ASN.1 sequence."""
    parsed_data = {}
    if not isinstance(root_of_trust_sequence, univ.Sequence) or len(root_of_trust_sequence) < 4:
        logger.warning(f"RootOfTrust sequence is not a sequence or has insufficient elements: {root_of_trust_sequence}")
        # Return minimal structure or raise error based on strictness
        return {
            'verified_boot_key': "",
            'device_locked': False,
            'verified_boot_state': 0, # Assuming 0 is a sensible default for UNKNOWN/FAILED
            'verified_boot_hash': ""
        }
    try:
        parsed_data['verified_boot_key'] = bytes(root_of_trust_sequence[0]).hex()
        parsed_data['device_locked'] = bool(root_of_trust_sequence[1])
        parsed_data['verified_boot_state'] = int(root_of_trust_sequence[2]) # Enum: Verified = 0, SelfSigned = 1, Unverified = 2, Failed = 3
        parsed_data['verified_boot_hash'] = bytes(root_of_trust_sequence[3]).hex()
    except (TypeError, ValueError, PyAsn1Error) as e:
        logger.error(f"Error parsing RootOfTrust fields: {e}. Sequence was: {root_of_trust_sequence}")
        # Fallback or re-raise depending on how critical this is
        return {
            'verified_boot_key': getattr(root_of_trust_sequence[0], 'prettyPrint', lambda: str(root_of_trust_sequence[0]))(), # Attempt to get some representation
            'device_locked': False, # Default
            'verified_boot_state': -1, # Indicate error
            'verified_boot_hash': getattr(root_of_trust_sequence[3], 'prettyPrint', lambda: str(root_of_trust_sequence[3]))()
        }
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
                try:
                    pkg_name = str(package_info_seq[0])
                    pkg_version = int(package_info_seq[1])
                    parsed_data['package_infos'].append({'package_name': pkg_name, 'version': pkg_version})
                except (TypeError, ValueError) as e:
                    logger.warning(f'Malformed PackageInfo entry (name/version) in AttestationApplicationId: {package_info_seq}, error: {e}')
            else:
                logger.warning(f'Malformed PackageInfo entry (not a sequence or wrong length) in AttestationApplicationId: {package_info_seq}')
    else:
        logger.warning('packageInfos is not a SetOf in AttestationApplicationId.')

    signature_digests_set = app_id_seq[1]
    if isinstance(signature_digests_set, univ.SetOf):
        for sig_digest_octet_str in signature_digests_set:
            if isinstance(sig_digest_octet_str, univ.OctetString):
                try:
                    parsed_data['signature_digests'].append(bytes(sig_digest_octet_str).hex())
                except (TypeError, ValueError) as e:
                     logger.warning(f'Malformed signatureDigest (conversion to hex) in AttestationApplicationId: {sig_digest_octet_str}, error: {e}')
            else:
                 logger.warning(f'Malformed signatureDigest entry (not OctetString) in AttestationApplicationId: {sig_digest_octet_str}')
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
        logger.warning(f"AuthorizationList is not a sequence: {type(auth_list_sequence)}")
        return parsed_props

    for item_value_pair in auth_list_sequence:
        try:
            if not hasattr(item_value_pair, 'tagSet') or not item_value_pair.tagSet:
                 logger.warning(f'Skipping item in AuthorizationList without a proper tagSet: {item_value_pair}')
                 continue
            # Ensure tagId is accessed correctly, it's part of the first tag in the TagSet
            tag_number = item_value_pair.tagSet[0].tagId
            # The value is the component of the EXPLICIT tagged type
            value_component_container = item_value_pair.getComponent()
            if value_component_container is None:
                logger.warning(f"Tag {tag_number} in AuthorizationList has no value component container.")
                continue

            # Check if the value component itself is another sequence or a simple type
            # This depends on how the EXPLICIT tag was defined in the ASN.1 schema
            # For many tags, the value is directly the component (e.g., INTEGER, OCTET STRING)
            # For some, like ROOT_OF_TRUST, it's a nested SEQUENCE.
            # If the component is a univ.Any or similar, we might need to decode it further.
            # For pyasn1, typically the .getComponent() on the tagged object gives the inner value.
            # If the value is directly a simple type (like Integer, OctetString), we use it.
            # If it's a constructed type (like Sequence), it's used directly.
            # The .getComponent() method on the tagged object itself (item_value_pair)
            # should give the value part of the [TAG] EXPLICIT Value construct.

            value = value_component_container # This is the actual value after the EXPLICIT tag

        except (AttributeError, IndexError, TypeError, PyAsn1Error) as e: # Added PyAsn1Error
            logger.warning(f'Could not get tag or value from auth list item: {item_value_pair}, error: {e}')
            continue

        try:
            if tag_number == TAG_ATTESTATION_APPLICATION_ID:
                # The value should be an OctetString containing the DER encoded App ID
                if isinstance(value, univ.OctetString):
                    app_id_bytes = bytes(value)
                    parsed_props['attestation_application_id'] = parse_attestation_application_id(app_id_bytes)
                else:
                    logger.warning(f"TAG_ATTESTATION_APPLICATION_ID value is not OctetString: {type(value)}")
            elif tag_number == TAG_OS_VERSION:
                parsed_props['os_version'] = int(value)
            elif tag_number == TAG_OS_PATCH_LEVEL: # YYYYMMDD format
                parsed_props['os_patch_level'] = int(value)
            elif tag_number == TAG_VENDOR_PATCH_LEVEL: # YYYYMMDD format
                parsed_props['vendor_patch_level'] = int(value)
            elif tag_number == TAG_BOOT_PATCH_LEVEL: # YYYYMMDD format
                parsed_props['boot_patch_level'] = int(value)
            elif tag_number == TAG_DIGEST: # SET OF INTEGER
                parsed_props['digests'] = [int(p) for p in value] if isinstance(value, univ.SetOf) else [int(value)] if isinstance(value, univ.Integer) else []
            elif tag_number == TAG_PURPOSE: # SET OF INTEGER
                parsed_props['purpose'] = [int(p) for p in value] if isinstance(value, univ.SetOf) else [int(value)] if isinstance(value, univ.Integer) else []
            elif tag_number == TAG_ALGORITHM:
                parsed_props['algorithm'] = int(value)
            elif tag_number == TAG_EC_CURVE:
                parsed_props['ec_curve'] = int(value)
            elif tag_number == TAG_RSA_PUBLIC_EXPONENT:
                parsed_props['rsa_public_exponent'] = int(value)
            elif tag_number == TAG_MGF_DIGEST: # For RSA PSS padding, SET OF INTEGER
                 parsed_props['mgf_digest'] = [int(p) for p in value] if isinstance(value, univ.SetOf) else [int(value)] if isinstance(value, univ.Integer) else []
            elif tag_number == TAG_KEY_SIZE:
                parsed_props['key_size'] = int(value)
            elif tag_number == TAG_NO_AUTH_REQUIRED: # NULL type implies presence
                parsed_props['no_auth_required'] = True
            elif tag_number == TAG_CREATION_DATETIME: # INTEGER milliseconds since epoch
                parsed_props['creation_datetime'] = int(value)
            elif tag_number == TAG_ORIGIN: # INTEGER (KeyOrigin)
                parsed_props['origin'] = int(value)
            elif tag_number == TAG_ATTESTATION_ID_BRAND:
                parsed_props['attestation_id_brand'] = bytes(value).decode('utf-8', errors='replace')
            elif tag_number == TAG_ATTESTATION_ID_DEVICE:
                parsed_props['attestation_id_device'] = bytes(value).decode('utf-8', errors='replace')
            elif tag_number == TAG_ATTESTATION_ID_PRODUCT:
                parsed_props['attestation_id_product'] = bytes(value).decode('utf-8', errors='replace')
            elif tag_number == TAG_ATTESTATION_ID_SERIAL:
                parsed_props['attestation_id_serial'] = bytes(value).decode('utf-8', errors='replace')
            elif tag_number == TAG_ATTESTATION_ID_MANUFACTURER:
                parsed_props['attestation_id_manufacturer'] = bytes(value).decode('utf-8', errors='replace')
            elif tag_number == TAG_ATTESTATION_ID_MODEL:
                parsed_props['attestation_id_model'] = bytes(value).decode('utf-8', errors='replace')
            elif tag_number == TAG_MODULE_HASH: # OCTET_STRING
                parsed_props['module_hash'] = base64.urlsafe_b64encode(bytes(value)).decode()
            elif tag_number == TAG_ROOT_OF_TRUST: # This is a SEQUENCE
                parsed_props['root_of_trust'] = parse_root_of_trust(value) # value should be the RootOfTrust SEQUENCE
            elif tag_number == TAG_PADDING: # SET OF INTEGER
                parsed_props['padding'] = [int(p) for p in value] if isinstance(value, univ.SetOf) else [int(value)] if isinstance(value, univ.Integer) else []
            elif tag_number == TAG_ROLLBACK_RESISTANCE: # NULL
                parsed_props['rollback_resistance'] = True
            elif tag_number == TAG_EARLY_BOOT_ONLY: # NULL
                parsed_props['early_boot_only'] = True
            elif tag_number == TAG_ACTIVE_DATETIME: # INTEGER milliseconds
                parsed_props['active_datetime'] = int(value)
            elif tag_number == TAG_ORIGINATION_EXPIRE_DATETIME: # INTEGER milliseconds
                parsed_props['origination_expire_datetime'] = int(value)
            elif tag_number == TAG_USAGE_EXPIRE_DATETIME: # INTEGER milliseconds
                parsed_props['usage_expire_datetime'] = int(value)
            elif tag_number == TAG_USAGE_COUNT_LIMIT: # INTEGER
                parsed_props['usage_count_limit'] = int(value)
            elif tag_number == TAG_USER_AUTH_TYPE: # INTEGER (Bitfield: 1=fingerprint, 2=password, 4=iris, etc.)
                parsed_props['user_auth_type'] = int(value)
            elif tag_number == TAG_AUTH_TIMEOUT: # INTEGER seconds
                parsed_props['auth_timeout'] = int(value)
            elif tag_number == TAG_ALLOW_WHILE_ON_BODY: # NULL
                parsed_props['allow_while_on_body'] = True
            elif tag_number == TAG_TRUSTED_USER_PRESENCE_REQUIRED: # NULL
                parsed_props['trusted_user_presence_required'] = True
            elif tag_number == TAG_TRUSTED_CONFIRMATION_REQUIRED: # NULL
                parsed_props['trusted_confirmation_required'] = True
            elif tag_number == TAG_UNLOCKED_DEVICE_REQUIRED: # NULL
                parsed_props['unlocked_device_required'] = True
            elif tag_number == TAG_ATTESTATION_ID_IMEI: # OCTET_STRING
                parsed_props['attestation_id_imei'] = bytes(value).decode('utf-8', errors='replace')
            elif tag_number == TAG_ATTESTATION_ID_MEID: # OCTET_STRING
                parsed_props['attestation_id_meid'] = bytes(value).decode('utf-8', errors='replace')
            elif tag_number == TAG_DEVICE_UNIQUE_ATTESTATION: # NULL (KeyMint v2+)
                parsed_props['device_unique_attestation'] = True
            elif tag_number == TAG_ATTESTATION_ID_SECOND_IMEI: # OCTET_STRING
                parsed_props['attestation_id_second_imei'] = bytes(value).decode('utf-8', errors='replace')
            else:
                # Store unknown tags as bytes if possible, or their string representation
                unknown_value_repr = ""
                if hasattr(value, 'asOctets'):
                    unknown_value_repr = f"bytes:{bytes(value).hex()}"
                elif hasattr(value, 'prettyPrint'):
                    unknown_value_repr = value.prettyPrint()
                else:
                    unknown_value_repr = str(value)
                logger.warning(f'Unknown tag in AuthorizationList: {tag_number}, value: {unknown_value_repr}')
                parsed_props[f'unknown_tag_{tag_number}'] = unknown_value_repr

        except (PyAsn1Error, ValueError, TypeError) as e:
            val_repr = getattr(value, 'prettyPrint', lambda: str(value))()
            logger.warning(f'Error parsing tag {tag_number} in AuthorizationList: {e}. Value component: {val_repr}')
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
        current_index = 0
        parsed_data['attestation_version'] = int(key_desc_sequence[current_index])
        current_index += 1
        parsed_data['attestation_security_level'] = int(key_desc_sequence[current_index]) # SecurityLevel enum
        current_index += 1
        parsed_data['keymint_or_keymaster_version'] = int(key_desc_sequence[current_index])
        current_index += 1
        parsed_data['keymint_or_keymaster_security_level'] = int(key_desc_sequence[current_index]) # SecurityLevel enum
        current_index += 1
        parsed_data['attestation_challenge'] = bytes(key_desc_sequence[current_index]) # OCTET STRING
        current_index += 1

        # uniqueId is optional, OCTET STRING
        if len(key_desc_sequence) > current_index and isinstance(key_desc_sequence[current_index], univ.OctetString):
            parsed_data['unique_id'] = bytes(key_desc_sequence[current_index]).hex()
            current_index += 1
        else:
            # If not present, it's not an error, just means it wasn't included.
            # Could be a NULL or the next sequence (software_enforced)
            # The schema implies unique_id is an OCTET STRING if present.
            # If the next item is a SEQUENCE, it's software_enforced.
            parsed_data['unique_id'] = None


        # softwareEnforced is a AuthorizationList (SEQUENCE)
        if len(key_desc_sequence) > current_index and isinstance(key_desc_sequence[current_index], univ.Sequence):
            sw_enforced_seq = key_desc_sequence[current_index]
            parsed_data['software_enforced'] = parse_authorization_list(sw_enforced_seq, parsed_data.get('attestation_version'))
            current_index += 1
        else:
            # This field is mandatory. If it's not a sequence, it's a format error.
            # However, to be robust, initialize to empty if parsing fails or structure is unexpected.
            logger.warning("Software enforced properties not found or not a sequence as expected.")
            parsed_data['software_enforced'] = {}


        # hardwareEnforced is a AuthorizationList (SEQUENCE)
        if len(key_desc_sequence) > current_index and isinstance(key_desc_sequence[current_index], univ.Sequence):
            hw_enforced_seq = key_desc_sequence[current_index]
            parsed_data['hardware_enforced'] = parse_authorization_list(hw_enforced_seq, parsed_data.get('attestation_version'))
            current_index += 1
        else:
            # This field is mandatory.
            logger.warning("Hardware enforced properties not found or not a sequence as expected.")
            parsed_data['hardware_enforced'] = {}

        # For KeyMint version 200 (Android T / attestation version 4) and above,
        # there's an optional VerifiedBootState field.
        # And for KeyMint version 100 (Android S / attestation version 3) and above,
        # there's an optional DeviceUniqueAttestation field (KeyMint v2 only - tag 720)
        # The schema shows:
        #   KeyDescription ::= SEQUENCE {
        #       keymasterVersion                   INTEGER,
        #       keymasterSecurityLevel             SecurityLevel,
        #       attestationChallenge               OCTET_STRING,
        #       uniqueId                           OCTET_STRING OPTIONAL,
        #       softwareEnforced                   AuthorizationList,
        #       teeEnforced                        AuthorizationList,
        #       -- KM4: The following two fields were added in Keymaster 4.0.
        #       -- Attestation v3 (KM4) adds these:
        #       -- vendorPatchLevel                 INTEGER OPTIONAL,
        #       -- bootPatchLevel                   INTEGER OPTIONAL,
        #       -- Attestation v4 (KM4.1/KeyMint) adds this:
        #       -- individualAttestation            NULL OPTIONAL, -- This is actually DeviceUniqueAttestation as per docs.
        #   }
        # The structure from the `cryptography` library for X.509 parsing suggests
        # the extension value is a SEQUENCE.
        # Let's check the official ASN.1 definition from AOSP:
        # KeyDescription ::= SEQUENCE {
        #    attestationVersion         INTEGER,    -- Version of the attestation data structure
        #    attestationSecurityLevel   SecurityLevel, -- Security level of the attestation
        #    keymasterVersion           INTEGER,    -- Version of Keymaster/KeyMint HAL
        #    keymasterSecurityLevel     SecurityLevel, -- Security level of Keymaster/KeyMint
        #    attestationChallenge       OCTET STRING, -- Challenge from the server
        #    uniqueId                   OCTET STRING OPTIONAL, -- Used for rate limiting
        #    softwareEnforced           AuthorizationList, -- Software-enforced properties
        #    teeEnforced                AuthorizationList, -- TEE-enforced properties
        #    -- New optional fields for KeyMint versions
        #    -- For attestationVersion >= 4 (KeyMint v200 / Android T)
        #    deviceUniqueAttestation    NULL OPTIONAL
        # }
        # The `deviceUniqueAttestation` field is at the end.

        if parsed_data.get('attestation_version') >= 4 and len(key_desc_sequence) > current_index:
             if isinstance(key_desc_sequence[current_index], univ.Null):
                parsed_data['device_unique_attestation_flag_present'] = True # Indicates the NULL field was present
                current_index += 1
        # Note: The actual boolean value for 'device_unique_attestation' is typically found within
        # the hardware_enforced properties under TAG_DEVICE_UNIQUE_ATTESTATION (720).
        # The NULL at the end of KeyDescription is more of a flag indicating it *could* be present.


    except (IndexError, ValueError, PyAsn1Error, TypeError) as e:
        logger.error(f'Error processing parsed KeyDescription sequence: {e}. Structure might be unexpected. Sequence: {key_desc_sequence.prettyPrint() if hasattr(key_desc_sequence, "prettyPrint") else key_desc_sequence}')
        # Consider what to return or if to re-raise. Returning partial data might be risky.
        # For now, re-raise as it indicates a significant parsing problem.
        raise ValueError(f'Malformed or unexpected KeyDescription structure: {e}')
    return parsed_data

def get_attestation_extension_properties(certificate):
    """
    Finds and parses the Android Key Attestation extension from a certificate.
    Returns a dictionary of properties or None if not found/parsed.
    """
    try:
        # Use the OID defined above
        ext = certificate.extensions.get_extension_for_oid(OID_ANDROID_KEY_ATTESTATION)
        if not ext: # Should raise ExtensionNotFound if not present, but double check
            logger.warning('Android Key Attestation extension not found in certificate (get_extension_for_oid returned None).')
            return None
    except x509.ExtensionNotFound:
        logger.warning(f'Android Key Attestation extension (OID {OID_ANDROID_KEY_ATTESTATION}) not found.')
        return None
    except Exception as e: # Catch any other errors during extension retrieval
        logger.error(f"Error retrieving attestation extension: {e}")
        return None


    # The ext.value of an X.509 extension is an object representing the parsed extension value.
    # For Android Key Attestation, this value is DER-encoded ASN.1 sequence (KeyDescription).
    # The `cryptography` library usually provides this as `UnrecognizedExtension.value` (bytes)
    # if it doesn't have a specific parser for this OID.
    # If it's already parsed into a structured type by `cryptography` (unlikely for this custom OID),
    # we'd need to handle that. For now, assume it's bytes.

    key_description_bytes = None
    if isinstance(ext.value, x509.UnrecognizedExtension):
        key_description_bytes = ext.value.value # This should be the raw bytes of the extension
    elif isinstance(ext.value, bytes): # If for some reason it's directly bytes
        key_description_bytes = ext.value
    else:
        logger.error(f'Unexpected type for attestation extension value: {type(ext.value)}. Value: {ext.value}')
        # This could happen if `cryptography` adds a specific parser for this OID in the future
        # and it's not just raw bytes.
        raise ValueError(f'Unexpected type for attestation extension value: {type(ext.value)}')

    if not key_description_bytes:
        logger.error('Attestation extension found but its value (KeyDescription bytes) is empty or None.')
        return None

    logger.info(f'KeyDescription bytes length from extension: {len(key_description_bytes)}')
    try:
        attestation_properties = parse_key_description(key_description_bytes)
        return attestation_properties
    except ValueError as e: # Catch parsing errors from parse_key_description
        logger.error(f'Failed to parse KeyDescription from attestation extension: {e}')
        raise # Re-raise to indicate parsing failure to the caller
    except Exception as e: # Catch any other unexpected errors
        logger.error(f'An unexpected error occurred while parsing KeyDescription: {e}')
        raise

# Example of how this might be used (for testing or direct use):
# from cryptography.hazmat.primitives import serialization
# cert_pem = """-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----"""
# cert_bytes = cert_pem.encode('utf-8')
# cert = x509.load_pem_x509_certificate(cert_bytes)
# properties = get_attestation_extension_properties(cert)
# if properties:
#     print(json.dumps(properties, indent=2))
