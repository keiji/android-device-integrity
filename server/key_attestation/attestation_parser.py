import base64
import logging
from cryptography import x509
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type import univ, namedtype, namedval, tag # Added namedtype, namedval, tag
from pyasn1.error import PyAsn1Error

logger = logging.getLogger(__name__)

# --- ASN.1 Type Definitions for pyasn1 ---

class VerifiedBootState(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('Verified', 0),
        ('SelfSigned', 1),
        ('Unverified', 2),
        ('Failed', 3)
    )

class RootOfTrustAsn1(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('verifiedBootKey', univ.OctetString()),
        namedtype.NamedType('deviceLocked', univ.Boolean()),
        namedtype.NamedType('verifiedBootState', VerifiedBootState()),
        namedtype.NamedType('verifiedBootHash', univ.OctetString())
    )

# --- End ASN.1 Type Definitions ---

def _parse_root_of_trust_from_asn1_obj(decoded_rot_obj: RootOfTrustAsn1) -> dict:
    """ Parses the RootOfTrust dictionary from a pyasn1 decoded RootOfTrustAsn1 object. """
    parsed_data = {}
    try:
        parsed_data['verified_boot_key'] = bytes(decoded_rot_obj.getComponentByName('verifiedBootKey')).hex()
        parsed_data['device_locked'] = bool(decoded_rot_obj.getComponentByName('deviceLocked'))
        # For ENUMERATED, pyasn1 gives the integer value directly
        parsed_data['verified_boot_state'] = int(decoded_rot_obj.getComponentByName('verifiedBootState'))
        parsed_data['verified_boot_hash'] = bytes(decoded_rot_obj.getComponentByName('verifiedBootHash')).hex()
    except (TypeError, ValueError, PyAsn1Error, AttributeError) as e: # Added AttributeError for getComponentByName
        logger.error(f"Error parsing fields from RootOfTrustAsn1 object: {e}. Object was: {decoded_rot_obj.prettyPrint() if hasattr(decoded_rot_obj, 'prettyPrint') else decoded_rot_obj}")
        # Fallback or re-raise depending on how critical this is
        return {
            'verified_boot_key': "", 'device_locked': False,
            'verified_boot_state': -1, 'verified_boot_hash': "" # Indicate error
        }
    return parsed_data

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

# NOTE: The original parse_root_of_trust is now replaced by _parse_root_of_trust_from_asn1_obj
# if this schema-based approach is fully adopted. For now, keeping the old one
# available if we need to revert or if other parts of code use it directly, though it's not used by the modified path.
# def parse_root_of_trust(root_of_trust_sequence): ... (original function)


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

    # Aligning with reference code's structure (b5f506e)
    parsed_data = {} # Reference initializes an empty dict, then adds keys like 'attestation_application_id'

    # Reference: if not isinstance(attestation_application_id_sequence, univ.SequenceOf): return parsed_data
    # Current app_id_seq is already decoded from bytes.
    # Reference expects `attestation_application_id_sequence` (our `app_id_seq`) to be SequenceOf according to its check,
    # but then accesses it like a Sequence: `app_id_seq[0][0]`
    # This implies app_id_seq might be a Sequence wrapping a SequenceOf or similar structure in practice for the reference.
    # For now, trying to match the access pattern of b5f506e as closely as possible.
    # The b5f506e structure:
    # AttestationApplicationId ::= SEQUENCE { // This is what app_id_seq is based on schema
    #    packageInfos SET OF PackageInfo, // app_id_seq[0]
    #    signatureDigests SET OF OCTET_STRING // app_id_seq[1]
    # }
    # PackageInfo ::= SEQUENCE { packageName UTF8String, version INTEGER }

    # b5f506e code:
    # package_info_sequence = attestation_application_id_sequence[0][0]
    # This [0][0] access is unusual if attestation_application_id_sequence is directly the AttestationApplicationId above.
    # It would imply attestation_application_id_sequence is something like: SEQUENCE { actual_att_app_id_seq AttestationApplicationId }
    # Or, if `univ.SequenceOf` was treated as `univ.Sequence` containing one element which is `univ.SequenceOf`.
    # Given the ASN.1 schema, app_id_seq[0] should be the SET OF PackageInfo.
    # And app_id_seq[0][0] would be the first PackageInfo sequence from that set.
    # The reference code's `package_info_sequence.items()` is the main non-standard part for a single PackageInfo.

    # Let's assume `app_id_seq` is the main `AttestationApplicationId ::= SEQUENCE`
    if not isinstance(app_id_seq, univ.Sequence) or len(app_id_seq) < 2: # Basic check
        logger.warning('AttestationApplicationId is not a SEQUENCE or has too few elements for b5f506e structure.')
        return parsed_data # Return empty dict as per reference's implicit behavior

    # packageInfos_set_or_seq = app_id_seq[0] # This should be the SET OF PackageInfo
    # The reference code `package_info_sequence = attestation_application_id_sequence[0][0]`
    # seems to imply it's picking the *first* PackageInfo from the set and then iterating its fields using `.items()`.
    # This is very specific and would only parse the first package if multiple exist.

    # Replicating b5f506e's logic for package info (parsing only the first package info's fields):
    # It seems b5f506e intends to get the first PackageInfo sequence.
    package_infos_outer = app_id_seq[0] # This should be SET OF PackageInfo
    if isinstance(package_infos_outer, univ.SetOf) and len(package_infos_outer) > 0:
        package_info_sequence = package_infos_outer[0] # Get the first PackageInfo SEQUENCE
        if isinstance(package_info_sequence, univ.Sequence):
            # Reference: items = package_info_sequence.items()
            # This is the non-standard part. It implies package_info_sequence was dict-like.
            # If it's a pyasn1 Sequence, .items() is not standard.
            # Mimicking the effect: access by index for known structure of PackageInfo (name, version)
            if len(package_info_sequence) >= 1: # packageName
                 # b5f506e uses str(value_component) where value_component is item[1] from .items()
                 # For a sequence element, just str() is fine.
                parsed_data['attestation_application_id'] = str(package_info_sequence[0]) # packageName
            if len(package_info_sequence) >= 2: # version
                parsed_data['attestation_application_version_code'] = int(package_info_sequence[1]) # version
        else:
            logger.warning(f"First PackageInfo in AttestationApplicationId is not a SEQUENCE: {package_info_sequence}")
    elif isinstance(package_infos_outer, univ.Sequence) and len(package_infos_outer) > 0 :
        # Fallback if it was a Sequence of PackageInfo instead of SetOf
        package_info_sequence = package_infos_outer[0]
        if isinstance(package_info_sequence, univ.Sequence):
            if len(package_info_sequence) >= 1:
                parsed_data['attestation_application_id'] = str(package_info_sequence[0])
            if len(package_info_sequence) >= 2:
                parsed_data['attestation_application_version_code'] = int(package_info_sequence[1])
        else:
            logger.warning(f"First PackageInfo in AttestationApplicationId (Sequence case) is not a SEQUENCE: {package_info_sequence}")
    else:
        logger.warning(f"packageInfos in AttestationApplicationId is not SetOf/SequenceOf or is empty: {package_infos_outer}")


    # Replicating b5f506e's logic for signatures
    signatures = []
    signature_set = app_id_seq[1] # This should be SET OF OCTET_STRING
    if isinstance(signature_set, univ.SetOf):
        # Reference: for index, item in enumerate(signature_set): signatures.append(bytes(item).hex())
        # This is standard for iterating a SetOf.
        for item_octet_string in signature_set:
            if isinstance(item_octet_string, univ.OctetString):
                signatures.append(bytes(item_octet_string).hex())
            else:
                logger.warning(f"Item in signature_set is not OctetString: {item_octet_string}")
    else:
        logger.warning(f"signatureDigests in AttestationApplicationId is not a SetOf: {signature_set}")
    parsed_data['application_signatures'] = signatures

    return parsed_data


def parse_authorization_list(auth_list_sequence, attestation_version):
    """
    Parses an AuthorizationList SEQUENCE using pyasn1.
    Returns a dictionary of parsed properties.
    """
    parsed_props = {}
    if not isinstance(auth_list_sequence, univ.Sequence):
        # Reference code doesn't explicitly log this but returns empty. Consistent.
        return parsed_props

    # Aligning with reference code's iteration style (b5f506e)
    # This iteration style is non-standard for pyasn1 univ.Sequence
    # and may rely on specific pyasn1 version behavior or a pre-processed sequence.
    for item in auth_list_sequence.items():
        try:
            # Aligning with reference code's tag and value extraction
            tag_set = item[1].tagSet
            tag_number = tag_set.superTags[1].tagId
            value_component = item[1] # In reference, this 'item[1]' is used as the value directly
        except (AttributeError, IndexError, TypeError): # Match reference error types if possible
            logger.warning(f"Could not get tag from item: {item}") # Reference log
            continue

        try:
            # Mirroring the if/elif structure and value processing from b5f506e
            if tag_number == TAG_ATTESTATION_APPLICATION_ID:
                # Assuming value_component is OctetString bytes as in reference
                parsed_props['attestation_application_id'] = parse_attestation_application_id(bytes(value_component))
            elif tag_number == TAG_OS_VERSION:
                parsed_props['os_version'] = int(value_component)
            elif tag_number == TAG_OS_PATCH_LEVEL:
                parsed_props['os_patch_level'] = int(value_component)
            elif tag_number == TAG_DIGEST: # SET OF INTEGER
                # Reference: digests = [int(p) for p in value_component]
                # This assumes value_component is directly iterable (like a pyasn1 SetOf/SequenceOf)
                parsed_props['digests'] = [int(p) for p in value_component]
            elif tag_number == TAG_PURPOSE:  # SET OF INTEGER
                parsed_props['purpose'] = [int(p) for p in value_component]
            elif tag_number == TAG_ALGORITHM:
                parsed_props['algorithm'] = int(value_component)
            elif tag_number == TAG_EC_CURVE:
                parsed_props['ec_curve'] = int(value_component)
            elif tag_number == TAG_RSA_PUBLIC_EXPONENT:
                parsed_props['rsa_public_exponent'] = int(value_component)
            elif tag_number == TAG_MGF_DIGEST: # SET OF INTEGER in reference
                parsed_props['mgf_digest'] = [int(p) for p in value_component]
            elif tag_number == TAG_KEY_SIZE:
                parsed_props['key_size'] = int(value_component)
            elif tag_number == TAG_NO_AUTH_REQUIRED:  # NULL
                parsed_props['no_auth_required'] = True
            elif tag_number == TAG_CREATION_DATETIME:
                parsed_props['creation_datetime'] = int(value_component)
            elif tag_number == TAG_ORIGIN: # Reference uses str()
                parsed_props['origin'] = str(value_component)
            elif tag_number == TAG_VENDOR_PATCH_LEVEL: # Present in b5f506e constants and parser
                parsed_props['vendor_patch_level'] = int(value_component)
            elif tag_number == TAG_BOOT_PATCH_LEVEL: # Present in b5f506e constants and parser
                parsed_props['boot_patch_level'] = int(value_component)
            elif tag_number == TAG_ATTESTATION_ID_BRAND: # Reference uses str()
                parsed_props['attestation_id_brand'] = str(value_component)
            elif tag_number == TAG_ATTESTATION_ID_DEVICE: # Reference uses str()
                parsed_props['attestation_id_device'] = str(value_component)
            elif tag_number == TAG_ATTESTATION_ID_PRODUCT: # Reference uses str()
                parsed_props['attestation_id_product'] = str(value_component)
            elif tag_number == TAG_ATTESTATION_ID_SERIAL: # Reference uses str()
                parsed_props['attestation_id_serial'] = str(value_component)
            elif tag_number == TAG_ATTESTATION_ID_MANUFACTURER: # Reference uses str()
                parsed_props['attestation_id_manufacturer'] = str(value_component)
            elif tag_number == TAG_ATTESTATION_ID_MODEL: # Reference uses str()
                parsed_props['attestation_id_model'] = str(value_component)
            elif tag_number == TAG_MODULE_HASH: # OCTET_STRING in reference
                 # Assuming value_component is OctetString bytes
                parsed_props['module_hash'] = base64.urlsafe_b64encode(bytes(value_component)).decode()
            elif tag_number == TAG_ROOT_OF_TRUST: # SEQUENCE (handled with schema)
                # value_component is the EXPLICITLY tagged RootOfTrust.
                # The actual RootOfTrust SEQUENCE is the single component of its constructed value.
                # pyasn1 typically represents this as a SequenceOf containing one element,
                # or the component itself is a Sequence.
                # We need to get the bytes of this inner SEQUENCE.
                if value_component and len(value_component) > 0:
                    # The EXPLICIT wrapper means value_component itself is a new type
                    # containing the original type (RootOfTrustAsn1).
                    # For pyasn1, when an EXPLICIT tag is applied, the resulting object
                    # often has the original object as its first (and only) component.
                    inner_sequence_obj = value_component.getComponentByPosition(0)
                    rot_bytes = der_encoder.encode(inner_sequence_obj) # Encode the specific RootOfTrustAsn1 part

                    decoded_rot, _ = der_decoder.decode(rot_bytes, asn1Spec=RootOfTrustAsn1())
                    parsed_props['root_of_trust'] = _parse_root_of_trust_from_asn1_obj(decoded_rot)
                else:
                    logger.warning(f"TAG_ROOT_OF_TRUST: value_component is empty or not structured as expected: {value_component}")
                    parsed_props['root_of_trust'] = {} # Or raise error
            # Tags explicitly NOT handled by b5f506e's if/elif but present in its constants or newer Android versions:
            # TAG_PADDING, TAG_ROLLBACK_RESISTANCE, TAG_EARLY_BOOT_ONLY, TAG_ACTIVE_DATETIME,
            # TAG_ORIGINATION_EXPIRE_DATETIME, TAG_USAGE_EXPIRE_DATETIME, TAG_USAGE_COUNT_LIMIT,
            # TAG_USER_AUTH_TYPE, TAG_AUTH_TIMEOUT, TAG_ALLOW_WHILE_ON_BODY,
            # TAG_TRUSTED_USER_PRESENCE_REQUIRED, TAG_TRUSTED_CONFIRMATION_REQUIRED,
            # TAG_UNLOCKED_DEVICE_REQUIRED, TAG_ATTESTATION_ID_IMEI, TAG_ATTESTATION_ID_MEID,
            # TAG_DEVICE_UNIQUE_ATTESTATION, TAG_ATTESTATION_ID_SECOND_IMEI.
            # These will fall into the 'else' block below, matching b5f506e's behavior.
            else:
                # Reference code's unknown tag logging
                logger.warning("Unknown tag:%d, %s" % (tag_number, value_component))
                # To fully mimic, we might not store unknown tags, or store them as per reference if it did.
                # The reference log doesn't show it storing them, so we won't by default.

        except (PyAsn1Error, ValueError, TypeError) as e: # Match reference error types
            # Reference log format
            logger.warning(
                f"Error parsing tag {tag_number} in AuthorizationList: {e}. Value component: {value_component}")
            # Make parsing stricter: if any tag fails, the whole list parsing fails.
            raise ValueError(f"Failed to parse tag {tag_number} in AuthorizationList: {e}") from e
    return parsed_props


def parse_key_description(key_desc_bytes):
    """
    Parses the KeyDescription SEQUENCE from the attestation extension using pyasn1.
    Returns a dictionary containing key properties.
    """
    key_desc_sequence = None
    MIN_KEY_DESC_COMPONENTS = 5 # attestationVersion, attestationSecurityLevel, keymasterVersion, keymasterSecurityLevel, attestationChallenge

    try:
        key_desc_sequence, rest = der_decoder.decode(key_desc_bytes)

        if not key_desc_sequence or not isinstance(key_desc_sequence, univ.Sequence) or len(key_desc_sequence) < MIN_KEY_DESC_COMPONENTS:
            # This log might still be useful even if debug is off generally, as it's an error condition.
            logger.error(f"Decoded KeyDescription is not a valid sequence or too short. Type: {type(key_desc_sequence)}, Length: {len(key_desc_sequence) if hasattr(key_desc_sequence, '__len__') else 'N/A'}")
            # Avoid logging the full sequence in non-debug, it can be large.
            raise ValueError('Decoded KeyDescription is not a valid/complete ASN.1 SEQUENCE.')

    except PyAsn1Error as e:
        logger.error(f'Failed to decode KeyDescription ASN.1 sequence with pyasn1: {e}')
        # Avoid logging full key_desc_bytes in non-debug for potentially sensitive data or large size.
        raise ValueError('Malformed KeyDescription sequence.') from e

    parsed_data = {}
    try:
        # Using idx naming and logic closer to reference version
        idx = 0
        # Attestation Version
        if not isinstance(key_desc_sequence[idx], univ.Integer):
            raise ValueError(f"Expected Integer for attestation_version at index {idx}, got {type(key_desc_sequence[idx])}: {key_desc_sequence[idx]}")
        parsed_data['attestation_version'] = int(key_desc_sequence[idx])
        idx += 1

        # Attestation Security Level
        if not isinstance(key_desc_sequence[idx], univ.Integer): # ENUMERATED is an Integer subclass
            raise ValueError(f"Expected Integer/Enum for attestation_security_level at index {idx}, got {type(key_desc_sequence[idx])}: {key_desc_sequence[idx]}")
        parsed_data['attestation_security_level'] = int(key_desc_sequence[idx])
        idx += 1

        # KeyMint/Keymaster Version
        if not isinstance(key_desc_sequence[idx], univ.Integer):
            raise ValueError(f"Expected Integer for keymint_or_keymaster_version at index {idx}, got {type(key_desc_sequence[idx])}: {key_desc_sequence[idx]}")
        parsed_data['keymint_or_keymaster_version'] = int(key_desc_sequence[idx])
        idx += 1

        # KeyMint/Keymaster Security Level
        if not isinstance(key_desc_sequence[idx], univ.Integer): # ENUMERATED is an Integer subclass
            raise ValueError(f"Expected Integer/Enum for keymint_or_keymaster_security_level at index {idx}, got {type(key_desc_sequence[idx])}: {key_desc_sequence[idx]}")
        parsed_data['keymint_or_keymaster_security_level'] = int(key_desc_sequence[idx])
        idx += 1

        # Attestation Challenge
        if not isinstance(key_desc_sequence[idx], univ.OctetString):
            raise ValueError(f"Expected OctetString for attestation_challenge at index {idx}, got {type(key_desc_sequence[idx])}: {key_desc_sequence[idx]}")
        parsed_data['attestation_challenge'] = bytes(key_desc_sequence[idx])
        idx += 1

        # uniqueId is optional OCTET STRING (reference: idx 5)
        if len(key_desc_sequence) > idx and isinstance(key_desc_sequence[idx], univ.OctetString):
            parsed_data['unique_id'] = bytes(key_desc_sequence[idx]).hex()
            idx += 1
        else:
            parsed_data['unique_id'] = None # Reference behavior implies it might not increment idx if not found

        # softwareEnforced AuthorizationList (reference: idx after uniqueId)
        if len(key_desc_sequence) > idx and isinstance(key_desc_sequence[idx], univ.Sequence):
            sw_enforced_seq = key_desc_sequence[idx]
            parsed_data['software_enforced'] = parse_authorization_list(
                sw_enforced_seq,
                parsed_data.get('attestation_version')
            )
            idx += 1
        else:
            logger.warning("Software enforced properties not found or not a sequence as expected.")
            parsed_data['software_enforced'] = {}

        # hardwareEnforced AuthorizationList (reference: idx after softwareEnforced)
        if len(key_desc_sequence) > idx and isinstance(key_desc_sequence[idx], univ.Sequence):
            hw_enforced_seq = key_desc_sequence[idx]
            parsed_data['hardware_enforced'] = parse_authorization_list(
                hw_enforced_seq,
                parsed_data.get('attestation_version')
            )
            idx += 1
        else:
            logger.warning("Hardware enforced properties not found or not a sequence as expected.")
            parsed_data['hardware_enforced'] = {}

        # Reference version's specific check for a trailing NULL for device_unique_attestation
        # if attestation_version is 4.
        # Reference: if parsed_data.get('attestation_version') == 4 and len(key_desc_sequence) > idx:
        #                if isinstance(key_desc_sequence[idx], univ.Null):
        #                    parsed_data['device_unique_attestation'] = True
        # This implies the 'device_unique_attestation' key should be set.
        if parsed_data.get('attestation_version') == 4 and len(key_desc_sequence) > idx:
            if isinstance(key_desc_sequence[idx], univ.Null):
                parsed_data['device_unique_attestation'] = True # Using key name from reference
                # idx += 1 # Reference didn't show incrementing idx here, but it would be logical if this was consumed.
                           # For safety and closer match, will not increment based on reference's visible logic.
            # else: # Ensure the key is not present if the condition isn't met, or set to False?
                  # Reference code implies it's only added if True.
                  # To match reference, only add if true.
            # Based on reference, idx is not incremented after this check.

    except (IndexError, ValueError, PyAsn1Error, TypeError) as e:
        seq_repr = getattr(key_desc_sequence, "prettyPrint", lambda: str(key_desc_sequence))()
        logger.error(f'Error processing parsed KeyDescription sequence: {e}. Structure might be unexpected. Sequence: {seq_repr}')
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
