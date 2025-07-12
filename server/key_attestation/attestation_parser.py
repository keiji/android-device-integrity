import base64
import logging
from cryptography import x509
from pyasn1.codec.der import decoder as der_decoder, encoder as der_encoder # Added der_encoder
from pyasn1.type import univ, namedtype, namedval, tag, constraint

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

# --- ASN.1 Schema Definitions for KeyDescription ---
class KeyDescriptionTopLevelSchema(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('attestationVersion', univ.Integer()),
        namedtype.NamedType('attestationSecurityLevel', univ.Integer()),
        namedtype.NamedType('keymasterVersion', univ.Integer()),
        namedtype.NamedType('keymasterSecurityLevel', univ.Integer()),
        namedtype.NamedType('attestationChallenge', univ.OctetString()),
        namedtype.OptionalNamedType('uniqueId', univ.OctetString()),
        namedtype.NamedType('softwareEnforced', univ.Any()), # Changed from univ.Sequence to univ.Any
        namedtype.NamedType('hardwareEnforced', univ.Any()), # Changed from univ.Sequence to univ.Any
        namedtype.OptionalNamedType('deviceUniqueAttestation', univ.Null())
    )
# --- End KeyDescription Schema ---

class ExtremelySimpleKeyDescriptionSchema(univ.Sequence): # For testing
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('attestationVersion', univ.Integer())
    )

def _parse_root_of_trust_from_asn1_obj(decoded_rot_obj: RootOfTrustAsn1) -> dict:
    """ Parses the RootOfTrust dictionary from a pyasn1 decoded RootOfTrustAsn1 object. """
    parsed_data = {}
    try:
        parsed_data['verified_boot_key'] = bytes(decoded_rot_obj.getComponentByName('verifiedBootKey')).hex()
        parsed_data['device_locked'] = bool(decoded_rot_obj.getComponentByName('deviceLocked'))
        parsed_data['verified_boot_state'] = int(decoded_rot_obj.getComponentByName('verifiedBootState'))
        parsed_data['verified_boot_hash'] = bytes(decoded_rot_obj.getComponentByName('verifiedBootHash')).hex()
    except (TypeError, ValueError, PyAsn1Error, AttributeError) as e:
        logger.error(f"Error parsing fields from RootOfTrustAsn1 object: {e}. Object was: {decoded_rot_obj.prettyPrint() if hasattr(decoded_rot_obj, 'prettyPrint') else decoded_rot_obj}")
        return {
            'verified_boot_key': "", 'device_locked': False,
            'verified_boot_state': -1, 'verified_boot_hash': ""
        }
    return parsed_data

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


def parse_attestation_application_id(attestation_application_id_bytes):
    try:
        app_id_seq, _ = der_decoder.decode(attestation_application_id_bytes)
    except PyAsn1Error as e:
        logger.error(f'Failed to decode AttestationApplicationId inner sequence: {e}')
        raise ValueError('Malformed AttestationApplicationId inner sequence.')

    if not isinstance(app_id_seq, univ.Sequence) or len(app_id_seq) < 2:
        logger.error('AttestationApplicationId is not a SEQUENCE or has too few elements.')
        raise ValueError('AttestationApplicationId not a valid SEQUENCE.')

    parsed_data = {}
    package_infos_outer = app_id_seq[0]
    if isinstance(package_infos_outer, univ.SetOf) and len(package_infos_outer) > 0:
        package_info_sequence = package_infos_outer[0]
        if isinstance(package_info_sequence, univ.Sequence):
            if len(package_info_sequence) >= 1:
                parsed_data['attestation_application_id'] = str(package_info_sequence[0])
            if len(package_info_sequence) >= 2:
                parsed_data['attestation_application_version_code'] = int(package_info_sequence[1])
        else:
            logger.warning(f"First PackageInfo in AttestationApplicationId is not a SEQUENCE: {package_info_sequence}")
    elif isinstance(package_infos_outer, univ.Sequence) and len(package_infos_outer) > 0 :
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

    signatures = []
    signature_set = app_id_seq[1]
    if isinstance(signature_set, univ.SetOf):
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
    parsed_props = {}
    if not isinstance(auth_list_sequence, univ.Sequence):
        return parsed_props

    for item in auth_list_sequence.items():
        try:
            tag_set = item[1].tagSet
            tag_number = tag_set.superTags[1].tagId
            value_component = item[1]
        except (AttributeError, IndexError, TypeError):
            logger.warning(f"Could not get tag from item: {item}")
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
                parsed_props['origin'] = str(value_component)
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
                if value_component and len(value_component) > 0:
                    inner_sequence_obj = value_component.getComponentByPosition(0)
                    rot_bytes = der_encoder.encode(inner_sequence_obj)
                    decoded_rot, _ = der_decoder.decode(rot_bytes, asn1Spec=RootOfTrustAsn1())
                    parsed_props['root_of_trust'] = _parse_root_of_trust_from_asn1_obj(decoded_rot)
                else:
                    logger.warning(f"TAG_ROOT_OF_TRUST: value_component is empty or not structured as expected: {value_component}")
                    parsed_props['root_of_trust'] = {}
            else:
                logger.warning("Unknown tag:%d, %s" % (tag_number, value_component))
        except (PyAsn1Error, ValueError, TypeError) as e:
            logger.warning(
                f"Error parsing tag {tag_number} in AuthorizationList: {e}. Value component: {value_component}")
            raise ValueError(f"Failed to parse tag {tag_number} in AuthorizationList: {e}") from e
    return parsed_props


def parse_key_description(key_desc_bytes):
    """
    Parses the KeyDescription SEQUENCE from the attestation extension using pyasn1.
    Returns a dictionary containing key properties.
    """
    key_desc_obj = None

    print(f"DEBUG_PRINT: AttestationParser: Raw key_desc_bytes (first 64 bytes): {key_desc_bytes[:64].hex() if key_desc_bytes else 'None'}")

    try:
        # Use the defined schema KeyDescriptionTopLevelSchema
        # key_desc_obj, rest = der_decoder.decode(key_desc_bytes, asn1Spec=KeyDescriptionTopLevelSchema()) # Using full schema
        key_desc_obj, rest = der_decoder.decode(key_desc_bytes, asn1Spec=ExtremelySimpleKeyDescriptionSchema()) # Using simple schema for test

        print(f"DEBUG_PRINT: AttestationParser: Type of decoded key_desc_obj: {type(key_desc_obj)}")
        print(f"DEBUG_PRINT: AttestationParser: repr(key_desc_obj): {repr(key_desc_obj)}")
        if hasattr(key_desc_obj, 'prettyPrint'):
            print(f"DEBUG_PRINT: AttestationParser: key_desc_obj.prettyPrint():\n{key_desc_obj.prettyPrint()}")
        else:
            print(f"DEBUG_PRINT: AttestationParser: key_desc_obj has no prettyPrint method.")
        print(f"DEBUG_PRINT: AttestationParser: Length of rest: {len(rest)}")

    except PyAsn1Error as e:
        logger.error(f'Failed to decode KeyDescription ASN.1 sequence with pyasn1 using schema: {e}')
        print(f"DEBUG_PRINT: AttestationParser: PyAsn1Error occurred during schema-based decode: {e}")
        raise ValueError('Malformed KeyDescription sequence (schema validation failed).') from e

    parsed_data = {}
    try:
        # Access components by name using the schema
        parsed_data['attestation_version'] = int(key_desc_obj.getComponentByName('attestationVersion'))
        parsed_data['attestation_security_level'] = int(key_desc_obj.getComponentByName('attestationSecurityLevel'))
        parsed_data['keymint_or_keymaster_version'] = int(key_desc_obj.getComponentByName('keymasterVersion'))
        parsed_data['keymint_or_keymaster_security_level'] = int(key_desc_obj.getComponentByName('keymasterSecurityLevel'))
        parsed_data['attestation_challenge'] = bytes(key_desc_obj.getComponentByName('attestationChallenge'))

        unique_id_comp = key_desc_obj.getComponentByName('uniqueId')
        if unique_id_comp is not None and unique_id_comp.isValue:
            parsed_data['unique_id'] = bytes(unique_id_comp).hex()
        else:
            parsed_data['unique_id'] = None

        sw_enforced_seq = key_desc_obj.getComponentByName('softwareEnforced')
        if sw_enforced_seq is None:
             logger.warning("Software enforced properties (softwareEnforced) is None after schema decoding.")
             parsed_data['software_enforced'] = {}
        else:
            if not isinstance(sw_enforced_seq, univ.Sequence):
                logger.error(f"softwareEnforced is not a univ.Sequence, but {type(sw_enforced_seq)}. Value: {sw_enforced_seq.prettyPrint() if hasattr(sw_enforced_seq, 'prettyPrint') else sw_enforced_seq}")
                if hasattr(sw_enforced_seq, 'items'):
                     parsed_data['software_enforced'] = parse_authorization_list(
                        sw_enforced_seq,
                        parsed_data.get('attestation_version')
                    )
                else:
                    parsed_data['software_enforced'] = {}
            else:
                 parsed_data['software_enforced'] = parse_authorization_list(
                    sw_enforced_seq,
                    parsed_data.get('attestation_version')
                )

        hw_enforced_seq = key_desc_obj.getComponentByName('hardwareEnforced')
        if hw_enforced_seq is None:
            logger.warning("Hardware enforced properties (hardwareEnforced) is None after schema decoding.")
            parsed_data['hardware_enforced'] = {}
        else:
            if not isinstance(hw_enforced_seq, univ.Sequence):
                logger.error(f"hardwareEnforced is not a univ.Sequence, but {type(hw_enforced_seq)}. Value: {hw_enforced_seq.prettyPrint() if hasattr(hw_enforced_seq, 'prettyPrint') else hw_enforced_seq}")
                if hasattr(hw_enforced_seq, 'items'):
                    parsed_data['hardware_enforced'] = parse_authorization_list(
                        hw_enforced_seq,
                        parsed_data.get('attestation_version')
                    )
                else:
                    parsed_data['hardware_enforced'] = {}
            else:
                parsed_data['hardware_enforced'] = parse_authorization_list(
                    hw_enforced_seq,
                    parsed_data.get('attestation_version')
                )

        device_unique_att_comp = key_desc_obj.getComponentByName('deviceUniqueAttestation')
        if device_unique_att_comp is not None and device_unique_att_comp.isValue:
             parsed_data['device_unique_attestation'] = True

    except (IndexError, ValueError, PyAsn1Error, TypeError, AttributeError) as e:
        seq_repr = getattr(key_desc_obj, "prettyPrint", lambda: str(key_desc_obj))()
        logger.error(f'Error processing parsed KeyDescription object: {e}. Structure might be unexpected. Object: {seq_repr}')
        print(f"DEBUG_PRINT: AttestationParser: Error processing KeyDescription object: {e}. Object (repr): {repr(key_desc_obj)}")
        raise ValueError(f'Malformed or unexpected KeyDescription structure: {e}')
    return parsed_data

def get_attestation_extension_properties(certificate):
    try:
        ext = certificate.extensions.get_extension_for_oid(OID_ANDROID_KEY_ATTESTATION)
        if not ext:
            logger.warning('Android Key Attestation extension not found in certificate (get_extension_for_oid returned None).')
            return None
    except x509.ExtensionNotFound:
        logger.warning(f'Android Key Attestation extension (OID {OID_ANDROID_KEY_ATTESTATION}) not found.')
        return None
    except Exception as e:
        logger.error(f"Error retrieving attestation extension: {e}")
        return None

    key_description_bytes = None
    if isinstance(ext.value, x509.UnrecognizedExtension):
        key_description_bytes = ext.value.value
    elif isinstance(ext.value, bytes):
        key_description_bytes = ext.value
    else:
        logger.error(f'Unexpected type for attestation extension value: {type(ext.value)}. Value: {ext.value}')
        raise ValueError(f'Unexpected type for attestation extension value: {type(ext.value)}')

    if not key_description_bytes:
        logger.error('Attestation extension found but its value (KeyDescription bytes) is empty or None.')
        return None

    # Using logger.info for this as it's less verbose than DEBUG_PRINT for general flow.
    logger.info(f'KeyDescription bytes length from extension: {len(key_description_bytes)}')
    try:
        attestation_properties = parse_key_description(key_description_bytes)
        return attestation_properties
    except ValueError as e:
        logger.error(f'Failed to parse KeyDescription from attestation extension: {e}')
        raise
    except Exception as e:
        logger.error(f'An unexpected error occurred while parsing KeyDescription: {e}')
        raise
