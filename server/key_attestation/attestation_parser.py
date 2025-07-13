import base64
import logging
from cryptography import x509
from pyasn1.codec.der import decoder as der_decoder, encoder as der_encoder
from pyasn1.type import univ, namedtype, namedval, tag, constraint
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

class SecurityLevel(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('software', 0),
        ('trustedEnvironment', 1),
        ('strongBox', 2)
    )

class AuthorizationList(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('purpose', univ.SetOf(componentType=univ.Integer()).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_PURPOSE))),
        namedtype.OptionalNamedType('algorithm', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_ALGORITHM))),
        namedtype.OptionalNamedType('keySize', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_KEY_SIZE))),
        namedtype.OptionalNamedType('digest', univ.SetOf(componentType=univ.Integer()).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_DIGEST))),
        namedtype.OptionalNamedType('padding', univ.SetOf(componentType=univ.Integer()).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_PADDING))),
        namedtype.OptionalNamedType('ecCurve', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_EC_CURVE))),
        namedtype.OptionalNamedType('rsaPublicExponent', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_RSA_PUBLIC_EXPONENT))),
        namedtype.OptionalNamedType('mgfDigest', univ.SetOf(componentType=univ.Integer()).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_MGF_DIGEST))),
        namedtype.OptionalNamedType('rollbackResistance', univ.Null().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, TAG_ROLLBACK_RESISTANCE))),
        namedtype.OptionalNamedType('earlyBootOnly', univ.Null().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, TAG_EARLY_BOOT_ONLY))),
        namedtype.OptionalNamedType('activeDateTime', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_ACTIVE_DATETIME))),
        namedtype.OptionalNamedType('originationExpireDateTime', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_ORIGINATION_EXPIRE_DATETIME))),
        namedtype.OptionalNamedType('usageExpireDateTime', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_USAGE_EXPIRE_DATETIME))),
        namedtype.OptionalNamedType('usageCountLimit', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_USAGE_COUNT_LIMIT))),
        namedtype.OptionalNamedType('noAuthRequired', univ.Null().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, TAG_NO_AUTH_REQUIRED))),
        namedtype.OptionalNamedType('userAuthType', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_USER_AUTH_TYPE))),
        namedtype.OptionalNamedType('authTimeout', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_AUTH_TIMEOUT))),
        namedtype.OptionalNamedType('allowWhileOnBody', univ.Null().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, TAG_ALLOW_WHILE_ON_BODY))),
        namedtype.OptionalNamedType('trustedUserPresenceRequired', univ.Null().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, TAG_TRUSTED_USER_PRESENCE_REQUIRED))),
        namedtype.OptionalNamedType('trustedConfirmationRequired', univ.Null().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, TAG_TRUSTED_CONFIRMATION_REQUIRED))),
        namedtype.OptionalNamedType('unlockedDeviceRequired', univ.Null().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, TAG_UNLOCKED_DEVICE_REQUIRED))),
        namedtype.OptionalNamedType('creationDateTime', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_CREATION_DATETIME))),
        namedtype.OptionalNamedType('origin', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_ORIGIN))),
        namedtype.OptionalNamedType('rootOfTrust', RootOfTrustAsn1().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_ROOT_OF_TRUST))),
        namedtype.OptionalNamedType('osVersion', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_OS_VERSION))),
        namedtype.OptionalNamedType('osPatchLevel', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_OS_PATCH_LEVEL))),
        namedtype.OptionalNamedType('attestationApplicationId', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_ATTESTATION_APPLICATION_ID))),
        namedtype.OptionalNamedType('attestationIdBrand', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_ATTESTATION_ID_BRAND))),
        namedtype.OptionalNamedType('attestationIdDevice', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_ATTESTATION_ID_DEVICE))),
        namedtype.OptionalNamedType('attestationIdProduct', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_ATTESTATION_ID_PRODUCT))),
        namedtype.OptionalNamedType('attestationIdSerial', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_ATTESTATION_ID_SERIAL))),
        namedtype.OptionalNamedType('attestationIdImei', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_ATTESTATION_ID_IMEI))),
        namedtype.OptionalNamedType('attestationIdMeid', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_ATTESTATION_ID_MEID))),
        namedtype.OptionalNamedType('attestationIdManufacturer', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_ATTESTATION_ID_MANUFACTURER))),
        namedtype.OptionalNamedType('attestationIdModel', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_ATTESTATION_ID_MODEL))),
        namedtype.OptionalNamedType('vendorPatchLevel', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_VENDOR_PATCH_LEVEL))),
        namedtype.OptionalNamedType('bootPatchLevel', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_BOOT_PATCH_LEVEL))),
        namedtype.OptionalNamedType('deviceUniqueAttestation', univ.Null().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, TAG_DEVICE_UNIQUE_ATTESTATION))),
        namedtype.OptionalNamedType('moduleHash', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, TAG_MODULE_HASH)))
    )

class KeyDescriptionSchemaV4(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('attestationVersion', univ.Integer()), # e.g., 400 for KeyMint 4.0
        namedtype.NamedType('attestationSecurityLevel', SecurityLevel()),
        namedtype.NamedType('keyMintVersion', univ.Integer()), # Changed from keymasterVersion for KeyMint
        namedtype.NamedType('keyMintSecurityLevel', SecurityLevel()), # Changed from keymasterSecurityLevel for KeyMint
        namedtype.NamedType('attestationChallenge', univ.OctetString()),
        namedtype.OptionalNamedType('uniqueId', univ.OctetString()),
        namedtype.NamedType('softwareEnforced', AuthorizationList()),
        namedtype.NamedType('hardwareEnforced', AuthorizationList())
    )
# --- End ASN.1 Schema Definitions ---

# --- Schemas for AttestationApplicationId ---
class AttestationPackageInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('packageName', univ.OctetString()),
        namedtype.NamedType('version', univ.Integer())
    )

class AttestationApplicationIdSchema(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('packageInfos', univ.SetOf(componentType=AttestationPackageInfo())),
        namedtype.NamedType('signatureDigests', univ.SetOf(componentType=univ.OctetString()))
    )
# --- End Schemas for AttestationApplicationId ---

def _parse_root_of_trust_from_asn1_obj(decoded_rot_obj: RootOfTrustAsn1) -> dict:
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
        app_id_obj, _ = der_decoder.decode(attestation_application_id_bytes, asn1Spec=AttestationApplicationIdSchema())
    except PyAsn1Error as e:
        logger.error(f'Failed to decode AttestationApplicationId with schema: {e}')
        # Fallback to generic decode for logging, then re-raise or raise specific error
        try:
            generic_app_id_obj, _ = der_decoder.decode(attestation_application_id_bytes)
            logger.debug(f"Generic decode of AppId: {generic_app_id_obj.prettyPrint() if hasattr(generic_app_id_obj, 'prettyPrint') else repr(generic_app_id_obj)}")
        except: # pylint: disable=bare-except
            pass # Ignore if generic decode also fails
        raise ValueError('Malformed AttestationApplicationId inner sequence (schema decode failed).') from e

    # logger.debug(f"PAAId: app_id_obj type: {type(app_id_obj)}")
    # if hasattr(app_id_obj, 'prettyPrint'):
    #     logger.debug(f"PAAId: app_id_obj prettyPrint: {app_id_obj.prettyPrint()}")
    # else:
    #     logger.debug(f"PAAId: app_id_obj (no prettyPrint): {repr(app_id_obj)}")
    # logger.debug(f"PAAId: app_id_obj length: {len(app_id_obj) if hasattr(app_id_obj, '__len__') else 'N/A'}")

    if not isinstance(app_id_obj, AttestationApplicationIdSchema): # Should be instance of schema
        logger.error(f'AttestationApplicationId not decoded as AttestationApplicationIdSchema, but as {type(app_id_obj)}.')
        raise ValueError('AttestationApplicationId not a valid schema instance.')

    parsed_data = {}
    package_infos_set = app_id_obj.getComponentByName('packageInfos')

    if package_infos_set.isValue and len(package_infos_set) > 0:
        # Assuming one AttestationPackageInfo as per typical Android usage
        # pyasn1 SetOf iteration can be direct or via getComponentByPosition if order is fixed (which it isn't for SET OF)
        # For simplicity, taking the first item if SET OF is not empty.
        package_info_item = None
        for item in package_infos_set: # Iterate over SET OF
            package_info_item = item # Take the first one
            break

        if package_info_item and isinstance(package_info_item, AttestationPackageInfo):
            pkg_name_comp = package_info_item.getComponentByName('packageName')
            pkg_version_comp = package_info_item.getComponentByName('version')

            if pkg_name_comp is not None and pkg_name_comp.isValue:
                parsed_data['attestation_application_id'] = str(pkg_name_comp)
            if pkg_version_comp is not None and pkg_version_comp.isValue:
                parsed_data['attestation_application_version_code'] = int(pkg_version_comp)
        else:
            logger.warning(f"First PackageInfo in AttestationApplicationId is not AttestationPackageInfo or SET is empty. Item: {package_info_item}")
    else:
        logger.warning(f"packageInfos in AttestationApplicationId is empty or not isValue. Value: {package_infos_set}")

    signatures = []
    signature_digests_set = app_id_obj.getComponentByName('signatureDigests')
    if signature_digests_set.isValue:
        for item_octet_string in signature_digests_set: # Iterate over SET OF
            if isinstance(item_octet_string, univ.OctetString):
                signatures.append(bytes(item_octet_string).hex())
            else:
                logger.warning(f"Item in signatureDigests is not OctetString: {item_octet_string}")
    parsed_data['application_signatures'] = signatures
    return parsed_data

def parse_authorization_list(auth_list_object: AuthorizationList, attestation_version: int) -> dict:
    parsed_props = {}
    if not isinstance(auth_list_object, AuthorizationList):
        logger.warning(f"parse_authorization_list called with non-AuthorizationList object: {type(auth_list_object)}")
        return parsed_props

    try:
        # Handle Integer types
        for name, key in [
            ('algorithm', 'algorithm'), ('keySize', 'key_size'), ('ecCurve', 'ec_curve'),
            ('rsaPublicExponent', 'rsa_public_exponent'), ('activeDateTime', 'active_date_time'),
            ('originationExpireDateTime', 'origination_expire_date_time'),
            ('usageExpireDateTime', 'usage_expire_date_time'), ('usageCountLimit', 'usage_count_limit'),
            ('userAuthType', 'user_auth_type'), ('authTimeout', 'auth_timeout'),
            ('creationDateTime', 'creation_datetime'), ('origin', 'origin'),
            ('osVersion', 'os_version'), ('osPatchLevel', 'os_patch_level'),
            ('vendorPatchLevel', 'vendor_patch_level'), ('bootPatchLevel', 'boot_patch_level')
        ]:
            comp = auth_list_object.getComponentByName(name)
            if comp is not None and comp.isValue:
                parsed_props[key] = int(comp)

        # Handle SetOf Integer types
        for name, key in [
            ('purpose', 'purpose'), ('digest', 'digests'),
            ('padding', 'padding'), ('mgfDigest', 'mgf_digest')
        ]:
            comp = auth_list_object.getComponentByName(name)
            if comp is not None and comp.isValue:
                parsed_props[key] = [int(c) for c in comp]

        # Handle Null types (flags)
        for name, key in [
            ('rollbackResistance', 'rollback_resistance'), ('earlyBootOnly', 'early_boot_only'),
            ('noAuthRequired', 'no_auth_required'), ('allowWhileOnBody', 'allow_while_on_body'),
            ('trustedUserPresenceRequired', 'trusted_user_presence_required'),
            ('trustedConfirmationRequired', 'trusted_confirmation_required'),
            ('unlockedDeviceRequired', 'unlocked_device_required'),
            ('deviceUniqueAttestation', 'device_unique_attestation')
        ]:
            comp = auth_list_object.getComponentByName(name)
            if comp is not None and comp.isValue:
                parsed_props[key] = True

        # Handle AttestationApplicationId (OctetString containing DER)
        app_id_comp = auth_list_object.getComponentByName('attestationApplicationId')
        if app_id_comp is not None and app_id_comp.isValue:
            parsed_props['attestation_application_id'] = parse_attestation_application_id(bytes(app_id_comp))

        # Handle RootOfTrust (RootOfTrustAsn1 instance)
        rot_comp = auth_list_object.getComponentByName('rootOfTrust')
        if rot_comp is not None and rot_comp.isValue:
            if isinstance(rot_comp, RootOfTrustAsn1):
                parsed_props['root_of_trust'] = _parse_root_of_trust_from_asn1_obj(rot_comp)
            else:
                logger.warning(f"RootOfTrust component expected RootOfTrustAsn1, got {type(rot_comp)}")

        # Handle OCTET_STRING based attestation IDs (decode as UTF-8 or hex)
        octet_string_fields_to_decode = [
            ('attestationIdBrand', 'attestation_id_brand'),
            ('attestationIdDevice', 'attestation_id_device'),
            ('attestationIdProduct', 'attestation_id_product'),
            ('attestationIdSerial', 'attestation_id_serial'),
            ('attestationIdImei', 'attestation_id_imei'),
            ('attestationIdMeid', 'attestation_id_meid'),
            ('attestationIdManufacturer', 'attestation_id_manufacturer'),
            ('attestationIdModel', 'attestation_id_model'),
        ]
        for name, key in octet_string_fields_to_decode:
            comp = auth_list_object.getComponentByName(name)
            if comp is not None and comp.isValue:
                val_bytes = bytes(comp)
                try:
                    parsed_props[key] = val_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    logger.warning(f"Could not decode {name} as UTF-8, using hex: {val_bytes.hex()}")
                    parsed_props[key] = val_bytes.hex()

        # Handle moduleHash (OctetString, base64url encoded)
        module_hash_comp = auth_list_object.getComponentByName('moduleHash')
        if module_hash_comp is not None and module_hash_comp.isValue:
            val_bytes = bytes(module_hash_comp)
            parsed_props['module_hash'] = base64.urlsafe_b64encode(val_bytes).decode()

    except Exception as e:
        logger.error(f"Error processing schema-defined AuthorizationList: {e}. Object: {auth_list_object.prettyPrint() if hasattr(auth_list_object, 'prettyPrint') else auth_list_object}", exc_info=True)
        raise ValueError(f"Failed to parse schema-defined AuthorizationList: {e}") from e

    return parsed_props

def parse_key_description(key_desc_bytes):
    """
    Parses the KeyDescription SEQUENCE from the attestation extension using pyasn1.
    Returns a dictionary containing key properties.
    """
    key_desc_obj = None

    # print(f"DEBUG_PRINT: AttestationParser: Raw key_desc_bytes (first 64 bytes): {key_desc_bytes[:64].hex() if key_desc_bytes else 'None'}")

    try:
        key_desc_obj, rest = der_decoder.decode(key_desc_bytes, asn1Spec=KeyDescriptionSchemaV4())

        # print(f"DEBUG_PRINT: AttestationParser: Type of decoded key_desc_obj: {type(key_desc_obj)}")
        # if hasattr(key_desc_obj, 'prettyPrint'):
        #     print(f"DEBUG_PRINT: AttestationParser: key_desc_obj.prettyPrint():\n{key_desc_obj.prettyPrint()}")
        # else:
        #     print(f"DEBUG_PRINT: AttestationParser: key_desc_obj has no prettyPrint method. repr: {repr(key_desc_obj)}")
        # print(f"DEBUG_PRINT: AttestationParser: Length of rest: {len(rest)}")
        if rest:
             logger.warning(f"Extra bytes found after decoding KeyDescription: {len(rest)} bytes. Rest: {rest[:64].hex()}")


    except PyAsn1Error as e:
        logger.error(f'Failed to decode KeyDescription ASN.1 sequence with pyasn1 using schema: {e}')
        # print(f"DEBUG_PRINT: AttestationParser: PyAsn1Error occurred during schema-based decode: {e}")
        raise ValueError('Malformed KeyDescription sequence (schema validation failed).') from e

    parsed_data = {}
    try:
        parsed_data['attestation_version'] = int(key_desc_obj.getComponentByName('attestationVersion'))
        attestation_security_level_comp = key_desc_obj.getComponentByName('attestationSecurityLevel')
        if attestation_security_level_comp is not None and attestation_security_level_comp.isValue:
            parsed_data['attestation_security_level'] = int(attestation_security_level_comp)

        # Use keyMintVersion and keyMintSecurityLevel as per schema for version 400
        keymint_version_comp = key_desc_obj.getComponentByName('keyMintVersion')
        if keymint_version_comp is not None and keymint_version_comp.isValue:
            parsed_data['keymint_or_keymaster_version'] = int(keymint_version_comp)

        keymint_security_level_comp = key_desc_obj.getComponentByName('keyMintSecurityLevel')
        if keymint_security_level_comp is not None and keymint_security_level_comp.isValue:
            parsed_data['keymint_or_keymaster_security_level'] = int(keymint_security_level_comp)

        parsed_data['attestation_challenge'] = bytes(key_desc_obj.getComponentByName('attestationChallenge'))

        unique_id_comp = key_desc_obj.getComponentByName('uniqueId')
        if unique_id_comp is not None and unique_id_comp.isValue:
            parsed_data['unique_id'] = bytes(unique_id_comp).hex()
        else:
            parsed_data['unique_id'] = None # Explicitly set to None if absent

        sw_enforced_comp = key_desc_obj.getComponentByName('softwareEnforced')
        if sw_enforced_comp is not None and sw_enforced_comp.isValue:
            parsed_data['software_enforced'] = parse_authorization_list(
                sw_enforced_comp,
                parsed_data.get('attestation_version')
            )
        else:
            parsed_data['software_enforced'] = {}
            logger.warning("Software enforced properties (softwareEnforced) is None or not isValue after schema decoding.")


        hw_enforced_comp = key_desc_obj.getComponentByName('hardwareEnforced')
        if hw_enforced_comp is not None and hw_enforced_comp.isValue:
            parsed_data['hardware_enforced'] = parse_authorization_list(
                hw_enforced_comp,
                parsed_data.get('attestation_version')
            )
        else:
            parsed_data['hardware_enforced'] = {}
            logger.warning("Hardware enforced properties (hardwareEnforced) is None or not isValue after schema decoding.")

    except (IndexError, ValueError, PyAsn1Error, TypeError, AttributeError) as e:
        seq_repr = getattr(key_desc_obj, "prettyPrint", lambda: str(key_desc_obj))()
        logger.error(f'Error processing parsed KeyDescription object: {e}. Structure might be unexpected. Object: {seq_repr}', exc_info=True)
        # print(f"DEBUG_PRINT: AttestationParser: Error processing KeyDescription object: {e}. Object (repr): {repr(key_desc_obj)}")
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
    elif isinstance(ext.value, bytes): # Should not happen with cryptography > 3.0 for this OID
        key_description_bytes = ext.value
    else: # Should be ParsedAttestationRecord if cryptography recognized it, but we want bytes
        logger.error(f'Unexpected type for attestation extension value: {type(ext.value)}. Value: {ext.value}')
        raise ValueError(f'Unexpected type for attestation extension value: {type(ext.value)}')


    if not key_description_bytes:
        logger.error('Attestation extension found but its value (KeyDescription bytes) is empty or None.')
        return None

    logger.info(f'KeyDescription bytes length from extension: {len(key_description_bytes)}')
    try:
        attestation_properties = parse_key_description(key_description_bytes)
        return attestation_properties
    except ValueError as e:
        logger.error(f'Failed to parse KeyDescription from attestation extension: {e}')
        raise
    except Exception as e:
        logger.error(f'An unexpected error occurred while parsing KeyDescription: {e}', exc_info=True)
        raise
