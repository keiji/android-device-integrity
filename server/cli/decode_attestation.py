import json
import sys
import base64
import argparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID, SignatureAlgorithmOID, AuthorityInformationAccessOID
from server.key_attestation.attestation_parser import get_attestation_extension_properties
from server.key_attestation.utils import convert_bytes_to_hex_str

def decode_certificate_chain(certs_data):
    chain = []
    for cert_b64 in certs_data:
        cert_bytes = base64.b64decode(cert_b64)
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())

        cert_info = {}

        # Name (Subject)
        cert_info['name'] = cert.subject.rfc4514_string()

        # Serial Number
        cert_info['serial_number'] = hex(cert.serial_number)[2:] # remove 0x

        # Signature Algorithm
        cert_info['signature_type_ln'] = cert.signature_algorithm_oid.dotted_string

        # Mapping for common Android Keystore algorithms
        oid_map = {
            "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
            "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
            "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
        }
        cert_info['signature_type_sn'] = oid_map.get(cert.signature_algorithm_oid.dotted_string, "Unknown")

        # Validity
        # Use UTC aware properties
        cert_info['valid_from'] = cert.not_valid_before_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
        cert_info['valid_to'] = cert.not_valid_after_utc.strftime('%Y-%m-%dT%H:%M:%SZ')

        # Key Usage
        try:
            ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            ku = ku_ext.value

            # encipher_only and decipher_only are only valid if key_agreement is set
            try:
                encipher_only = ku.encipher_only
            except ValueError:
                encipher_only = False

            try:
                decipher_only = ku.decipher_only
            except ValueError:
                decipher_only = False

            cert_info['key_usage'] = {
                "digital_signature": ku.digital_signature,
                "content_commitment": ku.content_commitment,
                "key_encipherment": ku.key_encipherment,
                "data_encipherment": ku.data_encipherment,
                "key_agreement": ku.key_agreement,
                "key_cert_sign": ku.key_cert_sign,
                "crl_sign": ku.crl_sign,
                "encipher_only": encipher_only,
                "decipher_only": decipher_only
            }
        except x509.ExtensionNotFound:
            cert_info['key_usage'] = None

        # Subject Key Identifier
        try:
            ski_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            cert_info['subject_key_identifier'] = ski_ext.value.digest.hex()
        except x509.ExtensionNotFound:
            cert_info['subject_key_identifier'] = None

        # Authority Key Identifier
        try:
            aki_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            cert_info['authority_key_identifier'] = aki_ext.value.key_identifier.hex() if aki_ext.value.key_identifier else None
        except x509.ExtensionNotFound:
            cert_info['authority_key_identifier'] = None

        chain.append(cert_info)

    return chain

def map_attestation_info(info):
    if not info:
        return None

    mapped = {}

    # Direct mappings or simple renames
    mapped['attestation_version'] = info.get('attestation_version')
    mapped['attestation_security_level'] = info.get('attestation_security_level')
    mapped['keymint_version'] = info.get('keymint_or_keymaster_version')
    mapped['keymint_security_level'] = info.get('keymint_or_keymaster_security_level')

    # Handle bytes for attestation_challenge -> base64 string
    if info.get('attestation_challenge'):
        mapped['attestation_challenge'] = base64.urlsafe_b64encode(info.get('attestation_challenge')).decode('utf-8').rstrip('=')
    else:
        mapped['attestation_challenge'] = None

    mapped['software_enforced_properties'] = convert_bytes_to_hex_str(info.get('software_enforced', {}))
    mapped['hardware_enforced_properties'] = convert_bytes_to_hex_str(info.get('hardware_enforced', {}))

    return mapped

def main():
    parser = argparse.ArgumentParser(description='Decode Android Key Attestation Certificate Chain')
    parser.add_argument('input_file', help='Path to the input JSON file containing certificate chain')
    parser.add_argument('output_file', help='Path to the output JSON file')

    args = parser.parse_args()

    try:
        with open(args.input_file, 'r') as f:
            input_data = json.load(f)

        if not isinstance(input_data, list) or len(input_data) == 0:
            print("Error: Input file must contain a JSON list of certificates.", file=sys.stderr)
            sys.exit(1)

        # Parse certificate chain
        chain_info = decode_certificate_chain(input_data)

        # Parse attestation info from the leaf certificate (first one)
        leaf_cert_bytes = base64.b64decode(input_data[0])
        leaf_cert = x509.load_der_x509_certificate(leaf_cert_bytes, default_backend())

        attestation_props = get_attestation_extension_properties(leaf_cert)
        attestation_info = map_attestation_info(attestation_props)

        output_data = {
            "attestation_info": attestation_info,
            "certificate_chain": chain_info
        }

        # Print to screen
        json_output = json.dumps(output_data, indent=2)
        print(json_output)

        # Write to file
        with open(args.output_file, 'w') as f:
            f.write(json_output)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
