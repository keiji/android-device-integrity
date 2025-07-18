import argparse
import json
import os
import sys

# Add the parent directory to the path to allow imports.
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from key_attestation.attestation_parser import get_attestation_extension_properties
from key_attestation.cryptographic_utils import decode_certificate_chain
from key_attestation.cryptographic_utils import extract_certificate_details
from key_attestation.utils import convert_bytes_to_hex_str, base64url_encode


def main():
  parser = argparse.ArgumentParser(
      description='Validate a key attestation certificate chain.')
  parser.add_argument(
      '--cert-chain',
      type=str,
      required=True,
      help='Path to the certificate chain file.')
  parser.add_argument(
      '--output',
      type=str,
      required=False,
      help='Path to the output file.')
  args = parser.parse_args()

  with open(args.cert_chain, 'rb') as f:
    cert_chain_json = json.load(f)

  decoded_certs = decode_certificate_chain(cert_chain_json)
  cert_details = [extract_certificate_details(cert) for cert in decoded_certs]
  leaf_cert_attestation_props = get_attestation_extension_properties(
      decoded_certs[0]
  )

  # Convert bytes to hex strings for JSON serialization.
  for cert in cert_details:
    for key, value in cert.items():
      if isinstance(value, bytes):
        cert[key] = convert_bytes_to_hex_str(value)

  leaf_cert_attestation_props['attestation_challenge'] = base64url_encode(
      leaf_cert_attestation_props['attestation_challenge'])
  json_output = {
      'attestation_info': leaf_cert_attestation_props,
      'certificate_chain': cert_details,
  }

  if args.output:
    with open(args.output, 'w') as f:
      json.dump(json_output, f, indent=2)

  print(json.dumps(json_output, indent=2))


if __name__ == '__main__':
  main()
