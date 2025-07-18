import argparse
import json
from . import attestation_parser
from . import cryptographic_utils

def main():
    """The main function to be executed when the script is run."""
    parser = argparse.ArgumentParser(
        description="A tool for parsing and validating Android Key Attestation data."
    )
    parser.add_argument(
        "--certificate-chain",
        dest="certificate_chain_path",
        required=True,
        help="Path to the certificate chain file.",
    )
    parser.add_argument(
        "--output",
        dest="output_path",
        required=True,
        help="Path to the output file.",
    )
    args = parser.parse_args()

    with open(args.certificate_chain_path, "rb") as f:
        cert_chain_json = json.load(f)

    pem_encoded_certs = [
        cryptographic_utils.get_pem_encoded_certificate_from_der_bytes(
            cryptographic_utils.decode_base64(cert)
        )
        for cert in cert_chain_json["certificateChain"]
    ]

    leaf_cert_bytes = cryptographic_utils.decode_base64(
        cert_chain_json["certificateChain"][0]
    )

    (
        tee_enforced,
        software_enforced,
    ) = attestation_parser.get_attestation_properties_from_certificate(
        leaf_cert_bytes
    )

    output_data = {
        "tee_enforced": tee_enforced,
        "software_enforced": software_enforced,
        "pem_encoded_certificates": pem_encoded_certs,
    }

    with open(args.output_path, "w") as f:
        json.dump(output_data, f, indent=4)

    print(json.dumps(output_data, indent=4))


if __name__ == "__main__":
    main()
