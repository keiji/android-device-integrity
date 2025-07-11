import unittest
import sys
import os
import base64
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding # Added asym_padding

# Add the parent directory (server/key_attestation) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cryptographic_utils import decode_certificate_chain, verify_certificate_chain, validate_attestation_signature, base64url_decode
from utils import base64url_encode # Import from utils

# --- Helper functions for generating self-signed certs ---
def generate_self_signed_certificate(common_name="test.example.com", key_type="rsa"):
    """Generates a self-signed certificate and its private key."""
    private_key = None
    if key_type == "rsa":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
    elif key_type == "ec":
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        raise ValueError("Unsupported key_type")

    public_key = private_key.public_key()

    from datetime import datetime, timedelta, timezone # Moved import to top of function
    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name)]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name)])) # Self-signed
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)) # Use actual datetime
        .not_valid_after(now + timedelta(days=30))  # Use actual datetime
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    # In a real scenario, not_valid_before and not_valid_after would be datetime objects.
    # For simplicity in testing where exact dates don't matter for these tests:
    # from datetime import datetime, timedelta, timezone # This block was redundant
    # now = datetime.now(timezone.utc)
    # builder = builder.not_valid_before(now - timedelta(days=1))
    # builder = builder.not_valid_after(now + timedelta(days=30))


    certificate = builder.sign(private_key, hashes.SHA256())
    return private_key, certificate

class TestCryptographicUtils(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rsa_private_key, cls.rsa_certificate = generate_self_signed_certificate(common_name="rsa.example.com", key_type="rsa")
        cls.ec_private_key, cls.ec_certificate = generate_self_signed_certificate(common_name="ec.example.com", key_type="ec")

        # Base64 encode one of the certs for decode_certificate_chain test
        cls.rsa_cert_der = cls.rsa_certificate.public_bytes(serialization.Encoding.DER)
        cls.rsa_cert_b64 = base64.b64encode(cls.rsa_cert_der).decode('utf-8')

    def test_decode_certificate_chain_single_valid(self):
        certs_b64 = [self.rsa_cert_b64]
        decoded_certs = decode_certificate_chain(certs_b64)
        self.assertEqual(len(decoded_certs), 1)
        self.assertIsInstance(decoded_certs[0], x509.Certificate)
        self.assertEqual(decoded_certs[0].serial_number, self.rsa_certificate.serial_number)

    def test_decode_certificate_chain_empty_input(self):
        with self.assertRaisesRegex(ValueError, "Input certificate chain is empty"):
            decode_certificate_chain([])

    def test_decode_certificate_chain_invalid_base64(self):
        certs_b64 = ["not-a-base64-string!@#"]
        # This input, surprisingly, might be "successfully" b64decoded to garbage,
        # then fail at x509 parsing. Or b64decode itself fails.
        # The actual error was "Cannot parse certificate data at index 0..."
        with self.assertRaisesRegex(ValueError, r"Cannot parse certificate data at index 0 into X509 object. Error: .*"):
            decode_certificate_chain(certs_b64)

    def test_decode_certificate_chain_not_a_cert(self):
        not_a_cert_b64 = base64.b64encode(b"this is not a DER certificate").decode('utf-8')
        certs_b64 = [not_a_cert_b64]
        # After changes to decode_certificate_chain, the error from x509.load_der_x509_certificate is more specific
        with self.assertRaisesRegex(ValueError, r"Cannot parse certificate data at index 0 into X509 object. Error: .*"):
            decode_certificate_chain(certs_b64)

    def test_decode_certificate_chain_mixed_valid_invalid(self):
        valid_cert_b64 = self.rsa_cert_b64
        invalid_cert_b64 = "invalid-base64"
        certs_b64 = [valid_cert_b64, invalid_cert_b64]
        with self.assertRaisesRegex(ValueError, r"Invalid Base64 content for certificate at index 1. Error: .*"):
            decode_certificate_chain(certs_b64)

    def test_verify_certificate_chain_single_self_signed(self):
        # A single self-signed certificate is considered valid by the function's logic
        self.assertTrue(verify_certificate_chain([self.rsa_certificate]))

    def test_verify_certificate_chain_empty(self):
        with self.assertRaisesRegex(ValueError, "Certificate chain is empty, cannot verify"):
            verify_certificate_chain([])

    # More complex chain verification tests would require generating a CA and a leaf cert signed by it.
    # For now, this covers the single cert case and empty list.

    def test_validate_attestation_signature_ec_valid(self):
        nonce_store = os.urandom(16)
        nonce_client = os.urandom(16)
        data_to_sign = nonce_store + nonce_client

        signature_bytes = self.ec_private_key.sign(
            data_to_sign,
            ec.ECDSA(hashes.SHA256())
        )

        nonce_store_b64url = base64url_encode(nonce_store)
        nonce_client_b64url = base64url_encode(nonce_client)
        signature_b64url = base64url_encode(signature_bytes)

        self.assertTrue(validate_attestation_signature(
            self.ec_certificate,
            nonce_store_b64url,
            nonce_client_b64url,
            signature_b64url
        ))

    def test_validate_attestation_signature_rsa_valid(self):
        nonce_store = os.urandom(16)
        nonce_client = os.urandom(16)
        data_to_sign = nonce_store + nonce_client

        signature_bytes = self.rsa_private_key.sign(
            data_to_sign,
            asym_padding.PKCS1v15(), # Corrected: Use asym_padding
            hashes.SHA256()
        )

        nonce_store_b64url = base64url_encode(nonce_store)
        nonce_client_b64url = base64url_encode(nonce_client)
        signature_b64url = base64url_encode(signature_bytes)

        self.assertTrue(validate_attestation_signature(
            self.rsa_certificate,
            nonce_store_b64url,
            nonce_client_b64url,
            signature_b64url
        ))

    def test_validate_attestation_signature_invalid_signature(self):
        nonce_store = os.urandom(16)
        nonce_client = os.urandom(16)

        # Signature is just random bytes, not a valid signature
        invalid_signature_bytes = os.urandom(64)

        nonce_store_b64url = base64url_encode(nonce_store)
        nonce_client_b64url = base64url_encode(nonce_client)
        signature_b64url = base64url_encode(invalid_signature_bytes)

        with self.assertRaisesRegex(ValueError, "Attestation signature verification failed"):
            validate_attestation_signature(
                self.ec_certificate,
                nonce_store_b64url,
                nonce_client_b64url,
                signature_b64url
            )

    def test_validate_attestation_signature_tampered_nonce(self):
        nonce_store = os.urandom(16)
        nonce_client_original = os.urandom(16)
        data_to_sign = nonce_store + nonce_client_original

        signature_bytes = self.ec_private_key.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))

        nonce_store_b64url = base64url_encode(nonce_store)
        # Use a different client nonce for verification
        nonce_client_tampered = os.urandom(16)
        nonce_client_tampered_b64url = base64url_encode(nonce_client_tampered)
        signature_b64url = base64url_encode(signature_bytes)

        with self.assertRaisesRegex(ValueError, "Attestation signature verification failed"):
            validate_attestation_signature(
                self.ec_certificate,
                nonce_store_b64url,
                nonce_client_tampered_b64url, # Tampered nonce
                signature_b64url
            )

    def test_base64url_encode_decode_roundtrip(self):
        original_bytes = os.urandom(33) # Test with a length not multiple of 3
        encoded = base64url_encode(original_bytes)
        self.assertNotIn("=", encoded) # No padding characters
        self.assertNotIn("+", encoded)
        self.assertNotIn("/", encoded)

        decoded_bytes = base64url_decode(encoded)
        self.assertEqual(original_bytes, decoded_bytes)

if __name__ == '__main__':
    unittest.main()
