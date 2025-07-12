import unittest
import sys
import os
import base64
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding
from datetime import datetime, timedelta, timezone

# Add the project root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..')))

from server.key_attestation.cryptographic_utils import decode_certificate_chain, verify_certificate_chain, validate_attestation_signature, base64url_decode
from server.key_attestation.utils import base64url_encode

# User-provided certificate data
USER_PROVIDED_CERT_B64 = "MIIC2TCCAn+gAwIBAgIBATAKBggqhkjOPQQDAjA5MSkwJwYDVQQDEyAyMDZmMTJkNjhkMjQyMGMwZjI5YWNmYjRlNDc0ZjBjODEMMAoGA1UEChMDVEVFMB4XDTcwMDEwMTAwMDAwMFoXDTQ4MDEwMTAwMDAwMFowHzEdMBsGA1UEAxMUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATyINSR0Wf9X1Jxdsdf09GKliJTPBC+HJO8gNDdFNbx7n6KTD68mrJphhFIIaJ78vNGCaOGYVPIpHbThsCG6Q3jo4IBkDCCAYwwDgYDVR0PAQH/BAQDAgeAMIIBeAYKKwYBBAHWeQIBEQSCAWgwggFkAgIBkAoBAQICAZAKAQEEIO1p6vfSmakeYfAW8HIi+CrW6Nr8Xus+xVrMJ81E+PxGBAAwgYi/hT0IAgYBl+SXKhe/hUVSBFAwTjEoMCYEIWRldi5rZWlqaS5kZXZpY2VpbnRlZ3JpdHkuZGV2ZWxvcAIBDjEiBCCEg7tsgmYaUpr+XL0nD7zehkyT/aIAXcgyH44btIaZH7+FVCIEIHMtalhZPLW4yWyP2sCsN4O/k1B8bqO5MNaJDipbSmC9MIGkoQgxBgIBAgIBA6IDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N3AgUAv4U+AwIBAL+FQEwwSgQgmsQXQVPUXkVFsPSeIv5jJzmZtqwctpScOp8D7IgH7ukBAf8KAQAEIBQ+0ZEIUkS3m+CK5xG+fIPd95UHafmGwGjG0ZHgRTh3v4VBBQIDAnEAv4VCBQIDAxcKv4VOBgIEATT/7b+FTwYCBAE0/+0wCgYIKoZIzj0EAwIDSAAwRQIgWJtsWC5QwsIy6ul82uykYmd7leztN4mTA1Kg4rJiPVMCIQD8ppExEufkiNzLaOF5a4q4AIGSCAyBPMuxlu20r2+uoQ=="

# --- Helper functions for generating certificates ---
def generate_certificate(subject_common_name, issuer_name, signing_key, public_key_to_sign, is_ca=False, path_length=0):
    """Generates a certificate."""
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, subject_common_name)]))
        .issuer_name(issuer_name)
        .public_key(public_key_to_sign)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
    )
    if is_ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=path_length if is_ca else None), critical=True)

    certificate = builder.sign(signing_key, hashes.SHA256())
    return certificate

def generate_self_signed_certificate(common_name="test.example.com", key_type="rsa", is_ca=True, path_length=None):
    """Generates a self-signed certificate and its private key."""
    private_key = None
    if key_type == "rsa":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif key_type == "ec":
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        raise ValueError("Unsupported key_type")

    public_key = private_key.public_key()
    subject_issuer_name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name)])

    return private_key, generate_certificate(
        subject_common_name=common_name,
        issuer_name=subject_issuer_name, # Self-signed
        signing_key=private_key,
        public_key_to_sign=public_key,
        is_ca=is_ca,
        path_length=path_length if is_ca else None
    )


class TestCryptographicUtils(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.root_ca_private_key, cls.root_ca_cert = generate_self_signed_certificate(
            common_name="Test Root CA", key_type="rsa", is_ca=True, path_length=1
        )
        cls.root_ca_name = cls.root_ca_cert.subject

        cls.intermediate_ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.intermediate_ca_public_key = cls.intermediate_ca_private_key.public_key()
        cls.intermediate_ca_cert = generate_certificate(
            subject_common_name="Test Intermediate CA",
            issuer_name=cls.root_ca_name,
            signing_key=cls.root_ca_private_key,
            public_key_to_sign=cls.intermediate_ca_public_key,
            is_ca=True,
            path_length=0
        )
        cls.intermediate_ca_name = cls.intermediate_ca_cert.subject

        cls.leaf_private_key = ec.generate_private_key(ec.SECP256R1())
        cls.leaf_public_key = cls.leaf_private_key.public_key()
        cls.leaf_cert = generate_certificate(
            subject_common_name="leaf.example.com",
            issuer_name=cls.intermediate_ca_name,
            signing_key=cls.intermediate_ca_private_key,
            public_key_to_sign=cls.leaf_public_key,
            is_ca=False
        )

        cls.rsa_private_key_single, cls.rsa_certificate_single = generate_self_signed_certificate(common_name="rsa.example.com", key_type="rsa", is_ca=False)
        cls.ec_private_key_single, cls.ec_certificate_single = generate_self_signed_certificate(common_name="ec.example.com", key_type="ec", is_ca=False)

        cls.rsa_cert_single_der = cls.rsa_certificate_single.public_bytes(serialization.Encoding.DER)
        cls.rsa_cert_single_b64 = base64.b64encode(cls.rsa_cert_single_der).decode('utf-8')

        cls.user_cert_b64 = USER_PROVIDED_CERT_B64
        try:
            user_cert_bytes = base64.b64decode(cls.user_cert_b64)
            cls.user_certificate = x509.load_der_x509_certificate(user_cert_bytes)
        except Exception as e:
            cls.user_certificate = None
            print(f"Warning: Could not load user-provided certificate during setUpClass: {e}")

        cls.leaf_cert_b64 = base64.b64encode(cls.leaf_cert.public_bytes(serialization.Encoding.DER)).decode('utf-8')
        cls.intermediate_ca_cert_b64 = base64.b64encode(cls.intermediate_ca_cert.public_bytes(serialization.Encoding.DER)).decode('utf-8')
        cls.root_ca_cert_b64 = base64.b64encode(cls.root_ca_cert.public_bytes(serialization.Encoding.DER)).decode('utf-8')
        cls.valid_chain_b64 = [cls.leaf_cert_b64, cls.intermediate_ca_cert_b64, cls.root_ca_cert_b64]


    def test_decode_certificate_chain_single_valid_generated(self):
        certs_b64 = [self.rsa_cert_single_b64]
        decoded_certs = decode_certificate_chain(certs_b64)
        self.assertEqual(len(decoded_certs), 1)
        self.assertIsInstance(decoded_certs[0], x509.Certificate)
        self.assertEqual(decoded_certs[0].serial_number, self.rsa_certificate_single.serial_number)

    def test_decode_certificate_chain_single_valid_user_provided(self):
        self.assertIsNotNone(self.user_certificate, "User certificate could not be loaded during setup")
        certs_b64 = [self.user_cert_b64]
        decoded_certs = decode_certificate_chain(certs_b64)
        self.assertEqual(len(decoded_certs), 1)
        self.assertIsInstance(decoded_certs[0], x509.Certificate)
        self.assertEqual(decoded_certs[0].serial_number, self.user_certificate.serial_number)
        self.assertEqual(decoded_certs[0].subject, self.user_certificate.subject)

    def test_decode_certificate_chain_multiple_valid(self):
        decoded_certs = decode_certificate_chain(self.valid_chain_b64)
        self.assertEqual(len(decoded_certs), 3)
        for cert in decoded_certs:
            self.assertIsInstance(cert, x509.Certificate)
        self.assertEqual(decoded_certs[0].subject, self.leaf_cert.subject)
        self.assertEqual(decoded_certs[1].subject, self.intermediate_ca_cert.subject)
        self.assertEqual(decoded_certs[2].subject, self.root_ca_cert.subject)

    def test_decode_certificate_chain_item_not_string(self):
        certs_input = [self.rsa_cert_single_b64, 12345]
        with self.assertRaisesRegex(ValueError, "Certificate at index 1 is not a string."):
            decode_certificate_chain(certs_input)

    def test_decode_certificate_chain_empty_input(self):
        with self.assertRaisesRegex(ValueError, "Input certificate chain is empty"):
            decode_certificate_chain([])

    def test_decode_certificate_chain_invalid_base64(self):
        certs_b64 = ["not-a-base64-string!@#"]
        with self.assertRaisesRegex(ValueError, r"Cannot parse certificate data at index 0 into X509 object. Error: .*"):
            decode_certificate_chain(certs_b64)

    def test_decode_certificate_chain_not_a_cert(self):
        not_a_cert_b64 = base64.b64encode(b"this is not a DER certificate").decode('utf-8')
        certs_b64 = [not_a_cert_b64]
        with self.assertRaisesRegex(ValueError, r"Cannot parse certificate data at index 0 into X509 object. Error: .*"):
            decode_certificate_chain(certs_b64)

    def test_decode_certificate_chain_mixed_valid_invalid_b64(self):
        valid_cert_b64 = self.rsa_cert_single_b64
        invalid_cert_b64 = "invalid-base64-chars$$"
        certs_b64 = [valid_cert_b64, invalid_cert_b64]
        with self.assertRaisesRegex(ValueError, r"Invalid Base64 content for certificate at index 1. Error: .*"):
            decode_certificate_chain(certs_b64)

    def test_decode_certificate_chain_mixed_valid_not_der(self):
        valid_cert_b64 = self.rsa_cert_single_b64
        not_der_b64 = base64.b64encode(b"valid b64 but not der").decode('utf-8')
        certs_b64 = [valid_cert_b64, not_der_b64]
        with self.assertRaisesRegex(ValueError, r"Cannot parse certificate data at index 1 into X509 object. Error: .*"):
            decode_certificate_chain(certs_b64)

    @patch('server.key_attestation.cryptographic_utils.ROOT_CERTIFICATES', new_callable=list)
    def test_verify_certificate_chain_single_self_signed(self, mock_root_certs):
        root_cert_pem = self.rsa_certificate_single.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        mock_root_certs.append(root_cert_pem.decode('utf-8'))
        self.assertTrue(verify_certificate_chain([self.rsa_certificate_single]))

    @patch('server.key_attestation.cryptographic_utils.ROOT_CERTIFICATES', new_callable=list)
    def test_verify_certificate_chain_valid_chain(self, mock_root_certs):
        root_cert_pem = self.root_ca_cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        mock_root_certs.append(root_cert_pem.decode('utf-8'))
        chain_to_verify = [self.leaf_cert, self.intermediate_ca_cert, self.root_ca_cert]
        self.assertTrue(verify_certificate_chain(chain_to_verify))

    @patch('server.key_attestation.cryptographic_utils.ROOT_CERTIFICATES', new_callable=list)
    def test_verify_certificate_chain_broken_signature(self, mock_root_certs):
        root_cert_pem = self.root_ca_cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        mock_root_certs.append(root_cert_pem.decode('utf-8'))
        rogue_leaf_private_key = ec.generate_private_key(ec.SECP256R1())
        rogue_leaf_cert = generate_certificate(
            subject_common_name="leaf.example.com",
            issuer_name=self.intermediate_ca_name,
            signing_key=rogue_leaf_private_key,
            public_key_to_sign=self.leaf_public_key
        )
        broken_chain = [rogue_leaf_cert, self.intermediate_ca_cert, self.root_ca_cert]
        with self.assertRaisesRegex(ValueError, r"Signature of certificate at index 0 is not valid by certificate at index 1."):
            verify_certificate_chain(broken_chain)

    @patch('server.key_attestation.cryptographic_utils.ROOT_CERTIFICATES', new_callable=list)
    def test_verify_certificate_chain_issuer_subject_mismatch(self, mock_root_certs):
        root_cert_pem = self.root_ca_cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        mock_root_certs.append(root_cert_pem.decode('utf-8'))
        other_intermediate_pk, other_intermediate_cert = generate_self_signed_certificate("Other Intermediate CA", "rsa", True, 0)
        mismatch_chain = [self.leaf_cert, other_intermediate_cert, self.root_ca_cert]
        with self.assertRaisesRegex(ValueError, r"Issuer of certificate at index 0 does not match subject of certificate at index 1."):
            verify_certificate_chain(mismatch_chain)

    def test_verify_certificate_chain_empty(self):
        with self.assertRaisesRegex(ValueError, "Certificate chain is empty, cannot verify"):
            verify_certificate_chain([])

    def test_validate_attestation_signature_ec_valid(self):
        nonce_store = os.urandom(16)
        nonce_client = os.urandom(16)
        data_to_sign = nonce_store + nonce_client

        signature_bytes = self.leaf_private_key.sign(
            data_to_sign,
            ec.ECDSA(hashes.SHA256())
        )

        nonce_store_b64url = base64url_encode(nonce_store)
        nonce_client_b64url = base64url_encode(nonce_client)
        signature_b64url = base64url_encode(signature_bytes)

        self.assertTrue(validate_attestation_signature(
            self.leaf_cert,
            nonce_store_b64url,
            nonce_client_b64url,
            signature_b64url
        ))

    def test_validate_attestation_signature_rsa_valid(self):
        nonce_store = os.urandom(16)
        nonce_client = os.urandom(16)
        data_to_sign = nonce_store + nonce_client

        signature_bytes = self.rsa_private_key_single.sign(
            data_to_sign,
            asym_padding.PKCS1v15(),
            hashes.SHA256()
        )

        nonce_store_b64url = base64url_encode(nonce_store)
        nonce_client_b64url = base64url_encode(nonce_client)
        signature_b64url = base64url_encode(signature_bytes)

        self.assertTrue(validate_attestation_signature(
            self.rsa_certificate_single,
            nonce_store_b64url,
            nonce_client_b64url,
            signature_b64url
        ))

    def test_validate_attestation_signature_invalid_signature(self):
        nonce_store = os.urandom(16)
        nonce_client = os.urandom(16)
        invalid_signature_bytes = os.urandom(64)

        nonce_store_b64url = base64url_encode(nonce_store)
        nonce_client_b64url = base64url_encode(nonce_client)
        signature_b64url = base64url_encode(invalid_signature_bytes)

        with self.assertRaisesRegex(ValueError, "Attestation signature verification failed"):
            validate_attestation_signature(
                self.leaf_cert,
                nonce_store_b64url,
                nonce_client_b64url,
                signature_b64url
            )

    def test_validate_attestation_signature_tampered_nonce(self):
        nonce_store = os.urandom(16)
        nonce_client_original = os.urandom(16)
        data_to_sign = nonce_store + nonce_client_original

        signature_bytes = self.leaf_private_key.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))

        nonce_store_b64url = base64url_encode(nonce_store)
        nonce_client_tampered_b64url = base64url_encode(os.urandom(16))
        signature_b64url = base64url_encode(signature_bytes)

        with self.assertRaisesRegex(ValueError, "Attestation signature verification failed"):
            validate_attestation_signature(
                self.leaf_cert,
                nonce_store_b64url,
                nonce_client_tampered_b64url,
                signature_b64url
            )

    def test_base64url_encode_decode_roundtrip(self):
        original_bytes = os.urandom(33)
        encoded = base64url_encode(original_bytes)
        self.assertNotIn("=", encoded)
        self.assertNotIn("+", encoded)
        self.assertNotIn("/", encoded)
        decoded_bytes = base64url_decode(encoded)
        self.assertEqual(original_bytes, decoded_bytes)

if __name__ == '__main__':
    unittest.main()
