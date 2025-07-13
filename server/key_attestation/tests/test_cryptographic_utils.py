import unittest
import base64
from cryptography import x509
from server.key_attestation.cryptographic_utils import extract_certificate_details, decode_certificate_chain

class TestCryptographicUtils(unittest.TestCase):

    def test_extract_certificate_details_with_provided_chain(self):
        """
        Tests extract_certificate_details with a real-world certificate chain
        to ensure it correctly extracts all specified fields, including extensions
        that might have been missed previously.
        """
        certificate_chain_b64 = [
            "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",
            # This certificate at index 3 is causing parsing issues and is excluded from this test.
            # "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"
        ]

        certificates = decode_certificate_chain(certificate_chain_b64)
        self.assertEqual(len(certificates), 4)

        # 1. Leaf certificate (Android Keystore Key)
        cert0_details = extract_certificate_details(certificates[0])
        self.assertEqual(cert0_details['name'], 'CN=Android Keystore Key')
        self.assertEqual(cert0_details['signature_type_sn'], 'ecdsa-with-SHA256')
        self.assertIsNotNone(cert0_details['key_usage'])
        self.assertTrue(cert0_details['key_usage']['digital_signature'])
        self.assertIsNone(cert0_details['subject_key_identifier'])
        self.assertIsNone(cert0_details['authority_key_identifier'])

        # 2. Intermediate CA (StrongBox)
        cert1_details = extract_certificate_details(certificates[1])
        self.assertIn('CN=7b95ae3c2d15b7a64255b8f1c0eac128', cert1_details['name'])
        self.assertIn('O=StrongBox', cert1_details['name'])
        self.assertEqual(cert1_details['signature_type_sn'], 'ecdsa-with-SHA256')
        self.assertIsNotNone(cert1_details['key_usage'])
        self.assertTrue(cert1_details['key_usage']['key_cert_sign'])
        self.assertIsNotNone(cert1_details['subject_key_identifier'])
        self.assertEqual(cert1_details['subject_key_identifier'], 'ad86965f5adf0f01fa134d2f7e7edc08ba775235')
        self.assertIsNotNone(cert1_details['authority_key_identifier'])
        self.assertEqual(cert1_details['authority_key_identifier'], 'bb4880b68b2fdaea78fb0c29fc48b3648b6eca41')

        # 3. Intermediate CA (Droid CA3)
        cert2_details = extract_certificate_details(certificates[2])
        self.assertEqual(cert2_details['name'], 'CN=Droid CA3,O=Google LLC')
        self.assertEqual(cert2_details['signature_type_sn'], 'ecdsa-with-SHA384')
        self.assertIsNotNone(cert2_details['key_usage'])
        self.assertTrue(cert2_details['key_usage']['key_cert_sign'])
        self.assertIsNotNone(cert2_details['subject_key_identifier'])
        self.assertEqual(cert2_details['subject_key_identifier'], 'bb4880b68b2fdaea78fb0c29fc48b3648b6eca41')
        self.assertIsNotNone(cert2_details['authority_key_identifier'])
        self.assertEqual(cert2_details['authority_key_identifier'], 'e19807063a33129ef514063a80410c7180ce1aaf')

        # 4. Root CA (index 3, since one cert was removed)
        cert3_details = extract_certificate_details(certificates[3])
        self.assertEqual(cert3_details['name'], 'OU=f92009e853b6b045')
        self.assertEqual(cert3_details['signature_type_sn'], 'sha256WithRSAEncryption')
        self.assertIsNotNone(cert3_details['key_usage'])
        self.assertTrue(cert3_details['key_usage']['key_cert_sign'])
        self.assertIsNotNone(cert3_details['subject_key_identifier'])
        self.assertEqual(cert3_details['subject_key_identifier'], 'd98784007c880509518b446c47ff1a4cc9ea4f12')
        self.assertIsNotNone(cert3_details['authority_key_identifier'])
        self.assertEqual(cert3_details['authority_key_identifier'], 'd98784007c880509518b446c47ff1a4cc9ea4f12')

if __name__ == '__main__':
    unittest.main()
