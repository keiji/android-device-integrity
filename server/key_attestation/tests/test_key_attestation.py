import unittest
import json
import sys
import os

# Add the parent directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from key_attestation.key_attestation import app
from key_attestation.cryptographic_utils import base64url_encode
from unittest.mock import patch, MagicMock
from google.cloud import datastore

class KeyAttestationAgreementTest(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

        # Mock the datastore client
        self.mock_datastore_client = MagicMock()
        self.patcher = patch('key_attestation.key_attestation.datastore_client', self.mock_datastore_client)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    @patch('key_attestation.key_attestation.get_ds_agreement_key_attestation_session')
    @patch('key_attestation.key_attestation.derive_shared_key')
    @patch('key_attestation.key_attestation.decrypt_data')
    @patch('key_attestation.key_attestation.verify_certificate_chain')
    @patch('key_attestation.key_attestation.get_attestation_extension_properties')
    def test_verify_agreement_success(self, mock_get_attestation_extension_properties, mock_verify_certificate_chain, mock_decrypt_data, mock_derive_shared_key, mock_get_ds_agreement_key_attestation_session):
        session_id = 'test_session_id'
        nonce = 'test_nonce'
        challenge = 'test_challenge'
        server_private_key = 'test_server_private_key'
        encrypted_data = 'test_encrypted_data'
        salt = 'test_salt'
        certificate_chain = ['cert1', 'cert2']
        device_info = {'brand': 'Google', 'model': 'Pixel 7', 'device': 'panther', 'product': 'panther_us', 'manufacturer': 'Google', 'hardware': 'gs201', 'board': 'slider', 'bootloader': 'slider-1.0-...', 'version_release': '13', 'sdk_int': 33, 'fingerprint': 'google/panther/panther:13/...', 'security_patch': '2023-05-01'}
        security_info = {'is_device_lock_enabled': True, 'is_biometrics_enabled': True, 'has_class_3_authenticator': True, 'has_strongbox': True}


        mock_get_ds_agreement_key_attestation_session.return_value = {
            'nonce': base64url_encode(nonce.encode()),
            'challenge': base64url_encode(challenge.encode()),
            'private_key': base64url_encode(server_private_key.encode())
        }
        mock_derive_shared_key.return_value = b'test_aes_key'
        mock_decrypt_data.return_value = nonce.encode()
        mock_get_attestation_extension_properties.return_value = {
            'attestation_challenge': challenge.encode()
        }

        with patch('key_attestation.key_attestation.decode_certificate_chain') as mock_decode_certificate_chain:
            mock_cert = MagicMock()
            mock_public_key = MagicMock()
            mock_public_key.public_bytes.return_value = b'test_public_key'
            mock_cert.public_key.return_value = mock_public_key
            mock_decode_certificate_chain.return_value = [mock_cert]

            response = self.app.post('/v1/verify/agreement',
                                     data=json.dumps({
                                         'session_id': session_id,
                                         'encrypted_data': base64url_encode(encrypted_data.encode()),
                                         'salt': base64url_encode(salt.encode()),
                                         'certificate_chain': certificate_chain,
                                         'device_info': device_info,
                                         'security_info': security_info
                                     }),
                                     content_type='application/json')
            self.assertEqual(response.status_code, 200)

    @patch('key_attestation.key_attestation.get_ds_agreement_key_attestation_session')
    @patch('key_attestation.key_attestation.derive_shared_key')
    @patch('key_attestation.key_attestation.decrypt_data')
    def test_verify_agreement_nonce_mismatch(self, mock_decrypt_data, mock_derive_shared_key, mock_get_ds_agreement_key_attestation_session):
        session_id = 'test_session_id'
        nonce = 'test_nonce'
        challenge = 'test_challenge'
        server_private_key = 'test_server_private_key'
        encrypted_data = 'test_encrypted_data'
        salt = 'test_salt'
        certificate_chain = ['cert1', 'cert2']
        device_info = {'brand': 'Google', 'model': 'Pixel 7', 'device': 'panther', 'product': 'panther_us', 'manufacturer': 'Google', 'hardware': 'gs201', 'board': 'slider', 'bootloader': 'slider-1.0-...', 'version_release': '13', 'sdk_int': 33, 'fingerprint': 'google/panther/panther:13/...', 'security_patch': '2023-05-01'}
        security_info = {'is_device_lock_enabled': True, 'is_biometrics_enabled': True, 'has_class_3_authenticator': True, 'has_strongbox': True}

        mock_get_ds_agreement_key_attestation_session.return_value = {
            'nonce': base64url_encode(nonce.encode()),
            'challenge': base64url_encode(challenge.encode()),
            'private_key': base64url_encode(server_private_key.encode())
        }
        mock_derive_shared_key.return_value = b'test_aes_key'
        mock_decrypt_data.return_value = b'wrong_nonce'

        with patch('key_attestation.key_attestation.decode_certificate_chain') as mock_decode_certificate_chain:
            mock_cert = MagicMock()
            mock_public_key = MagicMock()
            mock_public_key.public_bytes.return_value = b'test_public_key'
            mock_cert.public_key.return_value = mock_public_key
            mock_decode_certificate_chain.return_value = [mock_cert]

            response = self.app.post('/v1/verify/agreement',
                                     data=json.dumps({
                                         'session_id': session_id,
                                         'encrypted_data': base64url_encode(encrypted_data.encode()),
                                         'salt': base64url_encode(salt.encode()),
                                         'certificate_chain': certificate_chain,
                                         'device_info': device_info,
                                         'security_info': security_info
                                     }),
                                     content_type='application/json')
            response_data = json.loads(response.data)
            self.assertEqual(response.status_code, 400)
            self.assertIn('Nonce mismatch', response_data['error'])

if __name__ == '__main__':
    unittest.main()
