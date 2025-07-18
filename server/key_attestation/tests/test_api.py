import unittest
import json
import sys
import os
from unittest.mock import patch, MagicMock

from server.key_attestation.api import app
from server.key_attestation.cryptographic_utils import base64url_encode, base64url_decode
from google.cloud.exceptions import Conflict

class KeyAttestationPreparationTest(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

        # Mock the datastore client
        self.mock_datastore_client = MagicMock()
        self.patcher = patch('server.key_attestation.api.datastore_client', self.mock_datastore_client)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    @patch('server.key_attestation.api.store_key_attestation_session')
    def test_prepare_signature_success(self, mock_store_key_attestation_session):
        response = self.app.get('/key-attestation/v1/prepare/signature')
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertIn('session_id', response_data)
        self.assertIn('nonce', response_data)
        self.assertIn('challenge', response_data)
        # Ensure the store function was called with the generated session_id
        mock_store_key_attestation_session.assert_called_once()
        self.assertEqual(mock_store_key_attestation_session.call_args[0][1], response_data['session_id'])


    @patch('server.key_attestation.api.store_agreement_key_attestation_session')
    def test_prepare_agreement_success(self, mock_store_agreement_key_attestation_session):
        response = self.app.get('/key-attestation/v1/prepare/agreement')
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertIn('session_id', response_data)
        self.assertIn('nonce', response_data)
        self.assertIn('challenge', response_data)
        self.assertIn('public_key', response_data)
        # Ensure the store function was called with the generated session_id
        mock_store_agreement_key_attestation_session.assert_called_once()
        self.assertEqual(mock_store_agreement_key_attestation_session.call_args[0][1], response_data['session_id'])

    @patch('server.key_attestation.api.store_key_attestation_session')
    def test_prepare_signature_session_id_collision(self, mock_store_key_attestation_session):
        # Simulate a session ID collision on the first attempt
        mock_store_key_attestation_session.side_effect = [Conflict('Collision'), None]

        response = self.app.get('/key-attestation/v1/prepare/signature')
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertIn('session_id', response_data)
        self.assertEqual(mock_store_key_attestation_session.call_count, 2)

class KeyAttestationAgreementTest(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

        # Mock the datastore client
        self.mock_datastore_client = MagicMock()
        self.patcher = patch('server.key_attestation.api.datastore_client', self.mock_datastore_client)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    @patch('server.key_attestation.api.get_ds_agreement_key_attestation_session')
    @patch('server.key_attestation.api.derive_shared_key')
    @patch('server.key_attestation.api.decrypt_data')
    @patch('server.key_attestation.api.verify_certificate_chain')
    @patch('server.key_attestation.api.get_attestation_extension_properties')
    @patch('server.key_attestation.api.extract_certificate_details')
    def test_verify_agreement_success(self, mock_extract_certificate_details, mock_get_attestation_extension_properties, mock_verify_certificate_chain, mock_decrypt_data, mock_derive_shared_key, mock_get_ds_agreement_key_attestation_session):
        session_id = 'test_session_id'
        nonce = 'test_nonce'
        challenge = 'test_challenge'
        server_private_key = 'test_server_private_key'
        encrypted_data = 'test_encrypted_data'
        salt = 'test_salt'
        certificate_chain = ['cert1', 'cert2']
        device_info = {'brand': 'Google', 'model': 'Pixel 7'}
        security_info = {'is_device_lock_enabled': True}

        mock_get_ds_agreement_key_attestation_session.return_value = {
            'nonce': base64url_encode(nonce.encode()),
            'challenge': base64url_encode(challenge.encode()),
            'private_key': base64url_encode(server_private_key.encode())
        }
        mock_derive_shared_key.return_value = b'test_aes_key'
        mock_decrypt_data.return_value = nonce.encode()
        mock_get_attestation_extension_properties.return_value = {
            'attestation_challenge': challenge.encode(),
            'software_enforced': {},
            'hardware_enforced': {}
        }
        mock_verify_certificate_chain.return_value = True
        mock_extract_certificate_details.return_value = {"name": "test_cert"}

        with patch('server.key_attestation.api.decode_certificate_chain') as mock_decode_certificate_chain:
            mock_cert = MagicMock()
            mock_public_key = MagicMock()
            mock_public_key.public_bytes.return_value = b'test_public_key'
            mock_cert.public_key.return_value = mock_public_key
            mock_decode_certificate_chain.return_value = [mock_cert]

            response = self.app.post('/key-attestation/v1/verify/agreement',
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

    @patch('server.key_attestation.api.get_ds_agreement_key_attestation_session')
    @patch('server.key_attestation.api.derive_shared_key')
    @patch('server.key_attestation.api.decrypt_data')
    @patch('server.key_attestation.api.verify_certificate_chain')
    def test_verify_agreement_nonce_mismatch(self, mock_verify_certificate_chain, mock_decrypt_data, mock_derive_shared_key, mock_get_ds_agreement_key_attestation_session):
        session_id = 'test_session_id'
        nonce = 'test_nonce'
        challenge = 'test_challenge'
        server_private_key = 'test_server_private_key'
        encrypted_data = 'test_encrypted_data'
        salt = 'test_salt'
        certificate_chain = ['cert1', 'cert2']
        device_info = {'brand': 'Google', 'model': 'Pixel 7'}
        security_info = {'is_device_lock_enabled': True}

        mock_get_ds_agreement_key_attestation_session.return_value = {
            'nonce': base64url_encode(nonce.encode()),
            'challenge': base64url_encode(challenge.encode()),
            'private_key': base64url_encode(server_private_key.encode())
        }
        mock_derive_shared_key.return_value = b'test_aes_key'
        mock_decrypt_data.return_value = b'wrong_nonce'
        mock_verify_certificate_chain.return_value = True

        with patch('server.key_attestation.api.decode_certificate_chain') as mock_decode_certificate_chain, \
             patch('server.key_attestation.api.get_attestation_extension_properties') as mock_get_attestation_extension_properties, \
             patch('server.key_attestation.api.extract_certificate_details') as mock_extract_certificate_details:
            mock_cert = MagicMock()
            mock_public_key = MagicMock()
            mock_public_key.public_bytes.return_value = b'test_public_key'
            mock_cert.public_key.return_value = mock_public_key
            mock_decode_certificate_chain.return_value = [mock_cert]
            mock_get_attestation_extension_properties.return_value = {
                'attestation_challenge': challenge.encode()
            }
            mock_extract_certificate_details.return_value = {"name": "test_cert"}

            response = self.app.post('/key-attestation/v1/verify/agreement',
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
