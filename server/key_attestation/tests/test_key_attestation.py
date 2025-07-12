import unittest
import json
import sys
import os
from unittest.mock import patch, MagicMock

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from key_attestation.key_attestation import app
from key_attestation.utils import base64url_encode
from key_attestation.datastore_utils import AGREEMENT_KEY_ATTESTATION_SESSION_KIND

class KeyAttestationAgreementTest(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def tearDown(self):
        pass

    @patch('key_attestation.key_attestation.datastore_client', new_callable=MagicMock)
    @patch('key_attestation.key_attestation.get_ds_agreement_key_attestation_session')
    @patch('key_attestation.key_attestation.delete_ds_key_attestation_session')
    @patch('key_attestation.key_attestation.store_ds_key_attestation_result')
    @patch('key_attestation.key_attestation.derive_shared_key')
    @patch('key_attestation.key_attestation.decrypt_data')
    @patch('key_attestation.key_attestation.decode_certificate_chain')
    @patch('key_attestation.key_attestation.verify_certificate_chain')
    @patch('key_attestation.key_attestation.get_attestation_extension_properties')
    def test_verify_agreement_success(self, mock_get_props, mock_verify_chain, mock_decode_chain, mock_decrypt, mock_derive_key, mock_store_result, mock_delete_session, mock_get_session, mock_ds_client):
        # Mocking session data from Datastore
        mock_session_entity = MagicMock()
        mock_session_entity.get.side_effect = lambda key: {
            'nonce': base64url_encode(b'test_nonce'),
            'challenge': base64url_encode(b'test_challenge'),
            'private_key': base64url_encode(b'test_server_private_key')
        }.get(key)
        mock_get_session.return_value = mock_session_entity

        # Mocking key derivation and decryption
        mock_derive_key.return_value = b'test_aes_key'
        mock_decrypt.return_value = b'test_nonce'

        # Mocking certificate and attestation data
        mock_decode_chain.return_value = [MagicMock()]
        mock_verify_chain.return_value = True
        mock_get_props.return_value = {
            'attestation_challenge': b'test_challenge',
            'attestation_version': 4,
            'attestation_security_level': 1,
            'keymint_or_keymaster_version': 4,
            'keymint_or_keymaster_security_level': 1,
            'software_enforced': {},
            'hardware_enforced': {}
        }

        iv = base64url_encode(b'123456789012')
        encrypted_data = base64url_encode(b'encrypted_nonce')
        request_data = {
            "session_id": "test_session_id",
            "encrypted_data": f"{iv}{encrypted_data}",
            "client_public_key": base64url_encode(b'test_client_public_key'),
            "salt": base64url_encode(b'test_salt'),
            "certificate_chain": [base64url_encode(b'test_cert')]
        }

        response = self.app.post('/v1/verify/agreement', data=json.dumps(request_data), content_type='application/json')
        response_data = json.loads(response.data)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response_data['is_verified'])
        mock_get_session.assert_called_once_with(unittest.mock.ANY, "test_session_id")
        mock_delete_session.assert_called_once_with(unittest.mock.ANY, "test_session_id", AGREEMENT_KEY_ATTESTATION_SESSION_KIND)
        mock_store_result.assert_called_once()

    @patch('key_attestation.key_attestation.datastore_client', new_callable=MagicMock)
    @patch('key_attestation.key_attestation.get_ds_agreement_key_attestation_session')
    @patch('key_attestation.key_attestation.delete_ds_key_attestation_session')
    @patch('key_attestation.key_attestation.store_ds_key_attestation_result')
    @patch('key_attestation.key_attestation.derive_shared_key')
    @patch('key_attestation.key_attestation.decrypt_data')
    def test_verify_agreement_nonce_mismatch(self, mock_decrypt, mock_derive_key, mock_store_result, mock_delete_session, mock_get_session, mock_ds_client):
        # Mocking session data from Datastore
        mock_session_entity = MagicMock()
        mock_session_entity.get.side_effect = lambda key: {
            'nonce': base64url_encode(b'test_nonce'),
            'challenge': base64url_encode(b'test_challenge'),
            'private_key': base64url_encode(b'test_server_private_key')
        }.get(key)
        mock_get_session.return_value = mock_session_entity

        # Mocking key derivation and decryption for nonce mismatch
        mock_derive_key.return_value = b'test_aes_key'
        mock_decrypt.return_value = b'wrong_nonce'

        iv = base64url_encode(b'123456789012')
        encrypted_data = base64url_encode(b'encrypted_nonce')
        request_data = {
            "session_id": "test_session_id",
            "encrypted_data": f"{iv}{encrypted_data}",
            "client_public_key": base64url_encode(b'test_client_public_key'),
            "salt": base64url_encode(b'test_salt'),
            "certificate_chain": [base64url_encode(b'test_cert')]
        }

        response = self.app.post('/v1/verify/agreement', data=json.dumps(request_data), content_type='application/json')
        response_data = json.loads(response.data)

        self.assertEqual(response.status_code, 400)
        self.assertIn('Nonce mismatch', response_data['error'])
        mock_delete_session.assert_called_once_with(unittest.mock.ANY, "test_session_id", AGREEMENT_KEY_ATTESTATION_SESSION_KIND)
        mock_store_result.assert_called_once()
