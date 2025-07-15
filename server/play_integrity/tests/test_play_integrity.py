import unittest
import json
from unittest.mock import patch, MagicMock

from server.play_integrity.play_integrity import app

class TestPlayIntegrityEndpoints(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

        # Mock the Datastore Client class itself to prevent initialization
        self.mock_datastore_class = patch('google.cloud.datastore.Client').start()
        self.mock_datastore_instance = self.mock_datastore_class.return_value

        # Also mock the datastore_client instance in the play_integrity module
        self.patcher_datastore_instance = patch('server.play_integrity.play_integrity.datastore_client', self.mock_datastore_instance)
        self.patcher_datastore_instance.start()


    def tearDown(self):
        patch.stopall()

    @patch('server.play_integrity.play_integrity.store_nonce_with_session_v1')
    def test_create_nonce_endpoint_success(self, mock_store_nonce):
        session_id = "session-12345"
        expected_nonce = "generated-nonce-string"
        expected_time = 1678886400000
        mock_store_nonce.return_value = (expected_nonce, expected_time)

        response = self.app.post('/play-integrity/classic/v1/nonce',
                                 data=json.dumps({'session_id': session_id}),
                                 content_type='application/json')

        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertEqual(response_data['nonce'], expected_nonce)
        self.assertEqual(response_data['generated_datetime'], expected_time)
        mock_store_nonce.assert_called_once_with(self.mock_datastore_instance, session_id, unittest.mock.ANY)

    def test_create_nonce_endpoint_no_json(self):
        response = self.app.post('/play-integrity/classic/v1/nonce',
                                 data=b'',
                                 content_type='application/json')
        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.data)
        self.assertIn('Bad Request', response_data['error'])

    @patch('server.play_integrity.play_integrity.get_nonce_entity')
    @patch('server.play_integrity.play_integrity.decode_integrity_token')
    @patch('server.play_integrity.play_integrity.compare_nonces', return_value=True)
    @patch('server.play_integrity.play_integrity.delete_nonce')
    @patch('server.play_integrity.play_integrity.store_verification_attempt')
    def test_verify_classic_success(self, mock_store, mock_delete, mock_compare, mock_decode, mock_get_nonce):
        session_id = "session-verify-ok"
        token = "valid-integrity-token"

        mock_nonce_entity = MagicMock()
        mock_nonce_entity.get.return_value = "stored-nonce-value"
        mock_get_nonce.return_value = mock_nonce_entity

        mock_api_response = {
            "tokenPayloadExternal": {
                "requestDetails": {
                    "nonce": "api-nonce-value"
                }
            }
        }
        mock_decode.return_value = mock_api_response

        response = self.app.post('/play-integrity/classic/v1/verify',
                                 data=json.dumps({'session_id': session_id, 'token': token}),
                                 content_type='application/json')

        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertEqual(response_data['play_integrity_response'], mock_api_response)
        mock_get_nonce.assert_called_once_with(self.mock_datastore_instance, session_id)
        mock_decode.assert_called_once_with(token, unittest.mock.ANY)
        mock_compare.assert_called_once()
        mock_delete.assert_called_once_with(self.mock_datastore_instance, session_id)
        mock_store.assert_called_once()

    @patch('server.play_integrity.play_integrity.get_nonce_entity')
    @patch('server.play_integrity.play_integrity.store_verification_attempt')
    def test_verify_classic_invalid_session(self, mock_store, mock_get_nonce):
        mock_get_nonce.return_value = None

        response = self.app.post('/play-integrity/classic/v1/verify',
                                 data=json.dumps({'session_id': 'invalid-session', 'token': 'any-token'}),
                                 content_type='application/json')

        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.data)
        self.assertIn("Invalid session_id", response_data['error'])
        mock_store.assert_called_once()

    @patch('server.play_integrity.play_integrity.decode_integrity_token')
    @patch('server.play_integrity.play_integrity.store_verification_attempt')
    def test_verify_standard_success(self, mock_store, mock_decode):
        session_id = "session-standard-ok"
        token = "valid-standard-token"

        mock_api_response = {"tokenPayloadExternal": {}}
        mock_decode.return_value = mock_api_response

        response = self.app.post('/play-integrity/standard/v1/verify',
                                 data=json.dumps({'session_id': session_id, 'token': token}),
                                 content_type='application/json')

        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertEqual(response_data['play_integrity_response'], mock_api_response)
        mock_decode.assert_called_once_with(token, unittest.mock.ANY)
        mock_store.assert_called_once()
