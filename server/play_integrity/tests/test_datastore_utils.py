import unittest
from unittest.mock import MagicMock, patch, ANY
from datetime import datetime, timezone, timedelta

from server.play_integrity.datastore_utils import (
    store_nonce_with_session_v1,
    get_nonce_entity,
    delete_nonce,
    store_verification_attempt,
    cleanup_expired_nonces,
    NONCE_KIND,
    VERIFIED_PAYLOAD_KIND,
    NONCE_EXPIRY_MINUTES,
    RESULT_SUCCESS,
    RESULT_FAILED
)

class TestDatastoreUtils(unittest.TestCase):

    def setUp(self):
        self.mock_datastore_client = MagicMock()

    @patch('server.play_integrity.datastore_utils.cleanup_expired_nonces')
    @patch('server.play_integrity.datastore_utils.datastore.Entity')
    def test_store_nonce_with_session_v1(self, mock_entity_class, mock_cleanup):
        session_id = "test_session_1"
        raw_nonce = b"test_raw_nonce"

        mock_key = MagicMock()
        mock_entity_instance = MagicMock()
        self.mock_datastore_client.key.return_value = mock_key
        mock_entity_class.return_value = mock_entity_instance

        nonce, gen_time = store_nonce_with_session_v1(self.mock_datastore_client, session_id, raw_nonce)

        self.mock_datastore_client.key.assert_called_once_with(NONCE_KIND, session_id)
        mock_entity_class.assert_called_once_with(key=mock_key)
        mock_entity_instance.update.assert_called_once_with({
            'nonce': ANY,
            'generated_datetime': ANY,
            'expiry_datetime': ANY,
            'session_id': session_id,
        })
        self.mock_datastore_client.put.assert_called_once_with(mock_entity_instance)
        mock_cleanup.assert_called_once_with(self.mock_datastore_client)
        self.assertIsInstance(nonce, str)
        self.assertIsInstance(gen_time, int)

    def test_get_nonce_entity_found_and_valid(self):
        session_id = "test_session_2"
        mock_key = MagicMock()
        mock_entity = MagicMock()
        mock_entity.get.return_value = datetime.now(timezone.utc) + timedelta(minutes=5) # Not expired
        self.mock_datastore_client.key.return_value = mock_key
        self.mock_datastore_client.get.return_value = mock_entity

        entity = get_nonce_entity(self.mock_datastore_client, session_id)

        self.mock_datastore_client.get.assert_called_once_with(mock_key)
        self.assertIsNotNone(entity)

    def test_get_nonce_entity_expired(self):
        session_id = "test_session_3"
        mock_key = MagicMock()
        mock_entity = MagicMock()
        mock_entity.get.return_value = datetime.now(timezone.utc) - timedelta(minutes=NONCE_EXPIRY_MINUTES + 1) # Expired
        self.mock_datastore_client.key.return_value = mock_key
        self.mock_datastore_client.get.return_value = mock_entity

        entity = get_nonce_entity(self.mock_datastore_client, session_id)

        self.assertIsNone(entity)
        self.mock_datastore_client.delete.assert_called_once_with(mock_key)

    def test_get_nonce_entity_not_found(self):
        session_id = "test_session_4"
        self.mock_datastore_client.get.return_value = None

        entity = get_nonce_entity(self.mock_datastore_client, session_id)
        self.assertIsNone(entity)

    def test_delete_nonce(self):
        session_id = "test_session_5"
        mock_key = MagicMock()
        self.mock_datastore_client.key.return_value = mock_key

        delete_nonce(self.mock_datastore_client, session_id)

        self.mock_datastore_client.key.assert_called_once_with(NONCE_KIND, session_id)
        self.mock_datastore_client.delete.assert_called_once_with(mock_key)

    @patch('server.play_integrity.datastore_utils.generate_unique_id', return_value="unique-id-123")
    @patch('server.play_integrity.datastore_utils.datastore.Entity')
    def test_store_verification_attempt(self, mock_entity_class, mock_uuid):
        session_id = "test_session_6"
        client_data = {"device_info": {"model": "Pixel"}}

        mock_key = MagicMock()
        mock_entity_instance = MagicMock()
        self.mock_datastore_client.key.return_value = mock_key
        mock_entity_class.return_value = mock_entity_instance

        store_verification_attempt(
            self.mock_datastore_client, session_id, client_data,
            RESULT_SUCCESS, "classic", "Success", {"payload": "..."},
        )

        self.mock_datastore_client.key.assert_called_once_with(VERIFIED_PAYLOAD_KIND, "unique-id-123")
        mock_entity_class.assert_called_once_with(key=mock_key, exclude_from_indexes=['api_response', 'payload_data'])
        mock_entity_instance.update.assert_called_once()
        self.mock_datastore_client.put.assert_called_once_with(mock_entity_instance)

    def test_cleanup_expired_nonces(self):
        mock_query = MagicMock()
        mock_entity1 = MagicMock()
        mock_entity2 = MagicMock()
        mock_entity1.key = "key1"
        mock_entity2.key = "key2"
        mock_query.fetch.return_value = [mock_entity1, mock_entity2]
        self.mock_datastore_client.query.return_value = mock_query

        cleanup_expired_nonces(self.mock_datastore_client)

        self.mock_datastore_client.query.assert_called_once_with(kind=NONCE_KIND)
        mock_query.add_filter.assert_called_once_with('expiry_datetime', '<', ANY)
        self.mock_datastore_client.delete_multi.assert_called_once_with(["key1", "key2"])
