import unittest
from unittest.mock import MagicMock, patch, ANY
import sys
import os
from datetime import datetime, timezone, timedelta

# Add the parent directory (server/key_attestation) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from datastore_utils import (
    store_key_attestation_session,
    get_key_attestation_session,
    delete_key_attestation_session,
    store_key_attestation_result,
    cleanup_expired_sessions,
    KEY_ATTESTATION_SESSION_KIND,
    KEY_ATTESTATION_RESULT_KIND,
    NONCE_EXPIRY_MINUTES
)

class TestDatastoreUtils(unittest.TestCase):

    def test_store_key_attestation_session(self):
        mock_datastore_client = MagicMock()
        mock_entity = MagicMock()
        mock_key = MagicMock()

        mock_datastore_client.key.return_value = mock_key
        mock_datastore_client.entity.return_value = mock_entity
        # Ensure that the transaction doesn't find an existing entity
        mock_datastore_client.get.return_value = None

        session_id = "test_session_123"
        nonce_encoded = "test_nonce_encoded"
        challenge_encoded = "test_challenge_encoded"

        # Patch cleanup_expired_sessions within this test's scope
        with patch('datastore_utils.cleanup_expired_sessions') as mock_cleanup:
            store_key_attestation_session(mock_datastore_client, session_id, nonce_encoded, challenge_encoded)

            mock_datastore_client.key.assert_called_once_with(KEY_ATTESTATION_SESSION_KIND, session_id)
            mock_datastore_client.entity.assert_called_once_with(key=mock_key)

            mock_entity.update.assert_called_once_with({
                'session_id': session_id,
                'nonce': nonce_encoded,
                'challenge': challenge_encoded,
                'generated_at': ANY, # datetime.now(timezone.utc) is called
            })
            mock_datastore_client.put.assert_called_once_with(mock_entity)
            mock_cleanup.assert_called_once_with(mock_datastore_client, KEY_ATTESTATION_SESSION_KIND)


    def test_get_key_attestation_session_found_not_expired(self):
        mock_datastore_client = MagicMock()
        mock_entity = MagicMock()
        mock_key = MagicMock()

        session_id = "test_session_abc"
        stored_nonce = "stored_nonce"
        stored_challenge = "stored_challenge"
        # Generate a 'generated_at' that is recent (e.g., 5 minutes ago)
        generated_time = datetime.now(timezone.utc) - timedelta(minutes=5)

        mock_entity.get.side_effect = lambda key: {
            'nonce': stored_nonce,
            'challenge': stored_challenge,
            'generated_at': generated_time
        }.get(key)

        # Make the entity itself behave like a dictionary for .get calls
        # or make it return values for specific keys
        # Simplest: make the entity itself the dictionary
        mock_retrieved_entity = {
            'session_id': session_id, # Though not strictly checked by get_key_attestation_session
            'nonce': stored_nonce,
            'challenge': stored_challenge,
            'generated_at': generated_time
        }

        mock_datastore_client.key.return_value = mock_key
        mock_datastore_client.get.return_value = mock_retrieved_entity

        retrieved_session = get_key_attestation_session(mock_datastore_client, session_id)

        mock_datastore_client.key.assert_called_once_with(KEY_ATTESTATION_SESSION_KIND, session_id)
        mock_datastore_client.get.assert_called_once_with(mock_key)
        self.assertIsNotNone(retrieved_session)
        self.assertEqual(retrieved_session.get('nonce'), stored_nonce)


    def test_get_key_attestation_session_found_expired(self):
        mock_datastore_client = MagicMock()
        mock_key = MagicMock()
        session_id = "test_session_expired"

        # Generate a 'generated_at' that is older than NONCE_EXPIRY_MINUTES
        expired_time = datetime.now(timezone.utc) - timedelta(minutes=NONCE_EXPIRY_MINUTES + 5)

        mock_expired_entity = {
            'generated_at': expired_time
        }
        mock_datastore_client.key.return_value = mock_key
        mock_datastore_client.get.return_value = mock_expired_entity

        retrieved_session = get_key_attestation_session(mock_datastore_client, session_id)

        self.assertIsNone(retrieved_session)
        mock_datastore_client.key.assert_called_once_with(KEY_ATTESTATION_SESSION_KIND, session_id)
        mock_datastore_client.get.assert_called_once_with(mock_key)

    def test_get_key_attestation_session_not_found(self):
        mock_datastore_client = MagicMock()
        mock_key = MagicMock()
        session_id = "test_session_nonexistent"

        mock_datastore_client.key.return_value = mock_key
        mock_datastore_client.get.return_value = None # Simulate entity not found

        retrieved_session = get_key_attestation_session(mock_datastore_client, session_id)

        self.assertIsNone(retrieved_session)
        mock_datastore_client.key.assert_called_once_with(KEY_ATTESTATION_SESSION_KIND, session_id)
        mock_datastore_client.get.assert_called_once_with(mock_key)

    def test_delete_key_attestation_session(self):
        mock_datastore_client = MagicMock()
        mock_key = MagicMock()
        session_id = "session_to_delete"
        kind = KEY_ATTESTATION_SESSION_KIND

        mock_datastore_client.key.return_value = mock_key

        delete_key_attestation_session(mock_datastore_client, session_id, kind)

        mock_datastore_client.key.assert_called_once_with(kind, session_id)
        mock_datastore_client.delete.assert_called_once_with(mock_key)

    def test_store_key_attestation_result(self):
        mock_datastore_client = MagicMock()
        mock_entity = MagicMock()
        mock_key = MagicMock()

        mock_datastore_client.key.return_value = mock_key
        mock_datastore_client.entity.return_value = mock_entity

        session_id = "result_session_id"
        result = "verified"
        reason = "All checks passed."
        payload_str = "{'device_info': {}}"
        attestation_str = "{'attestation_version': 4}"

        store_key_attestation_result(mock_datastore_client, session_id, result, reason, payload_str, attestation_str)

        mock_datastore_client.key.assert_called_once_with(KEY_ATTESTATION_RESULT_KIND, session_id)
        mock_datastore_client.entity.assert_called_once_with(key=mock_key)
        mock_entity.update.assert_called_once_with({
            'session_id': session_id,
            'created_at': ANY, # datetime.now(timezone.utc)
            'result': result,
            'reason': reason,
            'payload_data': payload_str,
            'attestation_data': attestation_str
        })
        mock_datastore_client.put.assert_called_once_with(mock_entity)

    def test_cleanup_expired_sessions(self):
        mock_datastore_client = MagicMock()
        mock_query = MagicMock()

        # Simulate some expired entities found
        expired_key1 = mock_datastore_client.key(KEY_ATTESTATION_SESSION_KIND, "expired1")
        expired_key2 = mock_datastore_client.key(KEY_ATTESTATION_SESSION_KIND, "expired2")
        # The query.fetch() should return iterables that have a .key attribute
        mock_entity_with_key1 = MagicMock()
        mock_entity_with_key1.key = expired_key1
        mock_entity_with_key2 = MagicMock()
        mock_entity_with_key2.key = expired_key2

        mock_datastore_client.query.return_value = mock_query
        # query.fetch() returns a list of entities (or their keys if keys_only())
        mock_query.fetch.return_value = [mock_entity_with_key1, mock_entity_with_key2]


        cleanup_expired_sessions(mock_datastore_client, KEY_ATTESTATION_SESSION_KIND)

        mock_datastore_client.query.assert_called_once_with(kind=KEY_ATTESTATION_SESSION_KIND)
        mock_query.add_filter.assert_called_once_with('generated_at', '<', ANY)
        mock_query.keys_only.assert_called_once()
        mock_query.fetch.assert_called_once()
        mock_datastore_client.delete_multi.assert_called_once_with([expired_key1, expired_key2])

    def test_cleanup_expired_sessions_none_found(self):
        mock_datastore_client = MagicMock()
        mock_query = MagicMock()

        mock_datastore_client.query.return_value = mock_query
        mock_query.fetch.return_value = [] # No expired entities

        cleanup_expired_sessions(mock_datastore_client, KEY_ATTESTATION_SESSION_KIND)

        mock_datastore_client.query.assert_called_once_with(kind=KEY_ATTESTATION_SESSION_KIND)
        mock_query.add_filter.assert_called_once_with('generated_at', '<', ANY)
        mock_query.keys_only.assert_called_once()
        mock_query.fetch.assert_called_once()
        mock_datastore_client.delete_multi.assert_not_called()


if __name__ == '__main__':
    unittest.main()
