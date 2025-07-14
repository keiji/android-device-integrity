import unittest
from server.play_integrity.utils import mask_server_url, generate_unique_id

class TestUtils(unittest.TestCase):

    def test_mask_server_url(self):
        self.assertEqual(
            mask_server_url("Error connecting to https://example.com/api"),
            "Error connecting to API"
        )
        self.assertEqual(
            mask_server_url("Another error at http://another-site.net"),
            "Another error at API"
        )
        self.assertEqual(
            mask_server_url("No URL here"),
            "No URL here"
        )
        self.assertEqual(
            mask_server_url(12345),
            "12345"
        )

    def test_generate_unique_id(self):
        # Generate a couple of IDs and check they are different and have the expected length.
        id1 = generate_unique_id()
        id2 = generate_unique_id()
        self.assertIsInstance(id1, str)
        self.assertEqual(len(id1), 36) # UUID v4 string length
        self.assertNotEqual(id1, id2)
