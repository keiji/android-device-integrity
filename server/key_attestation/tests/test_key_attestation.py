import unittest
import sys
import os

# Add the parent directory to sys.path to allow importing key_attestation
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from key_attestation import convert_bytes_to_hex_str

class TestKeyAttestationHelpers(unittest.TestCase):

    def test_convert_bytes_to_hex_str_empty(self):
        self.assertEqual(convert_bytes_to_hex_str({}), {})

    def test_convert_bytes_to_hex_str_no_bytes(self):
        data = {"a": 1, "b": "hello", "c": [1, "world"]}
        self.assertEqual(convert_bytes_to_hex_str(data), data)

    def test_convert_bytes_to_hex_str_simple_bytes(self):
        data = {"key1": b"\x01\x02\x03", "key2": "string"}
        expected = {"key1": "010203", "key2": "string"}
        self.assertEqual(convert_bytes_to_hex_str(data), expected)

    def test_convert_bytes_to_hex_str_nested_dict(self):
        data = {
            "level1_str": "hello",
            "level1_bytes": b"\xaa\xbb",
            "level1_dict": {
                "level2_int": 123,
                "level2_bytes": b"\xcc\xdd\xee"
            }
        }
        expected = {
            "level1_str": "hello",
            "level1_bytes": "aabb",
            "level1_dict": {
                "level2_int": 123,
                "level2_bytes": "ccddee"
            }
        }
        self.assertEqual(convert_bytes_to_hex_str(data), expected)

    def test_convert_bytes_to_hex_str_list_with_bytes(self):
        data = {
            "list_key": [
                "item1",
                b"\x11\x22",
                {"inner_byte": b"\x33\x44"},
                33
            ]
        }
        expected = {
            "list_key": [
                "item1",
                "1122",
                {"inner_byte": "3344"},
                33
            ]
        }
        self.assertEqual(convert_bytes_to_hex_str(data), expected)

    def test_convert_bytes_to_hex_str_mixed_list(self):
        data = ["string", b"\xff", 123, {"byte_val": b"\xab\xcd"}]
        expected = ["string", "ff", 123, {"byte_val": "abcd"}]
        # The helper expects a dict as the top-level usually, but let's test its list handling directly
        # For the purpose of this test, we'll wrap it if the function expects a dict
        # However, the current implementation of convert_bytes_to_hex_str handles top-level lists too.
        self.assertEqual(convert_bytes_to_hex_str(data), expected)

if __name__ == '__main__':
    unittest.main()
