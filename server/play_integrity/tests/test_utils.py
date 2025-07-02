import unittest
from ..utils import mask_server_url

class TestMaskServerUrl(unittest.TestCase):

    def test_mask_http_url(self):
        self.assertEqual(
            mask_server_url("Error connecting to http://example.com"),
            "Error connecting to API"
        )

    def test_mask_https_url(self):
        self.assertEqual(
            mask_server_url("Error connecting to https://example.com/path?query=123"),
            "Error connecting to API"
        )

    def test_mask_multiple_urls(self):
        self.assertEqual(
            mask_server_url("Failed at https://test.com and http://another.org/test"),
            "Failed at API and API"
        )

    def test_no_url(self):
        self.assertEqual(
            mask_server_url("Just a normal error message."),
            "Just a normal error message."
        )

    def test_url_with_parentheses(self):
        self.assertEqual(
            mask_server_url("Error (see https://example.com/docs) for details."),
            "Error (see API) for details."
        )

    def test_url_at_end_of_string(self):
        self.assertEqual(
            mask_server_url("Problem with https://example.com"),
            "Problem with API"
        )

    def test_non_string_input(self):
        self.assertEqual(mask_server_url(123), "123")
        self.assertEqual(mask_server_url(None), "None")
        self.assertEqual(mask_server_url(["http://example.com"]), "['http://example.com']")

    def test_empty_string(self):
        self.assertEqual(mask_server_url(""), "")

    def test_url_with_various_chars(self):
        self.assertEqual(
            mask_server_url("Check https://example.com/path-with-hyphen_and_underscore/file.html?param1=value1&param2=value2#section"),
            "Check API"
        )

    def test_url_already_masked_returns_same(self):
        self.assertEqual(
            mask_server_url("Error with API endpoint"),
            "Error with API endpoint"
        )

    def test_complex_message_with_urls(self):
        message = "Service unavailable at https://service.example.com/api/v1/users, retry after 5 minutes. Also check status at http://status.example.com."
        expected = "Service unavailable at API, retry after 5 minutes. Also check status at API."
        self.assertEqual(mask_server_url(message), expected)

    def test_user_specified_error_message(self):
        # User-provided test case from chat
        error_string = '<HttpError 400 when requesting https://foobar.googleapis.com/v1/com.example.com:decodeIntegrityToken?alt=json returned "Integrity token has expired". Details: "Integrity token has expired">'
        expected_string = '<HttpError 400 when requesting API returned "Integrity token has expired". Details: "Integrity token has expired">'
        self.assertEqual(mask_server_url(error_string), expected_string)

if __name__ == '__main__':
    unittest.main()
