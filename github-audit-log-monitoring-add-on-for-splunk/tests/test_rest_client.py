"""Unit tests for rest client
"""
import os
import unittest
import configparser
from bin.rest_client import GitHub


class TestRestClient(unittest.TestCase):
    """Set of unit tests for the GitHub REST client class"""

    def setUp(self):
        """Read the local configuration file to fetch access token
        and instantiate the GitHub object
        """
        file_name = "config.ini"
        config_path = os.path.join(os.path.dirname(__file__), file_name)
        self.local = configparser.ConfigParser()
        self.local.read(config_path)
        self.GitHub = GitHub(
            api_url="https://api.github.com",
            access_token=self.local["config"]["access_token"],
        )

    def test_headers(self):
        """Test the headers mutator"""
        mock_headers = {"header1": "value1", "header-2": "value2"}
        # Pass no headers
        self.assertIsNone(self.GitHub.headers())
        # Pass empty headers
        self.assertEqual(self.GitHub.headers(""), "")
        # Pass empty dictionary
        self.assertDictEqual(self.GitHub.headers({}), {})
        # Happy flow
        self.assertDictEqual(self.GitHub.headers(mock_headers), mock_headers)

    def test_set_max_entries(self):
        # Fail max_entries not int
        mock_max_entries = "ABC"
        with self.assertRaises(ValueError):
            self.GitHub.set_max_entries(mock_max_entries)
        # Fail max_entries is not provided
        with self.assertRaises(TypeError):
            self.GitHub.set_max_entries()
        # Succeed
        mock_max_entries = 100
        output = self.GitHub.set_max_entries(mock_max_entries)
        self.assertEqual(output, mock_max_entries)

    def test_set_event_types(self):
        # Fail event_types not string
        mock_event_types = 12345
        with self.assertRaises(ValueError):
            self.GitHub.set_event_types(mock_event_types)
        # Fail event_types not included in [web, git, all]
        mock_event_types = "gat"
        with self.assertRaises(ValueError):
            self.GitHub.set_event_types(mock_event_types)
        # Succeed
        mock_event_types = "web"
        output = self.GitHub.set_event_types(mock_event_types)
        self.assertEqual(output, mock_event_types)

    @unittest.skip("Integration test, results vary based on production data")
    def test_get_enterprise_audit_log(self):
        mock_enterprise = self.local["config"]["enterprise_a"]
        audit_log = self.GitHub.get_enterprise_audit_log(
            enterprise=mock_enterprise, page_cursor=None
        )
        self.assertGreaterEqual(audit_log.total, 1)

    @unittest.skip("Integration test, results vary based on production data")
    def test_get_enterprise_audit_log_with_event_type(self):
        mock_enterprise = self.local["config"]["enterprise_a"]
        mock_event_types = "git"
        self.GitHub.set_event_types(mock_event_types)
        audit_log = self.GitHub.get_enterprise_audit_log(
            enterprise=mock_enterprise, page_cursor=None
        )
        self.assertEqual(audit_log.total, 0)

    @unittest.skip("Integration test, results vary based on production data")
    def test_get_enterprise_audit_log_with_max_entries(self):
        mock_enterprise = self.local["config"]["enterprise_b"]
        self.GitHub.set_max_entries(5000)
        audit_log = self.GitHub.get_enterprise_audit_log(
            enterprise=mock_enterprise, page_cursor=None
        )
        self.assertGreaterEqual(audit_log.total, 5000)

    @unittest.skip("Integration test, results vary based on production data")
    def test_get_enterprise_audit_log_with_page_cursor(self):
        mock_enterprise = self.local["config"]["enterprise_a"]
        mock_after_cursor = "MS41OTczMjA2ODI5NDdlKzEyfEV3WGF4QmVwNU5PLXV2ekNZWGtPNUE="
        audit_log = self.GitHub.get_enterprise_audit_log(
            enterprise=mock_enterprise, page_cursor=mock_after_cursor
        )
        self.assertGreaterEqual(audit_log.total, 1)

    @unittest.skip("Integration test, results vary based on production data")
    def test_get_enterprise_audit_log_with_last_page(self):
        mock_enterprise = self.local["config"]["enterprise_a"]
        mock_after_cursor = "MS42MTUyNDUwNjMxMzllKzEyfFJlajB3NGVFMDBhUVFzQ1ZheXU1QXc="
        mock_last_document_id = ""
        mock_last_count = 0
        audit_log = self.GitHub.get_enterprise_audit_log(
            enterprise=mock_enterprise,
            page_cursor=mock_after_cursor,
            last_document_id=mock_last_document_id,
            last_count=mock_last_count,
        )
        self.assertEqual(audit_log.total, 10)

    def test_rate_limit_reached_exception(self):
        pass
