"""Unit tests for the audit log class
"""
import os
import unittest
import configparser
import json
import hashlib
from bin.audit_log import AuditLog


class MockResponse:
    """[summary]"""

    def __init__(self, **args):
        self.__dict__.update(args)

    def json(self):
        return json.loads(self.content)


class TestAuditLog(unittest.TestCase):
    """Set of unit tests for the AuditLog class"""

    def setUp(self):
        self._audit_log = AuditLog("poizen-inc")
        self._mock_response = MockResponse(
            **{
                "url": "https://api.github.com/enterprises/poizen-inc/audit-log?phrase=&include=all&after=&before=&order=&per_page=10",
                "headers": {
                    "Server": "GitHub.com",
                    "Date": "Sat, 06 Mar 2021 12:39:30 GMT",
                    "Content-Type": "application/json; charset=utf-8",
                    "Transfer-Encoding": "chunked",
                    "Cache-Control": "private, max-age=60, s-maxage=60",
                    "Vary": "Accept, Authorization, Cookie, X-GitHub-OTP, Accept-Encoding, Accept, X-Requested-With",
                    "ETag": 'W/"randomfuzz"',
                    "X-OAuth-Scopes": "admin:enterprise, admin:org, read:packages, read:public_key, repo, user, workflow",
                    "X-Accepted-OAuth-Scopes": "admin:enterprise",
                    "X-GitHub-Media-Type": "github.v3; format=json",
                    "Link": '<https://api.github.com/enterprises/1070/audit-log?phrase=&include=all&after=MS42MTQ2OTI2NDYwMzZlKzEyfDY0N0w0UXBHVWtVclZPbEZmNVZXRVE9PQ%3D%3D&before=&order=&per_page=10>; rel="next", <https://api.github.com/enterprises/1070/audit-log?phrase=&include=all&after=&before=&order=&per_page=10>; rel="first", <https://api.github.com/enterprises/1070/audit-log?phrase=&include=all&after=&before=MS42MTQ2OTc2Mzg2NmUrMTJ8RzVnYmpBU1dUdVlYLV9CSmE2aTRlUT09&order=&per_page=10>; rel="prev"',
                    "X-RateLimit-Limit": "5000",
                    "X-RateLimit-Remaining": "4955",
                    "X-RateLimit-Reset": "1615036681",
                    "X-RateLimit-Used": "45",
                    "Access-Control-Expose-Headers": "ETag, Link, Location, Retry-After, X-GitHub-OTP, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Used, X-RateLimit-Reset, X-OAuth-Scopes, X-Accepted-OAuth-Scopes, X-Poll-Interval, X-GitHub-Media-Type, Deprecation, Sunset",
                    "Access-Control-Allow-Origin": "*",
                    "Strict-Transport-Security": "max-age=31536000; includeSubdomains; preload",
                    "X-Frame-Options": "deny",
                    "X-Content-Type-Options": "nosniff",
                    "X-XSS-Protection": "1; mode=block",
                    "Referrer-Policy": "origin-when-cross-origin, strict-origin-when-cross-origin",
                    "Content-Security-Policy": "default-src 'none'",
                    "Content-Encoding": "gzip",
                    "X-GitHub-Request-Id": "F713:FUZZ:FUZZ:FUZZ",
                },
                "content": '[{"@timestamp":1614697638660,"business":"poizen-inc","org":"org-demo","repo":"org-demo/public-repo","action":"git.fetch","transport_protocol_name":"http","transport_protocol":1,"repository":"org-demo/public-repo","repository_public":true},{"actor":"Link-","@timestamp":1614693008148,"org":"org-demo","created_at":1614693008148,"action":"org.update_member","user":"Link-","_document_id":"m-_x7LGec_iesTK56lXGgQ"},{"actor":"Link-","@timestamp":1614692712281,"org":"org-demo","created_at":1614692712281,"action":"org.update_default_repository_permission","_document_id":"wDFUFkZDYEac1CtSfJ61zg"},{"actor":"","@timestamp":1614692691041,"business":"poizen-inc","org":"org-demo","repo":"org-demo/private-repo-2","action":"git.clone","transport_protocol_name":"http","transport_protocol":1,"repository":"org-demo/private-repo-2","user":"","repository_public":false},{"actor":"","@timestamp":1614692689805,"business":"poizen-inc","org":"org-demo","repo":"org-demo/private-repo-2","action":"git.fetch","transport_protocol_name":"http","transport_protocol":1,"repository":"org-demo/private-repo-2","user":"","_document_id":"uQZXhZ0mcj8gJPuDbJxd8w==","repository_public":false},{"actor":"Link-","@timestamp":1614692687389,"visibility":"private","org":"org-demo","repo":"org-demo/private-repo-2","created_at":1614692687389,"action":"repo.create","_document_id":"45S66REXBCQ9NoQBPDwaGg"},{"actor":"Link-","@timestamp":1614692663825,"visibility":"private","org":"org-demo","repo":"org-demo/private-repo","created_at":1614692663825,"action":"repo.create","_document_id":"Go71L7jsQzHVjZzIVoHsBQ"},{"@timestamp":1614692646139,"business":"poizen-inc","org":"org-demo","repo":"org-demo/public-repo","action":"git.clone","transport_protocol_name":"http","transport_protocol":1,"repository":"org-demo/public-repo","_document_id":"Y_K0Y9VpsBzurQKAyCH3OQ==","repository_public":true},{"@timestamp":1614692646087,"business":"poizen-inc","org":"org-demo","repo":"org-demo/public-repo","action":"git.fetch","transport_protocol_name":"http","transport_protocol":1,"repository":"org-demo/public-repo","_document_id":"gaLqZSLus6Co6ginCtGX5A==","repository_public":true},{"@timestamp":1614692646036,"business":"poizen-inc","org":"org-demo","repo":"org-demo/public-repo","action":"git.fetch","transport_protocol_name":"http","transport_protocol":1,"repository":"org-demo/public-repo","_document_id":"647L4QpGUkUrVOlFf5VWEQ==","repository_public":true}]',
                "status_code": 200,
                "links": {
                    "next": {
                        "url": "https://api.github.com/enterprises/1070/audit-log?phrase=&include=all&after=MS42MTQ2OTI2NDYwMzZlKzEyfDY0N0w0UXBHVWtVclZPbEZmNVZXRVE9PQ%3D%3D&before=&order=&per_page=10",
                        "rel": "next",
                    },
                    "first": {
                        "url": "https://api.github.com/enterprises/1070/audit-log?phrase=&include=all&after=&before=&order=&per_page=10",
                        "rel": "first",
                    },
                    "prev": {
                        "url": "https://api.github.com/enterprises/1070/audit-log?phrase=&include=all&after=&before=MS42MTQ2OTc2Mzg2NmUrMTJ8RzVnYmpBU1dUdVlYLV9CSmE2aTRlUT09&order=&per_page=10",
                        "rel": "prev",
                    },
                },
            }
        )

    def test_set_page_cursor(self):
        # Test when next, first and prev parameters are available in the response
        mock_links_all = {
            "next": {
                "url": "https://api.github.com/enterprises/1070/audit-log?phrase=&include=all&after=MS42MTQ2OTI2NDYwMzZlKzEyfDY0N0w0UXBHVWtVclZPbEZmNVZXRVE9PQ%3D%3D&before=&order=&per_page=10",
                "rel": "next",
            },
            "first": {
                "url": "https://api.github.com/enterprises/1070/audit-log?phrase=&include=all&after=&before=&order=&per_page=10",
                "rel": "first",
            },
            "prev": {
                "url": "https://api.github.com/enterprises/1070/audit-log?phrase=&include=all&after=&before=MS42MTQ2OTc2Mzg2NmUrMTJ8RzVnYmpBU1dUdVlYLV9CSmE2aTRlUT09&order=&per_page=10",
                "rel": "prev",
            },
        }
        mock_url = "https://api.github.com/enterprises/1070/audit-log?phrase=&include=all&after=MS42MTQ2OTI2NDYwMzZlKzEyfDY0N0w0UXBHVWtVclZPbEZmNVZXRVE9PQ%3D%3D&before=&order=&per_page=10"
        output = self._audit_log.set_page_cursor(mock_links_all, mock_url)
        expected_output = {
            "prev": "MS42MTQ2OTc2Mzg2NmUrMTJ8RzVnYmpBU1dUdVlYLV9CSmE2aTRlUT09",
            "first": {"per_page": ["10"], "include": ["all"]},
            "next": "MS42MTQ2OTI2NDYwMzZlKzEyfDY0N0w0UXBHVWtVclZPbEZmNVZXRVE9PQ==",
            "last": "MS42MTQ2OTI2NDYwMzZlKzEyfDY0N0w0UXBHVWtVclZPbEZmNVZXRVE9PQ==",
        }
        self.assertEqual(output, expected_output)
        # Test when next, prev parameters only are available in the response
        mock_next_prev = {
            "next": {
                "url": "https://api.github.com/enterprises/1070/audit-log?phrase=&include=all&after=MS42MTQ2OTI2NDYwMzZlKzEyfDY0N0w0UXBHVWtVclZPbEZmNVZXRVE9PQ%3D%3D&before=&order=&per_page=10",
                "rel": "next",
            },
            "prev": {
                "url": "https://api.github.com/enterprises/1070/audit-log?phrase=&include=all&after=&before=MS42MTQ2OTc2Mzg2NmUrMTJ8RzVnYmpBU1dUdVlYLV9CSmE2aTRlUT09&order=&per_page=10",
                "rel": "prev",
            },
        }
        mock_url = "https://api.github.com/enterprises/1070/audit-log?phrase=&include=all&after=MS42MTQ2OTI2NDYwMzZlKzEyfDY0N0w0UXBHVWtVclZPbEZmNVZXRVE9PQ%3D%3D&before=&order=&per_page=10"
        output = self._audit_log.set_page_cursor(mock_next_prev, mock_url)
        expected_output = {
            "prev": "MS42MTQ2OTc2Mzg2NmUrMTJ8RzVnYmpBU1dUdVlYLV9CSmE2aTRlUT09",
            "first": None,
            "next": "MS42MTQ2OTI2NDYwMzZlKzEyfDY0N0w0UXBHVWtVclZPbEZmNVZXRVE9PQ==",
            "last": "MS42MTQ2OTI2NDYwMzZlKzEyfDY0N0w0UXBHVWtVclZPbEZmNVZXRVE9PQ==",
        }
        self.assertEqual(output, expected_output)
        # Test when no parameters are available in the response
        mock_no_params = {}
        mock_url = "https://api.github.com/enterprises/1070/audit-log?phrase=&include=all&after=MS42MTQ2OTI2NDYwMzZlKzEyfDY0N0w0UXBHVWtVclZPbEZmNVZXRVE9PQ%3D%3D&before=&order=&per_page=10"
        output = self._audit_log.set_page_cursor(mock_no_params, mock_url)
        expected_output = {
            "prev": None,
            "first": None,
            "next": None,
            "last": None,
        }
        self.assertEqual(output, expected_output)
        # Test when after is not specified in the url
        mock_no_params = {}
        mock_url = "https://api.github.com/enterprises/1070/audit-log?phrase=&include=all&after=&before=&order=&per_page=10"
        output = self._audit_log.set_page_cursor(mock_no_params, mock_url)
        expected_output = {
            "prev": None,
            "first": None,
            "next": None,
            "last": None,
        }
        self.assertEqual(output, expected_output)

    def test_set_api_limits(self):
        expected_output = {
            "x_rl_limit": "5000",
            "x_rl_remainig": "4955",
            "x_rl_reset_timestamp": "1615036681",
            "x_rl_used": "45",
        }
        output = self._audit_log.set_api_limits(self._mock_response.headers)
        self.assertEqual(output, expected_output)

    def test_set_last_page(self):
        expected_output = {"_document_id": "647L4QpGUkUrVOlFf5VWEQ==", "count": 10}
        output = self._audit_log.set_last_page(
            last_document_id="647L4QpGUkUrVOlFf5VWEQ==", last_count=10
        )
        self.assertEqual(output, expected_output)

    def test_truncate_from_start(self):
        mock_count = 5
        expected_entries = [
            "1614692687389 - repo.create",
            "1614692663825 - repo.create",
            "1614692646139 - git.clone",
            "1614692646087 - git.fetch",
            "1614692646036 - git.fetch",
        ]
        self._audit_log.load(self._mock_response)
        audit_log = iter(self._audit_log.truncate_from_start(count=mock_count))
        for audit_log_entry in audit_log:
            self.assertIn(audit_log_entry.id, expected_entries)

    def test_empty(self):
        self._audit_log.load(self._mock_response)
        audit_log = iter(self._audit_log.empty())
        self.assertEqual(audit_log.total, 0)

    def test_load(self):
        expected_page_cursor = {
            "prev": "MS42MTQ2OTc2Mzg2NmUrMTJ8RzVnYmpBU1dUdVlYLV9CSmE2aTRlUT09",
            "first": {"per_page": ["10"], "include": ["all"]},
            "next": "MS42MTQ2OTI2NDYwMzZlKzEyfDY0N0w0UXBHVWtVclZPbEZmNVZXRVE9PQ==",
            "last": None,
        }
        expected_api_limits = {
            "x_rl_limit": "5000",
            "x_rl_remainig": "4955",
            "x_rl_reset_timestamp": "1615036681",
            "x_rl_used": "45",
        }
        expected_last_page = {"_document_id": "647L4QpGUkUrVOlFf5VWEQ==", "count": 10}
        audit_log = iter(self._audit_log)
        audit_log.load(self._mock_response)
        self.assertEqual(audit_log.index, 0)
        self.assertEqual(audit_log.total, 10)
        self.assertEqual(audit_log.enterprise, "poizen-inc")
        self.assertEqual(audit_log.page_cursor, expected_page_cursor)
        self.assertEqual(audit_log.api_rate_limits, expected_api_limits)
        self.assertTrue(audit_log.has_next_page)
        self.assertEqual(audit_log.last_page, expected_last_page)

    def test_loop_iterator(self):
        audit_log = iter(self._audit_log)
        audit_log.load(self._mock_response)
        expected_entries = [
            "1614697638660 - git.fetch",
            "1614693008148 - org.update_member",
            "1614692712281 - org.update_default_repository_permission",
            "1614692691041 - git.clone",
            "1614692689805 - git.fetch",
            "1614692687389 - repo.create",
            "1614692663825 - repo.create",
            "1614692646139 - git.clone",
            "1614692646087 - git.fetch",
            "1614692646036 - git.fetch",
        ]
        for audit_log_entry in audit_log:
            self.assertIn(audit_log_entry.id, expected_entries)
