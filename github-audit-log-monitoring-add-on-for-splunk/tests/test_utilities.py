"""Unit tests for the audit log class
"""
import os
import unittest
from hashlib import md5
from bin.utilities import Utilities
from bin.audit_log_entry import AuditLogEntry


class TestUtilities(unittest.TestCase):
    """Set of unit tests for the Utilities class"""

    def test_splunk_serialize(self):
        mock_object = AuditLogEntry(
            timestamp="1614697638660",
            business="poizen-inc",
            org="org-demo",
            repo="org-demo/public-repo",
            action="git.fetch",
            transport_protocol_name="http",
            transport_protocol="1",
            repository="org-demo/public-repo",
            _document_id="G5gbjASWTuYX-_BJa6i4eQ==",
            repository_public="true",
        )
        output = sorted(Utilities.splunk_serialize(mock_object))
        expected_output = sorted(
            "transport_protocol=1 repository=org-demo/public-repo business=poizen-inc timestamp=1614697638660 repo=org-demo/public-repo action=git.fetch repository_public=true transport_protocol_name=http _document_id=G5gbjASWTuYX-_BJa6i4eQ== org=org-demo "
        )
        self.assertListEqual(output, expected_output)
