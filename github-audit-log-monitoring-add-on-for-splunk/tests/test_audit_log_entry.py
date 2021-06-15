import json
import hashlib
import unittest
from bin.audit_log_entry import AuditLogEntry

class TestAuditLogEntry(unittest.TestCase):

    def test_no_document_id(self):
        mock_entry = {
            "@timestamp":"1614697638660","org":"org-demo","business":"poizen-inc","repo":"org-demo/public-repo","action":"git.fetch","transport_protocol_name":"http","transport_protocol":1,"repository":"org-demo/public-repo","repository_public":"true"
        }
        expected_output = "61ff3c1a135b3c6cac7ccabe2c6fe209"
        entry = AuditLogEntry(**mock_entry)
        self.assertEqual(entry.document_id, expected_output)

    def test_document_id(self):
        mock_entry = {
            "@timestamp":"1614697638660","_document_id":"wSuRpMciieZn4qkaR4YUtg","business":"poizen-inc","org":"org-demo","repo":"org-demo/public-repo","action":"git.fetch","transport_protocol_name":"http","transport_protocol":1,"repository":"org-demo/public-repo","repository_public":"true"
        }
        expected_output = "wSuRpMciieZn4qkaR4YUtg"
        entry = AuditLogEntry(**mock_entry)
        self.assertEqual(entry.document_id, expected_output)
