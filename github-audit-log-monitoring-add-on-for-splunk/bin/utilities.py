"""Utilities class
"""
from __future__ import absolute_import, print_function


class Utilities:
    @staticmethod
    def empty_state_file():
        """Returns the default content of an empty state file"""
        return """
[input]
pat_credential_id =
page_cursor =
last_document_id =
last_count =
"""

    @staticmethod
    def splunk_serialize(obj=None):
        if obj is None:
            return ""
        output = ""
        for property, value in list(vars(obj).items()):
            output += "{}={} ".format(property, value)
        return output
