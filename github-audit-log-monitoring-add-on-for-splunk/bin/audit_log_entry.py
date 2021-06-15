"""Audit Log Entry class
"""
import json
import hashlib


class AuditLogEntry:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return self.id

    @property
    def id(self):
        return "{} - {}".format(self.timestamp, self.action)

    @property
    def timestamp(self):
        if self.__dict__["@timestamp"]:
            return self.__dict__["@timestamp"]
        elif self.__dict__["timestamp"]:
            return self.__dict__["timestamp"]
        else:
            return None

    @property
    def action(self):
        return self.__dict__["action"]

    @property
    def actor(self):
        return self.__dict__["actor"]

    @property
    def transport_protocol_name(self):
        return self.__dict__["transport_protocol_name"]

    @property
    def transport_protocol(self):
        return self.__dict__["transport_protocol"]

    @property
    def created_at(self):
        return self.__dict__["created_at"]

    @property
    def org(self):
        return self.__dict__["org"] if not None else self.__dict__["business"]

    @property
    def team(self):
        return self.__dict__["team"]

    @property
    def user(self):
        return self.__dict__["user"]

    @property
    def repo(self):
        return self.__dict__["repo"]

    @property
    def visibility(self):
        return (
            self.__dict__["visibility"]
            if not None
            else self.__dict__["repository_public"]
        )

    @property
    def document_id(self):
        return (
            self.__dict__["_document_id"]
            if "_document_id" in self.__dict__
            else str(self.hash)
        )

    @property
    def hash(self):
        return hashlib.md5(
            json.dumps(self.__dict__, sort_keys=True).encode("utf-8")
        ).hexdigest()
