"""Rest API Client class
"""
from __future__ import absolute_import, print_function
import warnings
import requests
import time

from audit_log import AuditLog


class GitHub:
    """[summary]"""

    def __init__(self, api_url, access_token, max_entries=None):
        self._headers = None
        self._api_url = "https://"+api_url
        self._access_token = access_token
        self._max_entries = 1000 if max_entries is None else int(max_entries)
        self._max_entries_reached = False
        self._event_types = "all"

    @property
    def max_entries_reached(self):
        return self._max_entries_reached

    def headers(self, headers=None):
        """Get / Set request headers

        Args:
            headers (dict, optional): Headers dictionary. Defaults to None.

        Returns:
            dict: Headers dictionary
        """
        if headers is not None:
            self._headers = headers
        return self._headers

    def set_max_entries(self, max_entries):
        """Set the maximum number of entries to fetch per run

        Args:
            max_entries ([int]): max number of entries to fetch per run

        Raises:
            ValueError: max_entries is not of type int
        """
        if not isinstance(max_entries, int):
            raise ValueError(
                "max_entries accepts integer values only: {} provided.".format(
                    max_entries
                )
            )
        self._max_entries = max_entries
        return self._max_entries

    def set_event_types(self, event_types):
        """Set the event types to include:
                - web - returns web (non-Git) events
                - git - returns Git events
                - all - returns both web and Git events

        Args:
            event_types ([str]): event types to include

        Raises:
            ValueError: event_types is not a string
            ValueError: event_types is not in [web, git, all]
        """
        if not isinstance(event_types, str):
            raise ValueError(
                "event_types accepts string values only: {} provided.".format(
                    event_types
                )
            )
        if event_types not in ["web", "git", "all"]:
            raise ValueError(
                "event_types not supported. Accepted values are: [web, git, all]. {} provided.".format(
                    event_types
                )
            )
        self._event_types = event_types
        return self._event_types

    def get_enterprise_audit_log(
        self, enterprise=None, page_cursor=None, last_document_id=None, last_count=None
    ):
        """Calls the GHE Audit Log REST API to fetch audit log entries.
        It creates an instance of the AuditLog iterable and passes the
        HTTP response to it.

        If page_cursor is passed, this method will fetch the entries after that
        page_cursor and will make subsequent API calls until has_next_page is False.

        If page_cursor is not passed, this method will fetch ALL the entries until
        has_next_page is False.

        Args:
            enterprise ([str], optional): [description]. Defaults to None.
            page_cursor ([str], optional): [description]. Defaults to None.
            last_document_id ([str], optional): _document_id of the last item fetched. Defaults to None.
            last_count ([int], optional): number of items fetched in the last page. Defaults to None.

        Returns:
            [AuditLog]: AuditLog: Returns an AuditLog instance
        """
        audit_log = AuditLog(enterprise=enterprise)
        while audit_log.has_next_page:
            slug = "/enterprises/{enterprise}/audit-log".replace(
                "{enterprise}", enterprise
            )
            headers = {
                "Accept": "application/vnd.github.v3+json",
                "Content-Type": "application/json",
                "Authorization": "Bearer {}".format(self._access_token),
            }
            params = {
                "phrase": "",
                "include": self._event_types,
                "after": ""
                if page_cursor is None or page_cursor == ""
                else page_cursor,
                "before": "",
                "order": "asc",
                "per_page": "100",
            }
            response = requests.get(
                "{}{}".format(self._api_url, slug), headers=headers, params=params
            )
            # Returns True if status_code is less than 400, False if not.
            if response.ok:
                audit_log.load(response)
                # Check API rate limits
                if audit_log.api_rate_limits["x_rl_remainig"] == 0:
                    raise RuntimeError(
                        "API rate limit reached. Will not be able to fetch data until the rate limit refreshes on: {}".format(
                            audit_log.api_rate_limits["x_rl_reset_timestamp"]
                        )
                    )
                # Stop loading and return results if we exceed the max
                # entries limit
                if audit_log.total >= self._max_entries:
                    self._max_entries_reached = True
                    break
                # Check if there are further pages
                if not audit_log.has_next_page:
                    # This is where we deal with pagination edge cases
                    if last_document_id is not None and last_count is not None:
                        # Case 1: If the number of items on the last page is
                        # equal to the value in our checkpoint and we are on the
                        # same last page as in our checkpoint then we don't have
                        # new data and we need to purge all the entries
                        if (
                            audit_log.last_page["count"] == last_count
                            and last_document_id == audit_log.last_page["_document_id"]
                        ):
                            audit_log = audit_log.empty()
                        # Case 2: If the number of items on the last page is
                        # equal to the value in our checkpoint but we are on a different
                        # last page then we don't need to do anything.
                        elif (
                            audit_log.last_page["count"] == last_count
                            and not last_document_id
                            == audit_log.last_page["_document_id"]
                        ):
                            pass
                        # Case 3: If the number of items on the last page is
                        # greater than the value in our checkpoint and we are on a
                        # different page then we need to truncate the first
                        # N of the items. N being the last_count
                        # in memory - the last count in the checkpoint
                        elif (
                            audit_log.last_page["count"] > last_count
                            and not last_document_id
                            == audit_log.last_page["_document_id"]
                        ):
                            count = audit_log.total - last_count
                            audit_log = audit_log.truncate_from_start(count=count)
                        # Case 4: If the number of items on the last page is
                        # less than the value in our checkpoint then we don't
                        # need to do anything
                        elif audit_log.last_page["count"] < last_count:
                            pass
                    break
                else:
                    page_cursor = audit_log.page_cursor["next"]
            else:
                raise RuntimeError(
                    "Could not fetch audit log data. Please check your configuration, access token scope / correctness and API rate limits. status_code: {} - url: {}".format(
                        response.status_code, response.url
                    )
                )
        return audit_log
