"""AuditLog class
"""
from __future__ import absolute_import, print_function

try:
    from six.moves.urllib.parse import urlparse, parse_qs
except ImportError:
    from urllib.parse import urlparse, parse_qs

from audit_log_entry import AuditLogEntry


class AuditLog:
    def __init__(self, type=None, enterprise=None, **kwargs):
        self._type = type
        self._enterprise = enterprise
        self._entries = []
        self._total = 0
        self._page_cursor = {"next": None, "prev": None, "first": None, "last": None}
        self._has_next_page = True
        self._index = 0
        self._last_page = {"_document_id": "", "count": 0}
        self._api_rate_limits = {
            "x_rl_limit": 0,
            "x_rl_remainig": 0,
            "x_rl_reset_timestamp": 0,
            "x_rl_used": 0,
        }

    @property
    def total(self):
        return self._total

    @property
    def index(self):
        return self._index

    @property
    def page_cursor(self):
        return self._page_cursor

    @property
    def type(self):
        return self._type

    @property
    def enterprise(self):
        return self._enterprise

    @property
    def has_next_page(self):
        return self._has_next_page

    @property
    def api_rate_limits(self):
        return self._api_rate_limits

    @property
    def last_page(self):
        return self._last_page

    def set_page_cursor(self, links, url=None):
        """Parse the links in the response headers

        Args:
            links (dict): Links response header item

        Returns:
            dict: Dictionary with next, first, prev cursors
        """
        if not links or links is None:
            self._page_cursor = {
                "next": None,
                "prev": None,
                "first": None,
                "last": None,
            }
        else:
            next = (
                parse_qs(urlparse(links["next"]["url"]).query)["after"][0]
                if "next" in links
                else None
            )
            first = (
                parse_qs(urlparse(links["first"]["url"]).query)
                if "first" in links
                else None
            )
            prev = (
                parse_qs(urlparse(links["prev"]["url"]).query)["before"][0]
                if "prev" in links
                else None
            )
            url_query_string = parse_qs(urlparse(url).query) if url is not None else {}
            last = url_query_string["after"][0] if "after" in url_query_string else None
            self._page_cursor = {
                "next": next,
                "first": first,
                "prev": prev,
                "last": last,
            }
        return self._page_cursor

    def set_api_limits(self, response_headers):
        """Parse the rate limits from the headers

        Args:
            response_headers ([dict]): Case-insensitive Dictionary of Response Headers.

        Returns:
            [dict]: Dictionary with the rate limit values
        """
        self._api_rate_limits = {
            "x_rl_limit": response_headers["X-RateLimit-Limit"],
            "x_rl_remainig": response_headers["X-RateLimit-Remaining"],
            "x_rl_reset_timestamp": response_headers["X-RateLimit-Reset"],
            "x_rl_used": response_headers["X-RateLimit-Used"],
        }
        return self._api_rate_limits

    def set_last_page(self, last_document_id=None, last_count=None):
        """Set the last page's meta-data (last document id and number of items
        fetched)

        Args:
            last_document_id ([str], optional): _document_id of the last item fetched. Defaults to None.
            last_count ([int], optional): number of items fetched in the last page. Defaults to None.

        Returns:
            [Dict]: Object containing the last_document_id and last_count
        """
        self._last_page = {"_document_id": last_document_id, "count": last_count}
        return self._last_page

    def empty(self):
        """Empty the entries list and reset the iterator

        Returns:
            [AuditLog]: AuditLog instance
        """
        self._entries = []
        self._total = 0
        return self

    def truncate_from_start(self, count=None):
        """Remove the first N elements

        Args:
            count ([type], optional): [description]. Defaults to None.

        Raises:
            ValueError: [description]

        Returns:
            [type]: [description]
        """
        if count is None:
            raise ValueError("count cannot be undefined. Nothing to purge.")
        self._entries = self._entries[-count:]
        self._total = count
        return self

    def load(self, response):
        """Will load and append audit log entries from the audit log
        API response and update the cursor.

        Args:
            response ([requests.Response]): requests library Response obect

        Raises:
            ValueError: response cannot be None or an empty string

        Returns:
            AuditLog: Returns the current AuditLog instance
        """
        if response is None or response == "":
            raise ValueError("API call response cannot be None or an empty string")
        json = response.json()
        # Set the meta-data first
        self.set_api_limits(response.headers)
        self.set_page_cursor(links=response.links, url=response.url)
        if "next" in self._page_cursor:
            self._has_next_page = self._page_cursor["next"] is not None
        # Otherwise add the entries
        for item in json:
            entry = AuditLogEntry(**item)
            self._entries.append(entry)
        # Number of entries in the last page
        if self._total == 0:
            last_count = len(self._entries) - self._total
        else:
            last_count = len(self._entries)
        if len(self._entries) > 0:
            self.set_last_page(
                last_document_id=self._entries[-1].document_id, last_count=last_count
            )
        self._total = len(self._entries)
        return self

    def __iter__(self):
        """Create the iterator object after parsing the raw JSON response
        from GHE

        Returns:
            AuditLog: Returns the current AuditLog instance
        """
        self._index = 0
        return self

    def __next__(self):
        """Return the next element in the collection

        Raises:
            StopIteration: Stop the iterator from executing forever

        Returns:
            Object: Content of the 'node' element in the entries
        """
        if self._index < self._total:
            result = self._entries[self._index]
            self._index += 1
            return result
        else:
            raise StopIteration

    def next(self):
        """Return the next element in the collection

        This method is needed for python 2.x backward compatibility

        Raises:
            StopIteration: Stop the iterator from executing forever

        Returns:
            Object: Content of the 'node' element in the entries
        """
        if self._index < self._total:
            result = self._entries[self._index]
            self._index += 1
            return result
        else:
            raise StopIteration
