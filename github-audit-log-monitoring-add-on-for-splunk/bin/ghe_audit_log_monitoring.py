# $SPLUNK_HOME/etc/apps/ghe_audit_log_monitoring/ghe_audit_log_monitoring.py
"""Modular Input for querying GitHub Enterprise for audit log data
"""
from __future__ import absolute_import, print_function
import os
import sys
import time
import logging
import hashlib
import warnings
import requests
import configparser
from io import open

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
# pylint: disable=E0401
# pylint: disable=C0413
from splunklib.modularinput import Script, Scheme, Argument, Event
import splunklib.client as client
from utilities import Utilities
from rest_client import GitHub


class MyScript(Script):
    """All modular inputs should inherit from the abstract base class Script
    from splunklib.modularinput.script.
    They must override the get_scheme and stream_events functions, and,
    if the scheme returned by get_scheme has Scheme.use_external_validation
    set to True, the validate_input function.
    """

    def __init__(self):
        self.session_key = None
        self.input_name = None
        self.input_items = None
        self.hostname = ""
        self.enterprise = ""
        self.personal_access_token = ""
        self.credential_id = ""
        self.ignore_ssc = False
        self.state = None
        self.type = ""
        # Configure  the logger
        self.logger = logging.getLogger()
        self.logging_handler = None

    def load_state(self, enterprise):
        """Loads and parses the file that contains the script's state
        The enterprise is used to create distinct state files as the module
        can be configured for multiple orgs.
        This is necessary to avoid race conditions when reading/writing
        state in the case of a multi-org configuration.
        """
        file_name = "{}_state.conf".format(enterprise)
        config_path = os.path.join(os.path.dirname(__file__), "..", "state/", file_name)
        # If file doesn't exist -> create it
        if not os.path.exists(config_path):
            with open(config_path, "w") as inputs_file:
                inputs_file.write(Utilities.empty_state_file())
        # Read the configuration
        config = configparser.ConfigParser()
        config.read(config_path)
        return config

    def save_state(self, config, enterprise):
        """Saves the provided configuration in the script's state file
        The enterprise is used to create distinct state files as the module
        can be configured for multiple orgs.
        This is necessary to avoid race conditions when reading/writing
        state in the case of a multi-org configuration.
        """
        file_name = "{}_state.conf".format(enterprise)
        config_path = os.path.join(os.path.dirname(__file__), "..", "state/", file_name)
        with open(config_path, "w") as inputs_file:
            return config.write(inputs_file)

    def enable_logger(self):
        """Adds a handler for the logger to enable writing logs to stderr"""
        if self.logging_handler is None:
            self.logger.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(levelname)s %(message)s")
            self.logging_handler = logging.StreamHandler(stream=sys.stderr)
            self.logging_handler.setFormatter(formatter)
            self.logger.addHandler(self.logging_handler)
            # Debug
            logging.debug("enable_logger() enabled!")

    def disable_logger(self):
        """Removes the logger handler if it exists"""
        if self.logging_handler is None:
            self.logger.setLevel(logging.INFO)
            formatter = logging.Formatter("%(levelname)s %(message)s")
            self.logging_handler = logging.StreamHandler(stream=sys.stderr)
            self.logging_handler.setFormatter(formatter)
            self.logger.addHandler(self.logging_handler)
            # Debug
            logging.debug("enable_logger() enabled!")

    # pylint: disable=R0201
    def get_scheme(self):
        """When Splunk starts, it looks for all the modular inputs defined by
        its configuration, and tries to run them with the argument --scheme.
        Splunkd expects the modular inputs to print a description of the
        input in XML on stdout. The modular input framework takes care of all
        the details of formatting XML and printing it. The user need only
        override get_scheme and return a new Scheme object.

        :return: scheme, a Scheme object
        """
        scheme = Scheme("GitHub Enterprise Audit Log Monitoring")
        scheme.description = "GitHub Enterprise Audit Log Monitoring."
        scheme.use_external_validation = True
        scheme.use_single_instance = False
        scheme.add_argument(
            Argument(
                name="hostname",
                title="Hostname",
                description="Hostname or IP of your instance. Make sure "
                "there is no trailing '/'."
                "Example: api.github.com",
                data_type=Argument.data_type_string,
                required_on_create=True,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            Argument(
                name="type",
                title="Account Type",
                description="Account type. Must be either 'organization' or 'enterprise'",
                data_type=Argument.data_type_string,
                required_on_create=True,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            Argument(
                name="enterprise",
                title="Enterprise",
                description="Enterprise name. " "Example: TestEnterprise",
                data_type=Argument.data_type_string,
                required_on_create=True,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            Argument(
                name="personal_access_token",
                title="Personal Access Token",
                description="Personal Access Token of a site administrator. "
                "Example: 83a200d1b9ea26c7363634c3560a60360c72ed02",
                data_type=Argument.data_type_string,
                required_on_create=True,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            Argument(
                name="event_types",
                title="Event Types",
                description="Event types to fetch from the audit log. "
                "accepted values: [web | git | all]",
                data_type=Argument.data_type_string,
                required_on_create=True,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            Argument(
                name="max_entries",
                title="Maximum Entries Per Run",
                description="Maximum number of audit log entries to fetch"
                "in each run.",
                data_type=Argument.data_type_number,
                required_on_create=True,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            Argument(
                name="ignore_ssc",
                title="Verify Self-Signed Certificates",
                description="Set to False if you're using a" "self-signed certificate.",
                data_type=Argument.data_type_boolean,
                required_on_create=True,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            Argument(
                name="debug",
                title="Debug Mode",
                description="If enabled app logs will be dumped into the "
                "splunkd log. WARNING: this will lead to the leaking of the "
                "personal access token into the logs!",
                data_type=Argument.data_type_boolean,
                required_on_create=True,
                required_on_edit=False,
            )
        )
        return scheme

    # pylint: disable=W0613
    def validate_input(self, config):
        """Mock method - not used in this implementation"""
        return

    def encrypt_personal_access_token(
        self, new_credential_id, new_personal_access_token
    ):
        """Encrypts the personal access token and stores it along with the
        credential id in Splunk's storage
        """
        if new_personal_access_token.startswith('ghe_'):
            args = {"token": self.session_key}
            service = client.connect(**args)
            # Debug
            logging.debug(
                "%s ::: encrypt_personal_access_token() personal_access_token: %s",
                self.input_name,
                new_personal_access_token,
            )
            logging.debug(
                "%s ::: encrypt_personal_access_token() credential_id: %s", self.input_name, new_credential_id
            )
            # If the credential already exists, delete it.
            for storage_credential in service.storage_passwords:
                if storage_credential.username == new_credential_id:
                    service.storage_passwords.delete(username=storage_credential.username)
                    break

            # Create the credential.
            cred = service.storage_passwords.create(
                new_personal_access_token, new_credential_id
            )
            logging.debug(
                "%s ::: encrypt_personal_access_token() service.storage_passwords.create(): %s",
                self.input_name,
                cred.content,
            )

    def mask_personal_access_token(self, credential_id):
        """Replaces the personal access token with the credential_id"""
        args = {"token": self.session_key}
        service = client.connect(**args)
        kind, input_name = self.input_name.split("://")
        item = service.inputs.__getitem__((input_name, kind))
        kwargs = {"personal_access_token": credential_id}
        # Store the new credential_id on file
        self.state.set("input", "pat_credential_id", credential_id)
        self.save_state(self.state, self.enterprise)
        # Debug
        logging.debug("mask_personal_access_token() mask_val: %s", kwargs)
        # Update the input field value
        item.update(**kwargs).refresh()

    def get_personal_access_token(self, input_credential_id):
        """credential_id is a unique md5 hash of the hostname and
        personal access token. It acts as an identifier for the PAT in
        Splunk's password storage (kind of like a username).

        The first time this modular input is configured, the PAT is provided.
        In this case we have to create a new credential_id, encrypt and store
        the PAT in Splunk's storage. Then we mask the PAT by replacing it
        with the credential_id in the UI.

        The n time this method is called, it will compare the
        input_credential_id to the value we have stored
        in the state file: credential_id. If the values are the same,
        this means that the PAT was not edited and it's safe to
        fetch the plain_text PAT from Splunk's password storage using the
        credential_id.

        However, if the input_credential_id is different this means that the
        personal_access_token field has been updated with a new value and we
        should consider this to be the new PAT. The new PAT will then be
        encrypted, stored in Splunk's password store and then the value
        in Splunk's UI will be replaced with the credential_id generated for
        this new PAT. The new credential_id will also be stored in the
        state/state.conf file.
        """
        credential_id = self.state["input"]["pat_credential_id"]
        # Debug
        logging.debug(
            "%s ::: get_personal_access_token() credential_id from state: %s", self.input_name, credential_id
        )
        logging.debug(
            "%s ::: get_personal_access_token() input_credential_id: %s", self.input_name, input_credential_id
        )
        if credential_id == input_credential_id:
            logging.debug("%s ::: get_personal_access_token() trying to fetch " "plaintext PAT", self.input_name)
            # credential_id matches the one on file. Meaning no new PAT
            # was provided.
            # We fetch the PAT on record
            args = {"token": self.session_key}
            service = client.connect(**args)
            for storage_credential in service.storage_passwords:
                if storage_credential.username == input_credential_id:
                    # Debug
                    logging.debug(
                        "%s ::: get_personal_access_token() personal_access_token: %s",
                        self.input_name,
                        storage_credential.content.clear_password,
                    )
                    return storage_credential.content.clear_password
            # If we loop through all the credentials and we don't find our
            # PAT - something is wrong.
            raise RuntimeError(
                "No personal access token was found for "
                "the provided credential_id. Fix: provide a new personal "
                "access token or check the app's permissions."
            )
        # If we get here then the PAT has changed.
        # Store the new value and mask the input field value
        new_personal_access_token = input_credential_id
        new_credential_id = hashlib.md5(
            "{}{}".format(self.hostname, new_personal_access_token).encode("utf8")
        ).hexdigest()
        self.encrypt_personal_access_token(new_credential_id, new_personal_access_token)
        self.mask_personal_access_token(new_credential_id)
        return new_personal_access_token

    def stream_events(self, inputs, event_writer):
        """This function handles all the action: splunk calls this modular input
        without arguments, streams XML describing the inputs to stdin, and waits
        for XML on stdout describing events.
        If you set use_single_instance to True on the scheme in get_scheme, it
        will pass all the instances of this input to a single instance of this
        script.
        """
        try:
            self.session_key = self._input_definition.metadata["session_key"]
            if not inputs.inputs:
                # Right after installation, the inputs are not configured yet
                # to avoid an exception in the logs, we skip this
                logging.debug("%s ::: stream_events() skipping...",self.input_name)
                return
            self.input_name, self.input_items = inputs.inputs.popitem()
            # The Argument.data_type_boolean is not actually a boolean it's
            # 0 or 1. Here we transform it to a boolean
            if bool(int(self.input_items["debug"])):
                self.enable_logger()
            else:
                self.disable_logger()
            self.ignore_ssc = bool(int(self.input_items["ignore_ssc"]))
            # Capture account type
            self.type = self.input_items["type"]
            if (self.type.lower()=="organization"):
                self.type="orgs"
            else:
                self.type="enterprises"

            # Capture the enterprise name
            self.enterprise = self.input_items["enterprise"]
            # Capture the maximum number of entries to fetch per run
            self.max_entries = self.input_items["max_entries"]
            # Capture the event types to fetch from the audit log.
            self.event_types = self.input_items["event_types"]
            # This script maintains the state in a config file: state/state.conf
            # everytime we need to process a new event we need to load the
            # latest state
            self.state = self.load_state(self.enterprise)
            # Debug
            logging.debug("%s ::: stream_events() input_name: %s", self.input_name, self.input_name)
            logging.debug("%s ::: stream_events() input_items: %s", self.input_name, self.input_items)
            logging.debug("%s ::: stream_events() config: %s", self.input_name, self.state["input"])
            self.hostname = self.input_items["hostname"]
            # If this is a GHES instance we need to manipulate the hostname
            # to build the appropriate GraphQL endpoint
            # GHES endpoint: https://ghes_hostname/api/graphql
            # GitHub.com endpoint: https://api.github.com
            if (self.hostname!="api.github.com"):
                self.hostname = "{}/api/graphql".format(self.hostname)
            else:
                self.hostname = "api.github.com"
            # The encryption and masking algorithm is encapsulated in this
            # method: self.get_personal_access_token()
            # It will handle PAT changes (if any) and will return a plain text
            # PAT that can be used in API requests.
            self.personal_access_token = self.get_personal_access_token(
                self.input_items["personal_access_token"]
            )
            logging.debug("%s ::: stream_events() hostname: %s", self.input_name, self.hostname)
            logging.debug("%s ::: stream_events() ignore_ssc: %s", self.input_name, self.ignore_ssc)
            # This section contains the logic for fetching the audit log entries.
            #
            # It will make multiple calls to get_enterprise_audit_log() and handle
            # the pagination logic.
            #
            # The output will be an AuditLog which will parse the JSON
            # received from get_enterprise_audit_log() and create an Iterable object.
            #
            # Then we will iterate over the entries of the AuditLog and write
            # each entry as a new event in Splunk.
            #
            # Eventually we will update the state file for the enterprise we
            # have fetched the data for. The state file will be used to fetch
            # only the fresh data in subsequent runs to avoid duplicates.
            github = GitHub(
                api_url=self.hostname,
                access_token=self.personal_access_token,
                max_entries=self.max_entries,
            )
            github.set_event_types(self.event_types)
            logging.debug(
                "{} ::: stream_events(): Loaded page_cursor from state file: {}".format(
                    self.input_name,
                    self.state["input"]["page_cursor"]
                )
            )
            logging.debug(
                "{} ::: stream_events(): Loaded last_document_id from state file: {}".format(
                    self.input_name,
                    self.state["input"]["last_document_id"]
                )
            )
            logging.debug(
                "{} ::: stream_events(): Loaded last_count from state file: {}".format(
                    self.input_name,
                    self.state["input"]["last_count"]
                )
            )
            logging.debug("%s ::: stream_events(): REQUESTING DATA", self.input_name)
            page_cursor = self.state["input"]["page_cursor"]
            last_document_id = self.state["input"]["last_document_id"]
            # last_count needs to be an integer and config_parser doesn't play
            # well with integers
            last_count = (
                int(self.state["input"]["last_count"])
                if not self.state["input"]["last_count"] == ""
                else 0
            )
            audit_log = github.get_enterprise_audit_log(
                type=self.type,
                enterprise=self.enterprise,
                page_cursor=page_cursor,
                last_document_id=last_document_id,
                last_count=last_count,
            )
            logging.debug("%s ::: stream_events(): Pushing data to splunk", self.input_name)
            logging.info("{} ::: stream_events(): Fetched: {} events".format(self.input_name, audit_log.total))
            for entry in audit_log:
                # Prepare the event
                event = Event()
                event.stanza = self.input_name
                event.data = Utilities.splunk_serialize(entry)
                event_writer.write_event(event)
            # Update and save page_cursor value if it exists
            if audit_log.page_cursor["next"] is not None:
                self.state.set("input", "page_cursor", audit_log.page_cursor["next"])
                logging.debug(
                    "{} ::: stream_events(): Updating page_cursor: {}".format(
                        self.input_name,
                        audit_log.page_cursor["next"]
                    )
                )
            else:
                self.state.set(
                    "input",
                    "page_cursor",
                    audit_log.page_cursor["last"]
                    if audit_log.page_cursor["last"] is not None
                    else "",
                )
                logging.debug(
                    "{} ::: stream_events(): Updating page_cursor: {}".format(
                        self.input_name,
                        audit_log.page_cursor["last"]
                    )
                )
            logging.debug(
                "{} ::: stream_events(): Max entries reached: {} with {} entries".format(
                    self.input_name,
                    github.max_entries_reached,
                    audit_log.total,
                )
            )
            logging.info(
                "{} ::: stream_events(): API Rate limits: {}".format(self.input_name, audit_log.api_rate_limits)
            )
            # Update the last document_id and count fetched
            logging.debug(
                "%s ::: stream_events(): Updating last_page: {} - {}".format(
                    audit_log.last_page["_document_id"],
                    str(audit_log.last_page["count"]),
                ), self.input_name
            )
            self.state.set(
                "input", "last_document_id", audit_log.last_page["_document_id"]
            )
            self.state.set("input", "last_count", str(audit_log.last_page["count"]))
            self.save_state(self.state, self.enterprise)
            logging.info("$s ::: stream_events(): SUCCESS", self.input_name)
        # pylint: disable=W0702
        except:
            logging.error("Unexpected error: \n", exc_info=True)


if __name__ == "__main__":
    sys.exit(MyScript().run(sys.argv))
