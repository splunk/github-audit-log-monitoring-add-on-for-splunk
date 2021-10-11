[ghe_audit_log_monitoring://<name>]
* Requests audit log information from GitHub Enterprise
interval = <value>
* Interval to collect data

hostname = <value>
* GHE hostname should be api.github.com

type = <value>
* organization or enterprise, defaults to enterprise

enterprise = <value>
* Enterprise name to query the audit log of

personal_access_token = <value>
* GHE personal access token

event_types = <value>
* Event types to fetch from the audit log

max_entries = <value>
* Maximum entries per run

ignore_ssc = <value>
* Ignore SSL certificate validation

debug = <value>
* Boolean to enable/disable debug mode

python.version = <value>
* Python version to run. Can also use python2 for older Splunk versions
