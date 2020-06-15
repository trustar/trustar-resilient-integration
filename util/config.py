# -*- coding: utf-8 -*-

"""Generate a default configuration-file section for trustar_resilient"""

from __future__ import print_function


def config_section_data():
    """Produce the default configuration section for app.config,
       when called by `resilient-circuits config [-c|-u]`
    """
    config_data = u"""
[trustar]

# Name of the message destination.
queue = trustar

# Set the value true if proxy is enabled on the machine where this utility is running.
proxy = false

# Set the below value true if secured proxy is in use.
secure_proxy = false

# URL of proxy server in ip:port format
proxy_url = 

# Username of secure proxy
proxy_username = ^proxy_username_for_trustar 

# Password of secure proxy
proxy_password = ^proxy_password_for_trustar





# This stanza is for the threat source. 
[trustar_threat_source]

# URL of TruSTAR platform.
url = https://api.trustar.co/

# API key of user from TruSTAR platform. Do not change this.
user_api_key = ^api_key_for_trustar_threat_source

# API secret of user from TruSTAR platform. Do not change this.
user_api_secret = ^api_secret_for_trustar_threat_source

# Enclave IDs of user from TruSTAR for searching indicators. Separate values using comma. 
enclave_ids_for_search = 






# User can configure multiple TruStar accounts. Create separate stanza for each account.
# Each account is associated with one or many Resilient workspaces.
# Stanza name should start with trustar_ (e.g trustar_prod)
[trustar_account_n]

# URL of TruSTAR platform.
url = https://api.trustar.co/

# API key of user from TruSTAR platform.
user_api_key = ^api_key_for_[stanza name (for e.g trustar_account_n)]

# API secret of user from TruSTAR platform.
user_api_secret = ^api_secret_for_[stanza name (for e.g trustar_account_n)]

# Enclave IDs of user from TruSTAR for submitting report. Separate values using comma. 
enclave_ids_for_submission = 

# Enclave IDs of user from TruSTAR from querying on TruSTAR. Separate values using comma.
enclave_ids_for_query = 

# Auto Submission parameter. Possible values - enable|disable
auto_submission = disable

# Sections of incident to submit with report to TruSTAR. Possible values -#Summary|Notes|Breach|Artifacts. Separate values using comma.
incident_content_to_submit = summary,notes,breach,artifacts

# Incident Types to exclude for report submission to TruSTAR. Separate values using comma. Values are case sensitive.
incident_types_to_exclude = 

# Workspaces to consider for TruSTAR enrichment. Should not be blank. Enter display names of workspaces.
workspace =  

# TAG to assign to the report submitted to TruSTAR
tag = 
    """
    return config_data
