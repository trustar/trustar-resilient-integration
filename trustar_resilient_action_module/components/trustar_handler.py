from __future__ import print_function
from trustar import TruStar, Report
import logging
from circuits.core.handlers import handler
from resilient_circuits import function, FunctionError, FunctionResult
from resilient_circuits.actions_component import ResilientComponent
from trustar.models.indicator import Indicator
import re
import requests
import time
import base64
import json
import validators

LOG = logging.getLogger("trustar_resilient")

CONFIG_DATA_SECTION = "trustar"

FIELD_MAPPING = {
    "id": "ID",
    "name": "Name",
    "description": "Description",
    "phase_id": "Phase",
    "inc_training": "Incident Training",
    "vers": "Version",
    "addr": "Address",
    "city": "City",
    "exposure_type_id": "Exposure Type",
    "incident_type_ids": "Incident Types",
    "reporter": "Reporter",
    "state": "State",
    "country": "Country",
    "zip": "Zip Code",
    "exposure": "Exposure",
    "members": "Members",
    "negative_pr_likely": "Negative PR",
    "task_changes": "Task Changes",
    "data_compromised": "Data Compromised",
    "properties": "Properties",
    "resolution_id": "Resolution",
    "resolution_summary": "Resolution Summary",
    "comments": "Notes",
    "admin_id": "Admin",
    "creator_id": "Creator",
    "crimestatus_id": "Crime Status",
    "employee_involved": "Employee Involved",
    "end_date": "End Date",
    "exposure_dept_id": "Exposure Department",
    "exposure_individual_name": "Exposure Individual Name",
    "exposure_vendor_id": "Exposure Vendor",
    "jurisdiction_name": "Jurisdiction Name",
    "jurisdiction_reg_id": "Jurisdiction Reg ID",
    "start_date": "Start Date",
    "discovered_date": "Incident Start",
    "org_id": "Organization ID",
    "is_scenario": "Is Scenario",
    "hard_liability": "Hard Liability",
    "nist_attack_vectors": "Nist Attack Vectors",
    "inc_start": "Discovered Date",
    "due_date": "Due Date",
    "create_date": "Create Date",
    "owner_id": "Owner",
    "severity_code": "Severity",
    "plan_status": "Plan Status",
    "harmstatus_id": "Harm Status ID",
    "data_encrypted": "Data Encrypted",
    "data_contained": "Data Contained",
    "impact_likely": "Impact Likely",
    "data_source_ids": "Data Source IDs",
    "data_format": "Data Format",
    "gdpr_harm_risk": "Harm Foreseeable",
    "gdpr_lawful_data_processing_categories": "Gdpr Lawful Data Processing Categories",
    "type": "Type",
    "value": "Value",
    "attachment": "Attachment",
    "hits": "Hits",
    "created": "Created",
    "relating": "Relating",
    "pending_sources": "Pending Sources",
    "actions": "Actions",
    "hash": "Hash",
    "text": "Text"
}

TAB_MAPPING = {
    "summary": {
        "name": "Summary",
        "fields": ["id", "description", "phase_id", "severity_code", "create_date", "inc_start", "discovered_date",
                   "data_compromised", "plan_status"]
    },
    "breach": {
        "name": "Personally Identifiable Information",
        "fields": ["gdpr_harm_risk", "exposure", "data_encrypted", "data_source_ids", "data_format"]
    },
    "notes": {
        "name": "Notes",
        "fields": ["id", "text"]
    },
    "artifacts": {
        "name": "Artifacts",
        "fields": ["hits", "created", "value", "type", "id"]
    }
}

MAX = 100


class TruSTARHandler(ResilientComponent):

    def __init__(self, opts):
        super(TruSTARHandler, self).__init__(opts)
        self.options = opts.get(CONFIG_DATA_SECTION, {})
        self.channel = "actions.{}".format(self.options.get('queue', "trustar"))
        self.proxy = self.options.get('proxy', None)
        self.secured_proxy = self.options.get('secure_proxy', None)
        self.proxy_url = self.options.get('proxy_url', None)
        self.proxy_username = self.options.get('proxy_username', None)
        self.proxy_password = self.options.get('proxy_password', None)
        self.url = ""
        self.enclave_ids_to_submit = []
        self.enclave_ids_for_query = []
        self.enclave_ids = []
        self.auto = ""
        self.threat_source = ""
        self.tabs = ""
        self.tag = ""
        self.types = ""
        self.map_data = {
            "EMAIL_ADDRESS": ["Email Sender"],
            "IP": ["IP Address"],
            "MD5": ["Malware MD5 Hash"],
            "SHA1": ["Malware SHA-1 Hash"],
            "SHA256": ["Malware SHA-256 Hash"],
            "URL": ["URL", "URL String", "url_string"],
            "MALWARE": ["Malware Family/Variant"],
            "SOFTWARE": ["File Name"],
            "CVE": ["Threat CVE ID"],
            "CIDR_BLOCK": ["Network CIDR Range"]
        }

    @staticmethod
    def encode_string(data):
        """
        This function will encode string in utf-8 encoding
        :param data: String to encode
        :return: encoded string
        """
        try:
            return unicode.encode(unicode(data), 'utf-8')
        except (NameError, UnicodeDecodeError):
            return data

    def submit_report(self, ts, data, incident_id, incident_name):
        """
        This function will submit report to the TruSTAR platform.
        :param ts: TruSTAR client object.
        :param incident_name: Name of the incident
        :param data: Data to submit.
        :param incident_id: External ID for the report.
        :return: Response Received from the platform.
        """
        try:

            if self.enclave_ids_to_submit:
                report = Report(title="Resilient Incident {}: {}".format(incident_id,
                                                                         self.encode_string(incident_name)), body=data,
                                enclave_ids=str(self.enclave_ids_to_submit).split(","), external_id="RESILIENT{}".
                                format(incident_id))
                response = ts.submit_report(report)
                for enclave_id in str(self.enclave_ids_to_submit).split(","):
                    if self.tag:
                        try:
                            ts.add_enclave_tag(response.id, self.tag, enclave_id, "internal")
                        except Exception as e:
                            LOG.error(e.args[0])
                            break
                    else:
                        LOG.info("TAG name is not configured in config file properly!! Report Submitted without TAG.")
                        break
                return response
            else:
                LOG.error("Enclave ids are not configured properly.")
                return None

        except Exception as e:
            LOG.error(e.args[0])
            return None

    def add_note(self, incident_id, new_note):
        """
        This function will be called to add a new note to an incident.
        :param incident_id: ID of the incident in which note will be added.
        :param new_note: Note to add.
        :return: Nothing.
        """
        try:

            uri = "/incidents/{}/comments".format(incident_id)
            response = self.rest_client().post(uri, new_note)
            LOG.info("Note Added Successfully for incident: {}.".format(incident_id))
            return response

        except Exception as e:
            LOG.error(e.args[0])
            return None

    def get_artifact_type_name(self, type_id):
        """
        This function will return name of artifact type of resilient.
        :param type_id: ID of artifact type
        :return: Name of artifact type.
        """
        try:

            url = "/artifact_types/{}".format(type_id)
            data = self.rest_client().get(url)
            return data['name']

        except Exception as e:
            LOG.error(e.args[0])
            return None

    def build_report_body(self, report_body, incident_data, fields):
        """
        This function will format data to add with report.
        :param report_body: Content of report body.
        :param incident_data: Data to format.
        :param fields: Fields that will be added as data.
        :return: String.
        """
        try:

            # Regex for removing tags from values.
            p = re.compile(r'<.*?>')

            for field in fields:

                if field == "phase_id":
                    phase = (self.rest_client().get("/phases/{}".format(incident_data['phase_id'])))['name']
                    report_body += "\n\tPhase: {}".format(p.sub(" ", self.encode_string(phase)))\
                        .replace("&nbsp;", " ")

                elif field == "severity_code":
                    url_for_severity = "/types/incident/fields/severity_code"
                    severity_codes = (self.rest_client().get(url_for_severity))['values']
                    severity = ""

                    for code in severity_codes:
                        if code['value'] == incident_data["severity_code"]:
                            severity = code['label']
                    report_body += "\n\tSeverity: {}".format(self.encode_string(severity))\
                        .replace("&nbsp;", " ")

                elif field == "resolution_id":
                    url_for_resolution = "/types/incident/fields/resolution_id"
                    resolution_ids = (self.rest_client().get(url_for_resolution))['values']
                    resolution = ""

                    for code in resolution_ids:
                        if code['value'] == incident_data["resolution_id"]:
                            resolution = code['label']
                    report_body += "\n\tResolution: {}".format(self.encode_string(resolution))\
                        .replace("&nbsp;", " ")

                elif field == "plan_status":
                    plan = "Active" if incident_data['plan_status'] == "A" else "Closed"
                    report_body += "\n\tStatus: {}".format(self.encode_string(plan))\
                        .replace("&nbsp;", " ")

                elif field == "inc_start" or field == "discovered_date" or field == "create_date":

                    if incident_data[field] is not None:
                        new_value = time.strftime('%m/%d/%Y %H:%M:%S', time.gmtime(incident_data[field] / 1000.))
                        report_body += "\n\t{}: {}".format(FIELD_MAPPING[field], new_value)
                    else:
                        report_body += "\n\t{}: {}".format(FIELD_MAPPING[field], incident_data[field])

                elif field == "hits":
                    hits = incident_data['hits']
                    report_body += "\n\t{}:".format(FIELD_MAPPING[field])

                    if hits:
                        for k, hit in enumerate(hits):
                            report_body += "\n\t\tHit {}: {}".format(k+1,
                                                                     self.encode_string(json.dumps(hit['properties'])))

                else:
                    try:
                        report_body += "\n\t{}: {}".format(FIELD_MAPPING[field], p.sub(" ",
                                                                                       self.encode_string(
                                                                                           incident_data[field]))). \
                            replace("&nbsp;", " ")
                    except TypeError:
                        report_body += "\n\t{}: {}".format(FIELD_MAPPING[field], p.sub(" ",
                                                                                       self.encode_string(
                                                                                           str(incident_data[field]))))\
                            .replace("&nbsp;", " ")
            return report_body

        except Exception as e:
            LOG.error(e.args[0])
            return None

    def get_incident_data(self, incident_id):
        """
        This function will fetch incident data from resilient platform using ID.
        :param incident_id: ID of the incident.
        :return: Incident data.
        """
        try:

            url = "/incidents/{}".format(incident_id)
            url_for_artifacts = "{}/artifacts".format(url)
            artifacts = self.rest_client().get(url_for_artifacts)
            LOG.info("Preparing incident data to submit.")
            list_of_tabs = str(self.tabs).lower().split(",")
            if '' in list_of_tabs:
                list_of_tabs.remove('')
            incident_data = self.rest_client().get(url)
            report_body = "Resilient Incident {}: {}\n\n".format(incident_id,
                                                                 self.encode_string(incident_data['name']))

            # Filtering notes in case of active incident.
            if incident_data['plan_status'] == "A" and "notes" in list_of_tabs:
                list_of_tabs.remove("notes")

            if list_of_tabs:

                for tab in list_of_tabs:
                    if tab in TAB_MAPPING.keys():
                        name = TAB_MAPPING[tab]['name']
                        report_body += name

                        # Adding Resolution and Resolution summary in case of closed incident.
                        if tab == "summary" and incident_data['plan_status'] == "C":
                            fields = TAB_MAPPING[tab]['fields'].__add__(['resolution_id', 'resolution_summary'])
                        else:
                            fields = TAB_MAPPING[tab]['fields']

                        if tab == "artifacts":

                            count = 1
                            for k, artifact in enumerate(artifacts):

                                if artifact['description'] != "TruSTAR Correlated Indicator":
                                    artifact['type'] = self.get_artifact_type_name(artifact['type'])
                                    report_body += "\n\n\tArtifact {}".format(count)
                                    count += 1
                                    report_body = self.build_report_body(report_body, artifact, fields)

                                    if report_body is None:
                                        return None

                            report_body += "\n\n"

                        elif tab == "notes":
                            url_for_note = "{}/comments".format(url)
                            notes_data = self.rest_client().get(url_for_note)
                            count = 1

                            for k, note in enumerate(notes_data):

                                if not note['text'].__contains__("TruSTAR Enrichment"):
                                    try:
                                        import html
                                        note_data = {
                                            "id": note['id'],
                                            "text": html.unescape(self.encode_string(note['text']))
                                        }
                                    except AttributeError:
                                        import HTMLParser
                                        h = HTMLParser.HTMLParser()
                                        try:
                                            note_data = {
                                                "id": note['id'],
                                                "text": h.unescape(note['text']).encode('latin1').decode('utf8')
                                            }
                                        except (UnicodeDecodeError, UnicodeEncodeError):
                                            note_data = {
                                                "id": note['id'],
                                                "text": self.encode_string(note['text'])
                                            }
                                    report_body += "\n\n\tNote {}".format(count)
                                    count += 1
                                    report_body = self.build_report_body(report_body, note_data, fields)

                                    if report_body is None:
                                        return None

                            report_body += "\n\n"

                        elif tab == "breach":
                            report_body = self.build_report_body(report_body, incident_data['pii'], fields)

                            if report_body is not None:
                                report_body += "\n\n"
                            else:
                                return None

                        else:
                            report_body = self.build_report_body(report_body, incident_data, fields)

                            if report_body is not None:
                                report_body += "\n\n"
                            else:
                                return None

                    else:
                        LOG.error("Entered list of tabs to submit to trustar is invalid!! Please enter valid tabs in"
                                  " config file!!")
                        return None

            else:
                return report_body

            LOG.info("Incident data is prepared")
            return report_body

        except Exception as e:
            LOG.error(e.args[0])
            return None

    def get_artifact_type(self, artifact_name):
        """
        This function will map incident type of trustar with resilient artifact type.
        :param artifact_name: Name of artifact to search.
        :return: Artifact Type Name
        """
        try:

            url = "/artifact_types"

            if artifact_name in self.map_data.keys():

                return self.map_data[artifact_name][0]

            else:

                artifact_types = self.rest_client().get(url)

                for entity in artifact_types['entities']:

                    if entity['name'] == "TruSTAR {}".format(artifact_name):
                        self.map_data.update({artifact_name: [entity['name']]})
                        return entity['name']

                new_artifact_type = {
                    "use_for_relationships": True,
                    "enabled": True,
                    "file": False,
                    "multi_aware": False,
                    "name": "TruSTAR {}".format(artifact_name),
                    "programmatic_name": "trustar_{}".format(artifact_name.lower()),
                    "desc": "TruSTAR Indicator Type."
                }
                data = self.rest_client().post(url, new_artifact_type)
                self.map_data.update({artifact_name: [data['name']]})
                return data['name']

        except Exception as e:
            LOG.error(e.args[0])
            return None

    def update_report(self, ts, report_id, data, incident_id, incident_name):
        """
        This function will update report on trustar platform.
        :param incident_name: incident ID
        :param incident_id: incident name
        :param ts: TruSTAR object.
        :param report_id: Report ID
        :param data: Data to update.
        :return: None
        """
        try:

            report = ts.get_report_details(str(report_id))
            report.body = data
            report.title = "Resilient Incident {}: {}".format(incident_id, self.encode_string(incident_name))
            report.enclave_ids = str(self.enclave_ids_to_submit).split(",")
            res = ts.update_report(report)
            LOG.info("Report Updated Successfully.")
            return res

        except Exception as e:
            LOG.error(e.args[0])
            return None

    def check_existing_artifacts(self, incident_id, artifact_value):
        """
        This function will check the existence of artifact in incident.
        :param incident_id: Incident ID
        :param artifact_value: Value of artifact to search.
        :return: True if found else False
        """
        try:

            url = "/incidents/{}/artifacts".format(incident_id)
            artifacts = self.rest_client().get(url)

            for artifact in artifacts:
                if self.encode_string(artifact['value']) == self.encode_string(artifact_value):
                    return False
                else:
                    continue
            return True

        except Exception as e:
            LOG.error(e.args[0])
            return None

    def get_artifact_type_id(self, artifact_name):
        """
        This function will get artifact type id.
        :param artifact_name:
        :return: Artifact type id
        """
        try:

            url_for_artifacts = "/artifact_types"
            artifact_types = self.rest_client().get(url_for_artifacts)
            flag = False
            for arti_type in artifact_types['entities']:

                if arti_type['name'] == artifact_name:
                    return arti_type['id']
                else:
                    continue

            if not flag:
                LOG.error("Artifact type not found!!")
                return None

        except Exception as e:
            LOG.error(e.args[0])
            return None

    def add_artifact_from_indicator(self, ts, event, extracted_indicators, incident_name, incident_id):
        """
        This function will add indicator as artifact in incident.
        :param ts: TruSTAR object.
        :param event: Event data received from resilient.
        :param extracted_indicators:
        :param incident_name:
        :param incident_id:
        :return:
        """
        try:

            if extracted_indicators:
                LOG.info("Getting Correlated Indicators.")

                if self.enclave_ids_for_query:
                    trustar_corr_indicators = ts.get_related_indicators(extracted_indicators, (str(
                        self.enclave_ids_for_query)).split(","))
                elif self.enclave_ids_to_submit:
                    trustar_corr_indicators = ts.get_related_indicators(extracted_indicators, str(
                        self.enclave_ids_to_submit).split(","))
                else:
                    LOG.error("Enter proper values of enclave ids in config file!!")
                    return None

                LOG.info("Correlated Data received successfully.")
                corelated_indicators = []
                url = "/incidents/{}/artifacts".format(incident_id)

                for indicator in trustar_corr_indicators:

                    if corelated_indicators.__len__() < MAX:
                        artifact_value = self.encode_string(indicator.value)
                        artifact_type = self.get_artifact_type(indicator.type)

                        if artifact_type:

                            if artifact_type == "URL" and not validators.url(artifact_value):
                                artifact_type = "URL String"

                            artifact_type = self.get_artifact_type_id(artifact_type)

                            if self.check_existing_artifacts(incident_id, artifact_value):

                                new_artifact = {
                                    "type": artifact_type,
                                    "value": self.encode_string(artifact_value),
                                    "description": "TruSTAR Correlated Indicator",
                                    "properties": [],
                                    "whois": {
                                        "raw": None,
                                        "pending": None
                                    },
                                    "pending_sources": []
                                }
                                try:

                                    self.rest_client().post(url, new_artifact)

                                except Exception as e:
                                    if e.args[0].__contains__("The specified URL is invalid"):
                                        artifact_type = self.get_artifact_type_id("URL String")
                                        new_artifact = {
                                            "type": artifact_type,
                                            "value": self.encode_string(artifact_value),
                                            "description": "TruSTAR Correlated Indicator",
                                            "properties": [],
                                            "whois": {
                                                "raw": None,
                                                "pending": None
                                            },
                                            "pending_sources": []
                                        }
                                        self.rest_client().post(url, new_artifact)

                                LOG.info("New Artifact Added Successfully.")
                                corelated_indicators.append(indicator)
                            else:
                                continue

                        else:
                            return None

                    else:
                        break

                if corelated_indicators:
                    LOG.info("Adding Correlated Indicators as Note in Incident.")
                    data = "<h3>TruSTAR Enrichment</h3><h4>Indicators</h4>"

                    for indicator in corelated_indicators:
                        try:
                            url = base64.b64encode(
                                "{}%7C{}".format(indicator.type, self.encode_string(indicator.value)))
                        except TypeError:
                            url = base64.b64encode(b''+bytes(indicator.type, 'utf-8') + b"%7C" + b''+bytes(
                                indicator.value, 'utf-8'))
                        url_indicator = "{}/constellation/reports/{}".format(self.url, url)
                        data += "\n\t<b>{}: </b><a href=\"{}\">{}</a>".format(indicator.type, url_indicator,
                                                                              self.encode_string(indicator.value))
                    new_note = {
                        "user_id": {
                            "id": {},
                            "name": event.message['incident']['creator']['fname'] + " " + event.message['incident']
                            ['creator']['lname']
                        },
                        "inc_id": incident_id,
                        "inc_name": incident_name,
                        "text": {"format": "html",
                                 "content": data}
                    }
                    note = self.add_note(incident_id, new_note)

                    if note is not None:
                        LOG.info("Correlated indicators added as note in the incident successfully.")
                        return note
                    else:
                        return None

            else:
                LOG.info("No extracted indicators found!!")
                return "Complete"

        except Exception as e:
            LOG.error(e.args[0])
            return None

    def get_indicators_data(self, ts, event):
        """
        This function will fetch extracted indicators from the trustar report.
        :param ts: TruSTAR object.
        :param event: Data received from platform.
        :return: None
        """
        try:

            incident_id = event.message['incident']['id']
            incident_name = event.message['incident']['name']
            report_id = ((ts.get_report_details("RESILIENT{}".format(incident_id), "external")).to_dict())['id']

            # Filtering indicators in case of active incident.
            if event.message['incident']['plan_status'] != "C":
                LOG.info("Fetching Extracted Indicators from TruSTAR.")
                extracted_indicator = ts.get_indicators_for_report(report_id)
                extracted_indicators = [data.value for data in extracted_indicator]
                LOG.info("Received Extracted Indicators successfully!!")
                res = self.add_artifact_from_indicator(ts, event, extracted_indicators, incident_name, incident_id)
                return res
            else:
                return "Incident is closed"

        except Exception as e:
            LOG.error(e.args[0])
            return None

    def get_workspace_name(self, workspace_id):
        """
        This function will fetch workspace name from resilient platform.
        :param workspace_id: ID of the workspace
        :return: Name of the workspace
        """
        try:

            url = "/workspaces/{}".format(workspace_id)
            workspace = self.rest_client().get(url)
            return workspace['display_name']

        except Exception as e:
            LOG.error(e.args[0])
            return None

    @staticmethod
    def get_proxy_data(proxy_url, secured_proxy, proxy_username, proxy_password):
        """
        This function will fetch proxy related data from config file.
        :param proxy_url: URL of proxy
        :param secured_proxy: Flag to check if proxy is secured or not.
        :param proxy_username: Username of proxy if secured proxy is in use.
        :param proxy_password: Password of proxy if secured proxy is in use.
        :return: Dict
        """
        proxy_data = {}

        if proxy_url:
            url = proxy_url

            if str(url).startswith("http://"):
                url = str(url).split("http://")[1]
            elif str(url).startswith("https://"):
                url = str(url).split("https://")[1]

            if str(url).endswith("/"):
                url = str(url)[:-1]

            # Checking if secured proxy is in use. If true adding credentials with proxy url.
            if secured_proxy.lower() == "true":

                if proxy_username and proxy_password:
                    username = proxy_username
                    password = proxy_password
                    proxy_data['https_proxy'] = "https://{}:{}@{}".format(username, password, url)
                    proxy_data['http_proxy'] = "http://{}:{}@{}".format(username, password, url)
                else:
                    LOG.error("Enter proper proxy credentials in config file.")
                    return None

            else:
                proxy_data['https_proxy'] = "https://{}".format(url)
                proxy_data['http_proxy'] = "http://{}".format(url)

        else:
            LOG.error("Enter proper value of proxy url in config file.")
            return None

        return proxy_data

    def get_ts(self, workspace_name):
        """
        This function will create object for communication with TruSTAR.
        :param workspace_name: Name of the workspace for which object will be fetched.
        :return: TruSTAR communication object
        """
        try:
            workspace_name = self.get_workspace_name(workspace_name)

            if workspace_name:
                all_sections = self.opts.keys()
                trustar_sections = [x for x in all_sections if str(x).startswith("trustar")]

                for section in trustar_sections:

                    # Check for workspace parameter in stanza.
                    if 'workspace' in dict(self.opts.get(section)).keys():
                        options = self.opts.get(section, "")
                        ws_name_list = str(options.get('workspace')).split(",")
                        for workspace in ws_name_list:
                            workspace.strip()

                        if str(workspace_name) in ws_name_list:
                            user_api_key = options.get("user_api_key", None)
                            if not user_api_key:
                                LOG.info("Please enter value for API KEY of TruSTAR by running \"res-keyring\" command")
                                return None
                            user_api_secret = options.get("user_api_secret", None)
                            if not user_api_secret:
                                LOG.info("Please enter value for API SECRET of TruSTAR by running \"res-keyring\""
                                         " command")
                                return None
                            self.enclave_ids = options.get('enclave_ids', "")
                            self.enclave_ids_for_query = options.get('enclave_ids_for_query', [])
                            self.enclave_ids_to_submit = options.get('enclave_ids_for_submission', [])
                            self.tabs = options.get('incident_content_to_submit', [])
                            self.types = options.get('incident_types_to_exclude', [])
                            self.auto = options.get('auto_submission', 'disable')
                            self.url = options.get('url', '')
                            self.tag = options.get('tag', '')

                            if str(self.url).endswith('/'):
                                self.url = str(self.url)[:-1]
                            auth_endpoint = self.url + "/oauth/token"
                            api_endpoint = self.url + "/api/1.3"
                            conf_for_trustar = {
                                "auth_endpoint": auth_endpoint,
                                "api_endpoint": api_endpoint,
                                "user_api_key": user_api_key,
                                "user_api_secret": user_api_secret,
                                "enclave_ids": self.enclave_ids_to_submit.split(","),
                                "client_type": "Python_SDK",
                                "client_version": "1.3",
                                "client_metatag": "Resilient"
                            }

                            if self.proxy.lower() == "true":
                                proxy_data = self.get_proxy_data(self.proxy_url, self.secured_proxy,
                                                                 self.proxy_username, self.proxy_password)
                            else:
                                proxy_data = "Not In Use"

                            if isinstance(proxy_data, dict):
                                conf_for_trustar['http_proxy'] = proxy_data['http_proxy']
                                conf_for_trustar['https_proxy'] = proxy_data['https_proxy']
                            elif proxy_data is None:
                                return None

                            ts = TruStar(config=conf_for_trustar)

                            try:

                                # Check connectivity with TruSTAR client object.
                                ts.ping()
                                return ts

                            except Exception as e:
                                LOG.error(e.args[0])
                                return None

                        else:
                            continue

                    else:
                        continue

            else:
                return None
            LOG.error("TruSTAR enrichment is not possible for this workspace!! Please add the workspace display name in"
                      " one of the config section.")
            return None

        except Exception as e:
            LOG.error(e.args[0])
            return None

    def create_report(self, ts, event, flag):
        """
        This function will create needed data to submit to TruSTAR.
        :param ts: TruSTAR object.
        :param event: Data received from platform.
        :param flag: To check if this function is called from Workflow function or Action Module.
        :return: None
        """
        try:

            LOG.info("Report Submission for newly created Incident is Started.")
            incident = event.message['incident']
            incident_id = incident['id']
            incident_name = incident['name']
            incident = self.get_incident_data(incident_id)

            if incident:
                LOG.info("Incident data received")
                response = self.submit_report(ts, incident, incident_id, incident_name)

                if response:
                    LOG.info("Report Submitted Successfully")
                    url = self.url + "/constellation/reports/{}".format(response.id)
                    new_note = {
                        "user_id": {
                            "id": {},
                            "name": event.message['incident']['creator']['fname'] + " " + event.message['incident']
                            ['creator']['lname']
                        },
                        "inc_id": incident_id,
                        "inc_name": incident_name,
                        "text": {"format": "html",
                                 "content": "<div><h3>TruSTAR Enrichment</h3><b>TruSTAR Report Submitted Successfully.\
                                     </b><br /><a href={}>{}</a></div>".format(url, url)}
                    }
                    note = self.add_note(incident_id, new_note)

                    if note:
                        LOG.info("Note with deeplink created successfully.")

                        if flag:
                            res = self.get_indicators_data(ts, event)

                            if res:
                                return response
                            else:
                                return None

                        else:
                            return response

        except Exception as e:
            LOG.error(e.args[0])
            return None

    @handler("casecreated")
    def incident_creation(self, event, *args, **kwargs):
        """
        This handler will be executed whenever a new incident is added on resilient platform.
        :param event: Data received from the platform.
        :param args: Arguments received from resilient platform
        :param kwargs: Arguments received from resilient platform
        :return: Yield Status to platform
        """
        try:

            workspace = event.message['incident']['workspace']
            ts = self.get_ts(workspace)

            if ts is not None:

                if self.auto == "enable":
                    url_for_type = "/types/incident/fields/incident_type_ids"
                    types = self.rest_client().get(url_for_type)
                    incident_types = types['values']
                    types_to_exclude = [i_type['value'] for i_type in incident_types if
                                        self.types.__contains__(i_type['label'])]
                    flag = True

                    for i_type in types_to_exclude:

                        if i_type in event.message['incident']['incident_type_ids']:
                            LOG.error("This type of incident can't be submitted to TruSTAR")
                            flag = False
                            break

                    if flag:
                        LOG.info("Submit Report Started.")
                        response = self.create_report(ts, event, True)

                        if response:
                            status = "Task Completed Successfully"
                        else:
                            status = "Task wasn't completed!!"
                        yield status

                    else:
                        yield "Task wasn't completed!!"

                else:
                    LOG.info(
                        "Auto Submission is disabled. Perform Send To TruSTAR to submit report on TruSTAR platform.")
                    status = "Task wasn't completed!!"
                    yield status

            else:
                yield "Task wasn't completed!!"

        except Exception as e:
            LOG.error(e.args[0])
            yield "Task wasn't completed"

    @handler("send_to_trustar")
    def get_reports(self, event, *args, **kwargs):
        """
        This function will be executed when Get Reports menu item rule will be triggered. This will then fetch report
        from the trustar and the response will be added as note in incident.
        :param event: Data Received from the platform.
        :param args: Arguments received from resilient platform
        :param kwargs: Arguments received from resilient platform
        :return: Yield status to platform.
        """
        try:

            workspace_name = event.message['incident']['workspace']
            ts = self.get_ts(workspace_name)

            if ts:
                report = ts.get_report_details("RESILIENT{}".format(event.message['incident']['id']), "external")
                LOG.info("Report Update Started!!")
                data = self.get_incident_data(event.message['incident']['id'])

                if data:
                    response = self.update_report(ts, report.id, data, event.message['incident']['id'],
                                                  event.message['incident']['name'])

                    if response:
                        res = self.get_indicators_data(ts, event)

                        if res:
                            yield "Task Completed Successfully!!"
                        else:
                            yield "Task wasn't completed!!"

                    else:
                        yield "Task wasn't completed!!"

                else:
                    yield "Task wasn't completed!!"

            else:
                yield "Task wasn't completed!!"

        except requests.HTTPError as e:
            if e.response.status_code == 404:
                workspace = event.message['incident']['workspace']
                ts = self.get_ts(workspace)

                if ts:
                    url_for_type = "/types/incident/fields/incident_type_ids"
                    types = self.rest_client().get(url_for_type)
                    incident_types = types['values']
                    types_to_exclude = [i_type['value'] for i_type in incident_types if i_type['label'] in self.types]
                    flag = True

                    for i_type in types_to_exclude:

                        if i_type in event.message['incident']['incident_type_ids']:
                            LOG.error("This type of incident can't be submitted to TruSTAR")
                            flag = False
                            break

                    if flag:
                        LOG.info("Submit Report Started.")
                        response = self.create_report(ts, event, True)

                        if response:
                            status = "Task Completed Successfully"
                        else:
                            status = "Task wasn't completed!!"
                        yield status

                    else:
                        yield "Task wasn't completed!!"

                else:
                    yield "Task wasn't completed!!"

        except Exception as e:
            LOG.error(e.args[0])
            yield "Task wasn't completed"

    @handler("updateincident", "artifactcreated")
    def update_incident(self, event, *args, **kwargs):
        """
        This function will check if the report exists on trustar for incident and if exists then update that.
        :param event: Data received form platform.
        :param args: Arguments received from resilient platform
        :param kwargs: Arguments received from resilient platform
        :return: Yield status to platform.
        """
        try:

            status = ""
            incident = event.message['incident']
            incident_id = incident['id']
            workspace = event.message['incident']['workspace']
            ts = self.get_ts(workspace)

            if ts:

                if self.auto == "enable":
                    report_id = ((ts.get_report_details("RESILIENT{}".format(incident_id), 'external')).to_dict())[
                        'id']
                    LOG.info("Report update is Started.")
                    incident = self.get_incident_data(incident_id)

                    if incident:
                        res = self.update_report(ts, report_id, incident, incident_id,
                                                 event.message['incident']['name'])

                        if res:
                            response = self.get_indicators_data(ts, event)

                            if response:
                                status = "Task completed successfully."
                            else:
                                status = "Task wasn't completed!!"

                        else:
                            status = "Task wasn't completed!!"
                        yield status

                else:
                    LOG.info("Auto Submission disabled. Perform Send To TruSTAR to update report in TruSTAR.")
                    status = "Task wasn't completed!!"
                yield status

            else:
                yield "Task wasn't completed!!"

        except Exception as e:
            LOG.error(e.args[0])
            yield "Task wasn't completed"

    @handler("whitelist_in_trustar")
    def whitelist_in_trustar(self, event, *args, **kwargs):
        """
        This function will whitelist artifact in trustar and this will be executed when Whitelist in trustar menu item
        rule will be triggered.
        :param event: Data received from platform
        :param args: Arguments received from resilient platform
        :param kwargs: Arguments received from resilient platform
        :return: Status to platform.
        """
        try:

            LOG.info("Whitelisting artifact in TruSTAR.")
            artifact_value = event.message['artifact']['value']
            artifact_value = self.encode_string(artifact_value)
            workspace_name = event.message['incident']['workspace']
            ts = self.get_ts(workspace_name)
            flag = True

            if ts:

                response = ts.add_terms_to_whitelist([artifact_value])

                for indicator in response:

                    if self.encode_string(indicator.value) == self.encode_string(artifact_value):
                        flag = False

                        if indicator.type not in self.map_data.keys():
                            self.map_data[indicator.type] = [event.message['artifact']['type']]
                        else:

                            if not event.message['artifact']['type'] in self.map_data[indicator.type]:
                                i_type = self.get_artifact_type_name(event.message['artifact']['type'])
                                self.map_data[indicator.type].extend([i_type])

                if not flag:
                    LOG.info("Artifact whitelisted in TruSTAR successfully")
                else:
                    LOG.info("Artifact: {} wasn't whitelisted in TruSTAR".format(artifact_value))
                status = "Task Completed Successfully"
                yield status

            else:
                yield "Task wasn't completed!!"

        except Exception as e:
            LOG.error(e.args[0])
            yield "Task wasn't completed"

    @handler("undo_whitelist_in_trustar")
    def undo_whitelist(self, event, *args, **kwargs):
        """
        This function will remove artifact from whitelist in trustar.
        :param event: Data received from platform.
        :param args: Arguments received from resilient platform
        :param kwargs: Arguments received from resilient platform
        :return: Yield status to platform.
        """
        try:

            LOG.info("Undo whitelist artifact in TruSTAR started.")
            artifact_type = event.message['artifact']['type']
            artifact_value = event.message['artifact']['value']
            artifact_value = self.encode_string(artifact_value)
            name = self.get_artifact_type_name(artifact_type)
            i_type = ""

            for field in self.map_data:

                if name in self.map_data[field]:
                    i_type = field

            indicator = {
                "indicatorType": i_type,
                "value": artifact_value
            }
            workspace_name = event.message['incident']['workspace']
            ts = self.get_ts(workspace_name)

            if ts:
                ts.delete_indicator_from_whitelist(Indicator.from_dict(indicator))
                LOG.info("Artifact removed from whitelist successfully.")
                status = "Task Completed Successfully"
                yield status

            else:
                yield "Task wasn't completed!!"

        except Exception as e:
            LOG.error(e.args[0])
            yield "Task wasn't completed!!"

    @handler("incident_deleted")
    def delete_incident(self, event, *args, **kwargs):
        """
        This handler will delete report from trustar whenever the incident is deleted from resilient.
        :param event: Data received from platform
        :param args: Arguments received from resilient platform
        :param kwargs: Arguments received from resilient platform
        :return:
        """
        try:

            if self.auto == "enable":
                LOG.info("Deleting report from TruSTAR.")
                incident_id = event.message['incident']['id']
                workspace_name = event.message['incident']['workspace']
                ts = self.get_ts(workspace_name)

                if ts:
                    try:

                        report = ts.get_report_details("RESILIENT{}".format(incident_id), "external")
                        ts.delete_report(report.id)
                        LOG.info("Report Deleted Successfully.")
                        status = "Task Completed Successfully"
                        yield status

                    except requests.HTTPError as e:
                        if e.response.status_code == 404:
                            LOG.error("Report not found for incident: {}".format(incident_id))

                else:
                    yield "Task wasn't completed!!"

            else:
                LOG.info(
                    "Auto Submission disabled. Delete report for this incident manually on TruSTAR platform.")
                status = "Task Completed Unsuccessfully"
                yield status

        except Exception as e:
            LOG.error(e.args[0])
            yield "Task wasn't completed"

    @function("submit_report_to_trustar")
    def submit_report_to_trustar(self, event, *args, **kwargs):
        """
        This is a workflow function handler which will submit incident as a report in trustar.
        :param event: Data received from platform
        :param args: Arguments received from resilient platform
        :param kwargs: Arguments received from resilient platform
        :return: Report in json format as function result.
        """

        if kwargs.get('trustar_incident_id', None):

            try:

                url = "/incidents/{}".format(kwargs.get('trustar_incident_id', ''))
                event.message['incident'] = self.rest_client().get(url)
                workspace_name = event.message['incident']['workspace']
                ts = self.get_ts(workspace_name)

                if ts:
                    incident_id = kwargs.get('trustar_incident_id', "")
                    report = ts.get_report_details("RESILIENT{}".format(incident_id), "external")
                    LOG.info("Report Update Started!!")
                    data = self.get_incident_data(incident_id)

                    if data:
                        res = self.update_report(ts, report.id, data, incident_id, event.message['incident']['name'])

                        if res:
                            res = res.to_dict()
                            yield FunctionResult(res)

                        else:
                            yield FunctionResult({'error': "Please check logs!!"})

                    else:
                        yield FunctionResult({'error': "Please check logs!!"})

                else:
                    yield FunctionResult({'error': "Please check logs!!"})

            except requests.HTTPError as e:
                event.message['incident'] = (self.rest_client().get("/incidents/{}".format(
                    kwargs.get('trustar_incident_id'))))

                if e.response.status_code == 404:
                    workspace = event.message['incident']['workspace']
                    ts = self.get_ts(workspace)

                    if ts:
                        url_for_type = "/types/incident/fields/incident_type_ids"
                        types = self.rest_client().get(url_for_type)
                        incident_types = types['values']
                        types_to_exclude = [i_type['value'] for i_type in incident_types if i_type['label'] in
                                            self.types]
                        flag = True

                        for i_type in types_to_exclude:

                            if i_type in event.message['incident']['incident_type_ids']:
                                LOG.error("This type of incident can't be submitted to TruSTAR")
                                flag = False
                                break

                        if flag:
                            LOG.info("Submit Report Started.")
                            res = self.create_report(ts, event, False)

                            if res:
                                res = res.to_dict()
                                yield FunctionResult(res)
                            else:
                                yield FunctionResult(res)

                        else:
                            yield FunctionResult({'error': "Please check logs!!"})

                    else:
                        yield FunctionResult({'error': "Please check logs!!"})

            except Exception as e:
                LOG.error(e.args[0])
                yield FunctionResult({'error': e.args[0]})

        else:
            LOG.error("Please provide proper inputs to the function \"Submit Report to TruSTAR\"!!")
            yield FunctionResult({'error': "Please provide proper inputs to the function \"Submit Report to"
                                           " TruSTAR\"!!"})

    @function("delete_report_in_trustar")
    def delete_report(self, event, *args, **kwargs):
        """
        This is a workflow function handler which will delete report from trustar.
        :param event: Data received from platform.
        :param args: Arguments received from resilient platform
        :param kwargs: Arguments received from resilient platform
        :return: status as function result.
        """
        if kwargs.get('trustar_incident_id', None):

            try:
                incident_id = kwargs.get('trustar_incident_id', "")
                url = "/incidents/{}".format(kwargs.get('trustar_incident_id', ''))
                event.message['incident'] = self.rest_client().get(url)
                workspace_name = event.message['incident']['workspace']
                ts = self.get_ts(workspace_name)

                if ts:
                    LOG.info("Report deletion is started!")

                    try:
                        report = ts.get_report_details("RESILIENT{}".format(incident_id), "external")
                        ts.delete_report(report.id)
                        LOG.info("Report deleted Successfully.")
                        yield FunctionResult({'status': "Done"})

                    except Exception as e:
                        LOG.error(e.args[0])
                        yield FunctionResult({'error': "Please check logs!!"})

                else:
                    yield FunctionResult({'error': "Please check logs!!"})

            except Exception as e:
                LOG.error(e.args[0])
                yield FunctionResult({'error': e.args[0]})

        else:
            yield FunctionResult({'error': "Please provide proper inputs to the function \"Delete report in TruSTAR\"!!"
                                  })

    @function("get_priority_score_of_indicator")
    def get_priority_score(self, event, *args, **kwargs):
        """
        This is a workflow function handler which will fetch priority score of an indicator from trustar.
        :param event: Data received from platform
        :param args: Arguments received from resilient platform
        :param kwargs: Arguments received from resilient platform
        :return: Priority score as function result
        """
        if kwargs.get('trustar_incident_id', None) or kwargs.get('trustar_artifact_value', None):

            try:
                artifact_value = kwargs.get('trustar_artifact_value', "")
                artifact_value = self.encode_string(artifact_value)
                url = "/incidents/{}".format(kwargs.get('trustar_incident_id', ''))
                event.message['incident'] = (self.rest_client().get(url))
                workspace_name = event.message['incident'][0]['workspace']
                ts = self.get_ts(workspace_name)
                flag = False

                if ts:
                    LOG.info("Getting priority score of indicator {}.".format(artifact_value))
                    indicators = ts.search_indicators(artifact_value)

                    for indicator in indicators:

                        if indicator.value == artifact_value:
                            flag = True
                            LOG.info("Got Priority score of indicator {} - {}".format(artifact_value,
                                                                                      indicator.priority_level))
                            yield FunctionResult({'priorityLevel': indicator.priority_level})
                            break

                    if not flag:
                        LOG.info("Got priority score of indicator - {}.".format("NOT_FOUND"))
                        yield FunctionResult({'priorityLevel': "NOT_FOUND"})

                else:
                    yield FunctionResult({'error': "Please check logs!!"})

            except Exception as e:
                LOG.error(e.args[0])
                yield FunctionResult({'error': e.args[0]})

        else:
            yield FunctionResult({'error': "Please provide proper inputs to the function \"Get Priority Score of "
                                           "Indicator\"!!"})

    @function("get_correlated_indicators_from_trustar")
    def get_corelated_indicators_from_trustar(self, event, *args, **kwargs):
        """
        This is a workflow function handler which will fetch Correlated indicators for an incident.
        :param event: Data received from platform
        :param args: Arguments received from resilient platform
        :param kwargs: Arguments received from resilient platform
        :return: List of correlated indicators in json format as function result
        """
        if kwargs.get('trustar_incident_id', None):

            try:
                incident_id = kwargs.get('trustar_incident_id', "")
                url = "/incidents/{}".format(kwargs.get('trustar_incident_id', ''))
                event.message['incident'] = self.rest_client().get(url)
                workspace_name = event.message['incident']['workspace']
                ts = self.get_ts(workspace_name)

                if ts:
                    report = (ts.get_report_details("RESILIENT{}".format(incident_id), "external")).to_dict()
                    report_id = report['id']
                    LOG.info("Getting Extracted Indicators.")
                    extracted_indicator = ts.get_indicators_for_report(report_id)
                    extracted_indicators = [data.value for data in extracted_indicator]
                    corelated_indicators = []

                    if extracted_indicators:
                        LOG.info("Getting Correlated Indicators.")

                        if self.enclave_ids_for_query:
                            corelated_indicator = ts.get_related_indicators(extracted_indicators, (str(
                                self.enclave_ids_for_query)).split(","))
                        elif self.enclave_ids_to_submit:
                            corelated_indicator = ts.get_related_indicators(extracted_indicators, str(
                                self.enclave_ids_to_submit).split(","))
                        else:
                            corelated_indicator = {}
                            LOG.error("Please enter proper values of enclave ids in config file!!")
                            yield FunctionResult({'error': "Please enter proper values of enclave ids in config "
                                                           "file!!"})

                        LOG.info("Correlated Data Received.")
                        max_iocs = 100

                        for indicator in corelated_indicator:

                            if max_iocs > 0:
                                indicator.value = self.encode_string(indicator.value)
                                corelated_indicators.append({'type': indicator.type, 'value': indicator.value})
                                max_iocs -= 1
                            else:
                                break

                        response = {'indicators': corelated_indicators}
                        yield FunctionResult(response)

                    else:
                        LOG.info("No extracted indicators found!!")
                        yield FunctionResult({})

                else:
                    yield FunctionResult({'error': "Please check logs!!"})

            except Exception as e:
                LOG.error(e.args[0])
                yield FunctionResult({'error': e.args[0]})

        else:
            LOG.error("Please provide proper inputs to the function \"Get Correlated Indicators from TruSTAR\"!!")
            yield FunctionResult({'error': "Please provide proper inputs to the function \"Get Correlated Indicators "
                                           "from TruSTAR\"!!"})

    @function("whitelist_in_trustar")
    def f_whitelist_in_trustar(self, event, *args, **kwargs):
        """
        This is a workflow function handler which will add an indicator in whitelist in trustar.
        :param event: Data received from platform
        :param args: Arguments received from resilient platform
        :param kwargs: Arguments received from resilient platform
        :return: Whitelisted artifact in json as function result
        """
        if kwargs.get('trustar_artifact_value', None) or kwargs.get('trustar_incident_id', None):

            try:
                LOG.info("Whitelisting artifact in TruSTAR.")
                artifact_value = kwargs.get('trustar_artifact_value', '')
                artifact_value = self.encode_string(artifact_value)
                incident_id = kwargs.get('trustar_incident_id', "")
                artifact_type = ""
                url_for_artifacts = "/incidents/{}/artifacts".format(incident_id)
                artifacts = self.rest_client().get(url_for_artifacts)

                for artifact in artifacts:

                    if self.encode_string(artifact['value']) == self.encode_string(artifact_value):
                        artifact_type = artifact['type']

                url = "/incidents/{}".format(kwargs.get('trustar_incident_id', ''))
                event.message['incident'] = self.rest_client().get(url)
                workspace_name = event.message['incident']['workspace']
                ts = self.get_ts(workspace_name)
                indicators = []

                if ts:
                    response = ts.add_terms_to_whitelist([artifact_value])
                    flag = True

                    for indicator in response:

                        if self.encode_string(indicator.value) == self.encode_string(artifact_value):
                            flag = False
                            indicators.append({'type': indicator.type, 'value': indicator.value})

                            if indicator.type not in self.map_data.keys():
                                self.map_data[indicator.type] = artifact_type
                            else:

                                if artifact_type not in self.map_data[indicator.type]:
                                    i_type = self.get_artifact_type_name(artifact_type)
                                    self.map_data[indicator.type].extend([i_type])

                    if not flag:
                        LOG.info("Artifact whitelisted in TruSTAR successfully")
                    else:
                        LOG.info("Artifact: {} wasn't whitelisted in TruSTAR".format(artifact_value))

                    response = {'indicators': indicators}
                    yield FunctionResult(response)

                else:
                    yield FunctionResult({'error': "Please check logs!!"})

            except Exception as e:
                LOG.error(e.args[0])
                yield FunctionResult({'error': "Some error occurred!! Please check logs!!"})

        else:
            yield FunctionError("Please provide proper inputs to the function \"Whitelist in TruSTAR\"!!")

    @function("undo_whitelist_in_trustar")
    def f_undo_whitelist_in_trustar(self, event, *args, **kwargs):
        """
        This is a workflow function handler which will remove an indicator from whitelist in trustar.
        :param event: Data received from platform
        :param args: Arguments received from resilient platform
        :param kwargs: Arguments received from resilient platform
        :return: Status in json format as function result
        """
        if kwargs.get('trustar_artifact_value', None) or kwargs.get('trustar_incident_id', None):

            try:
                LOG.info("Undo whitelisting artifact in TruSTAR.")
                artifact_value = kwargs.get('trustar_artifact_value', "")
                artifact_value = self.encode_string(artifact_value)
                artifact_type = kwargs.get('trustar_artifact_type', None)

                if artifact_type:
                    i_type = ""

                    for field in self.map_data:

                        if artifact_type in self.map_data[field]:
                            i_type = field

                    indicator = {
                        "indicatorType": i_type,
                        "value": artifact_value
                    }
                    url = "/incidents/{}".format(kwargs.get('trustar_incident_id', ''))
                    event.message['incident'] = self.rest_client().get(url)
                    workspace_name = event.message['incident']['workspace']
                    ts = self.get_ts(workspace_name)

                    if ts:
                        ts.delete_indicator_from_whitelist(Indicator.from_dict(indicator))
                        LOG.info("Artifact removed from whitelist successfully.")
                        yield FunctionResult({'status': "Done"})

                    else:
                        yield FunctionResult({'error': "Please check logs!!"})

                else:
                    LOG.error("Please enter proper value of artifact type in function inputs!")
                    yield FunctionResult({'error': "Some error occurred!! Please check logs!!"})

            except Exception as e:
                LOG.error(e.args[0])
                yield FunctionResult({'error': e.args[0]})

        else:
            LOG.error("Please provide proper inputs to the function \"Undo Whitelist in TruSTAR\"!!")
            yield FunctionResult({'error': "Please provide proper inputs to the function \"Undo Whitelist in TruSTAR"
                                           "\"!!"})
