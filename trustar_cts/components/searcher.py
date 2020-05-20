from __future__ import unicode_literals
import logging
from trustar import TruStar
from trustar_resilient_action_module.components.trustar_handler import TruSTARHandler
from circuits import BaseComponent, handler
try:
    from rc_cts import searcher_channel, Hit, StringProp, ThreatServiceLookupEvent
except ImportError as e:
    raise ImportError("rc_cts package is required. Install the package and then run the integration.")


LOG = logging.getLogger(__name__)

CONFIG_SECTION = "trustar_threat_source"


class TruSTARThreatSearcher(BaseComponent):
    """
    Custom threat lookup for TruSTAR

    """
    channel = searcher_channel("trustar")

    def __init__(self, opts):
        super(TruSTARThreatSearcher, self).__init__(opts)
        self.options = opts.get(CONFIG_SECTION, {})
        self.url = self.options.get('url', '')
        if str(self.url).endswith('/'):
            self.url = str(self.url)[:-1]
        self.auth_endpoint = self.url + "/oauth/token"
        self.api_endpoint = self.url + "/api/1.3"
        self.user_api_key = self.options.get("user_api_key", None)
        if not self.user_api_key:
            LOG.info("Please enter value for API KEY of TruSTAR by running \"res-keyring\" command")
        self.user_api_secret = self.options.get("user_api_secret", None)
        if not self.user_api_secret:
            LOG.info("Please enter value for API SECRET of TruSTAR by running \"res-keyring\""
                     " command")
        self.enclave_ids = self.options.get('enclave_ids_for_search', "")
        self.conf_for_trustar = {
            "auth_endpoint": self.auth_endpoint,
            "api_endpoint": self.api_endpoint,
            "user_api_key": self.user_api_key,
            "user_api_secret": self.user_api_secret,
            "enclave_ids": self.enclave_ids,
            "client_type": "Python_SDK",
            "client_version": "1.3",
            "client_metatag": "Resilient"
        }
        trustar_options = opts.get('trustar', {})
        self.proxy = trustar_options.get('proxy', None)
        self.secured_proxy = trustar_options.get('secure_proxy', None)
        self.proxy_url = trustar_options.get('proxy_url', None)
        self.proxy_username = trustar_options.get('proxy_username', None)
        self.proxy_password = trustar_options.get('proxy_password', None)

        if self.proxy.lower() == "true":
            proxy_data = TruSTARHandler.get_proxy_data(self.proxy_url, self.secured_proxy, self.proxy_username, self.proxy_password)
        else:
            proxy_data = "Not in use"

        if isinstance(proxy_data, dict):
            self.conf_for_trustar['http_proxy'] = proxy_data['http_proxy']
            self.conf_for_trustar['https_proxy'] = proxy_data['https_proxy']
        elif proxy_data is None:
            self.conf_for_trustar['error'] = True

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

    @handler()
    def _lookup_artifact(self, event, *args, **kwargs):
        """Lookup an artifact"""

        if not isinstance(event, ThreatServiceLookupEvent):
            return

        LOG.info("Threat Lookup started for artifact: {}".format(event.artifact['value']))
        artifact_value = event.artifact['value']
        artifact_value = self.encode_string(artifact_value)
        hits = []
        flag = True
        try:
            if not self.conf_for_trustar.get('error'):
                ts = TruStar(config=self.conf_for_trustar)
            else:
                return None
        except Exception as err:
            LOG.error(err.args[0])
            return None
        try:

            indicators = ts.search_indicators(str(artifact_value), self.enclave_ids.split(","))

            for indicator in indicators:

                if self.encode_string(indicator.value) == self.encode_string(artifact_value):

                    if str(indicator.priority_level).upper() == "HIGH" or str(
                            indicator.priority_level).upper() == "MEDIUM":
                        flag = False
                        hit = Hit(StringProp(name="Priority Level", value=indicator.priority_level))
                        hits.append(hit)
                        LOG.info(
                            "Priority Score of artifact: {} is {}.".format(artifact_value, indicator.priority_level))
                        break
            if flag:
                LOG.info("Priority Score of artifact: {} not found.".format(artifact_value))
            return hits

        except Exception as err:
            LOG.error(err.args[0])
            return None
