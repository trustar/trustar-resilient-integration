from __future__ import unicode_literals
import logging
import time
from datetime import datetime
from trustar import TruStar
import unicodedata
from trustar_resilient_action_module.components.trustar_handler import TruSTARHandler
from circuits import BaseComponent, handler
try:
    from rc_cts import searcher_channel, Hit, StringProp, ThreatServiceLookupEvent
except ImportError as e:
    raise ImportError("rc_cts package is required. Install the package and then run the integration.")
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from typing import *
    from trustar import Report, IndicatorSummary, IndicatorScore, IndicatorAttribute


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

    def case_insensitive_string_compare(self, s_a, s_b):
        """ Compares 2 strings, case-insensitive.  """
        a = self.unicode_norm(s_a)                   # type: str
        a = a.casefold()
        b = self.unicode_norm(s_b)                   # type: str
        b = b.casefold()
        return a == b

    @staticmethod
    def unicode_norm(s):                                # type: (str) -> str
        """ Normalizes a unicode string for comparison to another. """
        return unicodedata.normalize('NFD', s)

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
            now_millis = int(time.time() * 1000.0)
            one_day_millis = 60 * 60 * 24 * 1000
            indicators = ts.search_indicators(
                self.unicode_norm(artifact_value),
                enclave_ids=self.enclave_ids.split(","),
                from_time=now_millis - (90 * one_day_millis)
            )

            correlation_enclave_ids = self.enclave_ids.split(",")
            correlation_enclave_ids = [
                encl_id.strip() for encl_id
                in correlation_enclave_ids]                  # type: List[str]

            indicator_value = None
            for indicator in indicators:

                # TODO: Need to make sure this is the correct way to do
                #  this.  What unicode normalizations need to be done
                #  to a string before searching Station for an IOC by
                #  that name?  What normalizations need to be done to
                #  Station's response?  Need to think through this
                #  more.
                if self.case_insensitive_string_compare(indicator.value,
                                                        artifact_value):
                    indicator_value = indicator.value

            if not indicator_value:
                return []

            summary_hits = self.get_summary_hits(
                ts, indicator_value, correlation_enclave_ids
            )                                                 # type: List[Hit]

            report_hits = self.get_report_hits(
                ts, indicator_value, correlation_enclave_ids
            )                                                # type: List[Hit]

            hits.extend(summary_hits)
            hits.extend(report_hits)

            return hits

        except Exception as err:
            LOG.error(err.args[0])
            return None

    def get_enclave_ids_names(self, ts):             # type: (TruStar) -> Dict
        """ Builds & caches the enclave_ids_names dict. """
        attr_name = '__enclave_ids_names'
        if not hasattr(self, attr_name):
            setattr(self, attr_name, None)
        if not getattr(self, attr_name):
            enclaves = ts.get_user_enclaves()
            enclave_ids_names = {e.id: e.name for e in enclaves}
            setattr(self, attr_name, enclave_ids_names)
        return getattr(self, attr_name)

    def get_report_hits(self, ts,                            # type: TruStar
                        indicator_value,                     # type: str
                        correlation_enclaves                 # type: List[str]
                        ):                          # type: (...) -> List[Hit]
        """ Builds list of Hits for the artifact, one Hit for each
        report in the correlation enclaves that the indicator is
        sighted in. """

        gen = ts.get_correlated_reports(
            [indicator_value],
            enclave_ids=correlation_enclaves)        # type: Generator[Report]

        reports = [r for r in gen if r]              # type: List[Report]

        hits = []
        for report in reports:                                  # type: Report

            # Title.
            if report.title:
                title_prop = report.title
            else:
                title_prop = " ** This report had no title. ** "


            # Updated timestamp.
            if report.updated:
                dt = datetime.fromtimestamp(report.updated/1000.0)
                updated_prop = str(dt)
            else:
                updated_prop = (" ** This report had no 'updated' "
                                "timestamp. ** ")


            # TimeBegan timestamp.
            if report.time_began:
                dt = datetime.fromtimestamp(report.updated/1000.0)
                began_prop = str(dt)
            else:
                began_prop = (" ** This report had no 'timeBegan' "
                                "timestamp. ** ")


            # Deeplink.
            ts_report_base_url = (
                "https://station.trustar.co/constellation/reports/")
            deeplink_prop = "{}{}".format(ts_report_base_url, report.id)


            properties = [title_prop, updated_prop, began_prop, deeplink_prop]
            hits.append(Hit(properties))

        return hits

    def get_summary_hits(self, ts,                           # type: TruStar
                         indicator_value,                    # type: str
                         correlation_enclaves                # type: List[str]
                         ):                         # type: (...) -> List[Hit]
        """ Builds list of Hits for the artifact based on TruSTAR Indicator
        Summary info. """
        summaries = ts.get_indicator_summaries(
            [indicator_value],
            enclave_ids=correlation_enclaves
        )                                  # type: Generator[IndicatorSummary]

        summaries = [
            s for s in summaries if s]          # type: List[IndicatorSummary]

        hits = []                                            # type: List[Hit]
        for s in summaries:                           # type: IndicatorSummary

            # Enclave name property.
            if s.source:
                source_prop = StringProp(name="Intel Provider",
                                         value=s.source)
            else:
                source_prop = StringProp(name="Intel Provider",
                                         value="Not found in TruSTAR Summary.")


            # Report Title property.
            report = ts.get_report_details(s.report_id)
            if report.title:
                title = report.title
            else:
                title = "**This report had no title.**"
            title_prop = StringProp(name="Report Title",
                                    value=title)


            # Normalized Score Property.
            score_prop = None
            if s.score:                                 # type: IndicatorScore
                if s.score.name and s.score.value:
                    score_prop = StringProp(name=s.score.name,
                                            value=s.score.value)
            if not score_prop:
                score_prop = StringProp(name="Score",
                                        value="None provided.")


            # Build/append Hit.
            properties = [source_prop, title_prop,
                          score_prop]                  # type: List[StringProp]

            hits.append(Hit(properties))

        return hits