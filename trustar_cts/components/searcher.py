# encoding=utf-8

""" Custom threat service for Resilient. """

from __future__ import unicode_literals
import logging
import time
import sys
from datetime import datetime
from typing import TYPE_CHECKING

from trustar import TruStar
from trustar_resilient_action_module.components.trustar_handler import TruSTARHandler
from circuits import BaseComponent, handler
from rc_cts import (searcher_channel, Hit, StringProp, UriProp,
                    ThreatServiceLookupEvent)

if TYPE_CHECKING:
    from typing import *
    from trustar import (Report, IndicatorSummary, IndicatorScore, Indicator,
                         EnclavePermissions)
    from resilient.co3argparse import ConfigDict



LOG = logging.getLogger(__name__)

THREAT_SOURCE_CONFIG_SECTION = "trustar_threat_source"
TRUSTAR_CONFIG_SECTION = "trustar"
CLIENT_METATAG = "RESILIENT_CUSTOM_THREAT_SOURCE"

class TruSTARThreatSearcher(BaseComponent):
    """ Custom threat lookup for TruSTAR. """

    channel = searcher_channel("trustar_cts")

    def __init__(self, opts,                                # type: ConfigDict
                 *args, **kwargs):

        # Threat source stanza.
        options = opts.get(THREAT_SOURCE_CONFIG_SECTION, {})

        user_api_key = options.get("user_api_key", None)
        if not user_api_key:
            msg = "TruSTAR user API key missing from config file."
            self._log_raise(msg)

        user_api_secret = options.get("user_api_secret", None)
        if not user_api_secret:
            msg = "TruSTAR API secret missing from config file."
            self._log_raise(msg)

        enclave_ids = options.get('enclave_ids_for_search', "")
        if not enclave_ids:
            msg = "'enclave_ids_for_search' missing from config file."
            self._log_raise(msg)



        # Client Config Dict.
        trustar_client_config = {"user_api_key": user_api_key,
                                 "user_api_secret": user_api_secret,
                                 "client_metatag": CLIENT_METATAG}



        # "trustar" stanza.
        trustar_options = opts.get(TRUSTAR_CONFIG_SECTION, {})

        uses_proxy = trustar_options.get('proxy', None)

        if uses_proxy.lower() == "true":

            secured_proxy = trustar_options.get('secure_proxy', None)
            proxy_url = trustar_options.get('proxy_url', None)
            proxy_username = trustar_options.get('proxy_username', None)
            proxy_password = trustar_options.get('proxy_password', None)

            proxy_data = TruSTARHandler.get_proxy_data(
                proxy_url,
                secured_proxy,
                proxy_username,
                proxy_password)                # type: Dict[str] or {} or None

            if not proxy_data:
                raise Exception("Problem with proxy settings in config file."
                                "Please fix them and try again.")

            trustar_client_config['http_proxy'] = proxy_data['http_proxy']
            trustar_client_config['https_proxy'] = proxy_data['https_proxy']




        # Client.
        self.ts = TruStar(config=trustar_client_config)

        self.search_enclave_ids = [x.strip() for x in
                                   enclave_ids.split(",")]




        # Enclave validation.
        this_users_enclaves = self.ts.get_user_enclaves()   # type: List[EnclavePermissions]

        self.enclave_names = {}
        for enclave in this_users_enclaves:         # type: EnclavePermissions
            self.enclave_names[enclave.id] = enclave.name

        enclave_read_permissions = {}
        for enclave in this_users_enclaves:
            enclave_read_permissions[enclave.id] = enclave.read


        for enclave_id in self.search_enclave_ids:
            if enclave_id not in self.enclave_names:
                raise Exception("This set of TruSTAR API creds does not "
                                "have access to enclave '{}'."
                                .format(enclave_id))

            read_perms = enclave_read_permissions[enclave_id]
            no_read_access_msg = ("This set of creds does not have read "
                                  "access to enclave '{}'."
                                  .format(enclave_id))

            if isinstance(read_perms, str):
                if read_perms != "true":
                    raise Exception(no_read_access_msg)

            elif not read_perms:
                raise Exception(no_read_access_msg)

        super(TruSTARThreatSearcher, self).__init__(opts, *args, **kwargs)

    @staticmethod
    def _log_raise(msg):
        """ Logs an error message, then raises exception with it. """
        LOG.error(msg)
        raise Exception(msg)


    @handler()
    def _lookup_artifact(self, event,       # type: ThreatServiceLookupEvent
                         *args,
                         **kwargs):         # type: (...) -> List[Hit] or []
        """ Lookup an artifact.

        :param event: ThreatServiceLookupEvent.
        :return: List[Hit] - Must return a list of Hits or yield one hit
        at a time in generator fashion. """

        if not isinstance(event, ThreatServiceLookupEvent):
            return None


        artifact_value = event.artifact['value'].strip()
        LOG.info("Threat Lookup started for artifact: '{}'"
                .format(artifact_value))
        if not artifact_value:
            LOG.error("No artifact found in ThreatServiceLookupEvent.")
            return None
        artifact_value = str(artifact_value)

        try:
            hits = self._lookup_string_artifact(artifact_value)
            LOG.info("Returning '{}' hits for artifact '{}'."
                     .format(str(len(hits)), artifact_value))
            return hits
        except Exception as e:
            msg = ("Lookup for '{}' failed.  Exception  message:  '{}'."
                   .format(artifact_value, str(e)))
            self._log_raise(msg)
            msg = "RETURNED MESSAGE:  " + msg
            return msg

    def _lookup_string_artifact(self, artifact_value):


        now_millis = int(time.time() * 1000.0)
        n_millis_in_a_day = 24 * 60 * 60 * 1000
        from_time_millis = now_millis - 180 * n_millis_in_a_day

        gen = self.ts.search_indicators(
            search_term=artifact_value,
            from_time=from_time_millis,
            to_time=now_millis,
            enclave_ids=self.search_enclave_ids)  # type: Generator[Indicator]

        indicators = []                           # type: List[Indicator]
        for indicator in gen:
            indicators.append(indicator)

        LOG.info(str(len(indicators)))

        for indicator in indicators:                         # type: Indicator
            LOG.info(indicator.value + " found in search.")

        indicator_value = None
        for indicator in indicators:                        # type: Indicator

            # TODO: Need to make sure this is the correct way to do
            #  this.  What unicode normalizations need to be done
            #  to a string before searching Station for an IOC by
            #  that name?  What normalizations need to be done to
            #  Station's response?  Need to think through this
            #  more.

            value = str(indicator.value)
            if value == artifact_value:
                indicator_value = value

        if not indicator_value:
            LOG.info("No matching indicators found in Station.")
            return []


        try:
            summary_hits = self.get_summary_hits(indicator_value) # type: List[Hit]
        except Exception as e:
            summary_hits = []
            raise Exception("Building summary hits for '{}' failed.  "
                            "Exception message:  '{}'."
                            .format(artifact_value, str(e)))

        try:
            report_hits = self.get_report_hits(indicator_value)  # type: List[Hit]
        except Exception as e:
            report_hits = []
            raise Exception("Buildint report hits for '{}' failed.  "
                            "Exception message:  '{}'."
                            .format(artifact_value, str(e)))

        hits = []                                            # type: List[Hit]
        hits.extend(summary_hits)
        hits.extend(report_hits)
        return hits



    def get_report_hits(self, indicator_value,      # type: str
                        ):                          # type: (...) -> List[Hit]
        """ Builds list of Hits for the artifact, one Hit for each
        report in the search enclaves that the indicator is
        mentioned in. """

        gen = self.ts.get_correlated_reports(
            [indicator_value],
            enclave_ids=self.search_enclave_ids)     # type: Generator[Report]

        reports = []                                      # type: List[Report]
        for report in gen:
            if report:
                reports.append(report)

        hits = []
        for report in reports:                                  # type: Report

            # Title.
            if report.title:
                title = report.title
            else:
                title = " ** This report had no title. ** "
            title_prop = StringProp(name="Title", value=title)


            # Updated timestamp.
            if report.updated:
                dt = datetime.fromtimestamp(report.updated/1000.0)
                updated = str(dt)
            else:
                updated = " ** This report had no 'updated' timestamp. ** "
            updated_prop = StringProp(name="Time Report Last Updated",
                                      value=updated)


            # TimeBegan timestamp.
            if report.time_began:
                dt = datetime.fromtimestamp(report.updated/1000.0)
                began = str(dt)
            else:
                began = " ** This report had no 'timeBegan' timestamp. ** "
            began_prop = StringProp(name="Time Report's Incident/Event Began",
                                    value=began)

            # Deeplink to TruSTAR.
            ts_report_base_url = (
                "https://station.trustar.co/constellation/reports/")
            deeplink = "{}{}".format(ts_report_base_url, report.id)
            deeplink_prop = UriProp(name="Link to TruSTAR Report",
                                    value=deeplink)

            # Deeplink to Source.
            if report.external_url:
                source_report_url = report.external_url
            else:
                source_report_url = (" ** TruSTAR does not have a source "
                                     "report URL for this report. ** ")
            source_report_url_prop = UriProp(name="Link to Source Report",
                                             value=source_report_url)


            # Aggregate properties, build Hit, add to Hits list.
            hits.append(Hit(title_prop,
                            updated_prop,
                            began_prop,
                            deeplink_prop,
                            source_report_url_prop))

        return hits

    def get_summary_hits(self, indicator_value,   # type: str
                         ):                       # type: (...) -> List[Hit]
        """ Builds list of Hits for the artifact based on TruSTAR Indicator
        Summary info. """
        gen = self.ts.get_indicator_summaries(
            [indicator_value],
            enclave_ids=self.search_enclave_ids
        )                                  # type: Generator[IndicatorSummary]

        summaries = []                          # type: List[IndicatorSummary]
        for summary in gen:
            if summary:
                summaries.append(summary)
            else:
                LOG.error("TruSTAR Summary object was null.")

        hits = []                                            # type: List[Hit]
        for s in summaries:                           # type: IndicatorSummary

            # Enclave name property.
            if s.source:
                source_prop = StringProp(name="Intel Provider",
                                         value=s.source)
            else:
                source_prop = StringProp(name="Intel Provider",
                                         value="Not found in TruSTAR Summary.")

            report = self.ts.get_report_details(s.report_id)

            # Report Title property.
            if report.title:
                title = report.title
            else:
                title = "**This report had no title.**"
            title_prop = StringProp(name="Report Title",
                                    value=title)


            # Pass-through Score Property.
            score_prop = None
            if s.score:                                 # type: IndicatorScore
                if s.score.name and s.score.value:
                    score_prop = StringProp(name=s.score.name,
                                            value=s.score.value)
            if not score_prop:
                score_prop = StringProp(name="Score",
                                        value="None provided.")

            h = Hit(source_prop, title_prop, score_prop)
            hits.append(h)

        return hits