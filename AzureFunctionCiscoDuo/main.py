"""
Primary Cisco Duo Admin API Log endpoint program for Azure Sentinel data connector
"""
from __future__ import print_function, annotations

import os
import logging
import time
import re
import math
from typing import Iterable
import duo_client

import azure.functions as func

from sentinel_connector import AzureSentinelConnector
from state_manager import StateManager

from activity_log import ActivityLog
from auth_log import AuthLog
from trust_monitor_log import TrustMonitorLog
from admin_log import AdminLog
from telephony_log import TelephonyLog
from offline_enrollment_log import OfflineEnrollmentLog


logging.getLogger('azure.core.pipeline.policies.http_logging_policy').setLevel(logging.ERROR)

CISCO_DUO_INTEGRATION_KEY = os.environ['CISCO_DUO_INTEGRATION_KEY']
CISCO_DUO_SECRET_KEY = os.environ['CISCO_DUO_SECRET_KEY']
CISCO_DUO_API_HOSTNAME = os.environ['CISCO_DUO_API_HOSTNAME']
WORKSPACE_ID = os.environ['WORKSPACE_ID']
SHARED_KEY = os.environ['SHARED_KEY']
FILE_SHARE_CONN_STRING = os.environ['AzureWebJobsStorage']
LOG_TYPE = 'CiscoDuo'
MAX_SYNC_WINDOW_PER_RUN_MINUTES = os.getenv('MAX_SYNC_WINDOW_PER_RUN_MINUTES', "60")
MAX_SCRIPT_EXEC_TIME_MINUTES = 10

LOG_ANALYTICS_URI = os.environ.get('logAnalyticsUri')

if not LOG_ANALYTICS_URI or str(LOG_ANALYTICS_URI).isspace():
    LOG_ANALYTICS_URI = 'https://' + WORKSPACE_ID + '.ods.opinsights.azure.com'

pattern = r'https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$'
match = re.match(pattern, str(LOG_ANALYTICS_URI))
if not match:
    raise Exception("Invalid Log Analytics Uri.")


def main(mytimer: func.TimerRequest) -> None:
    """Program entry point."""
    logging.info('Starting script')
    start_ts = math.floor(time.time())
    admin_api = duo_client.Admin(ikey=CISCO_DUO_INTEGRATION_KEY, skey=CISCO_DUO_SECRET_KEY,
                                 host=CISCO_DUO_API_HOSTNAME, )
    sentinel = AzureSentinelConnector(log_analytics_uri=LOG_ANALYTICS_URI, workspace_id=WORKSPACE_ID,
                                      shared_key=SHARED_KEY, log_type=LOG_TYPE, queue_size=5000)

    log_types = get_log_types()

    if 'activity' in log_types:
        state_manager = StateManager(FILE_SHARE_CONN_STRING, file_path='cisco_duo_activity_logs_last_ts.txt')
        activity_log = ActivityLog(admin_api=admin_api, state_manager=state_manager, sentinel=sentinel)
        activity_log.process_activity_logs(start_ts=start_ts)
        if check_if_script_runs_too_long(start_ts):
            logging.info('Script is running too long. Saving progress and exit.')
            return

    if 'trust_monitor' in log_types:
        state_manager = StateManager(FILE_SHARE_CONN_STRING, file_path='cisco_duo_trust_monitor_logs_last_ts.txt')
        trust_monitor_log = TrustMonitorLog(admin_api=admin_api, state_manager=state_manager, sentinel=sentinel)
        trust_monitor_log.process_trust_monitor_events()
        if check_if_script_runs_too_long(start_ts):
            logging.info('Script is running too long. Saving progress and exit.')
            return

    if 'authentication' in log_types:
        state_manager = StateManager(FILE_SHARE_CONN_STRING, file_path='cisco_duo_auth_logs_last_ts.txt')
        auth_log = AuthLog(admin_api=admin_api, state_manager=state_manager, sentinel=sentinel)
        auth_log.process_auth_logs(start_ts=start_ts)
        if check_if_script_runs_too_long(start_ts):
            logging.info('Script is running too long. Saving progress and exit.')
            return

    if 'administrator' in log_types:
        state_manager = StateManager(FILE_SHARE_CONN_STRING, file_path='cisco_duo_admin_logs_last_ts.txt')
        admin_log = AdminLog(admin_api=admin_api, state_manager=state_manager, sentinel=sentinel)
        admin_log.process_admin_logs(start_ts=start_ts)
        if check_if_script_runs_too_long(start_ts):
            logging.info('Script is running too long. Saving progress and exit.')
            return

    if 'telephony' in log_types:
        state_manager = StateManager(FILE_SHARE_CONN_STRING, file_path='cisco_duo_tele_logs_last_ts.txt')
        telephony_log = TelephonyLog(admin_api=admin_api, state_manager=state_manager, sentinel=sentinel)
        telephony_log.process_telephony_logs(start_ts=start_ts)
        if check_if_script_runs_too_long(start_ts):
            logging.info('Script is running too long. Saving progress and exit.')
            return

    if 'offline_enrollment' in log_types:
        state_manager = StateManager(FILE_SHARE_CONN_STRING, file_path='cisco_duo_offline_enrollment_logs_last_ts.txt')
        offline_enroll_log = OfflineEnrollmentLog(admin_api=admin_api, state_manager=state_manager, sentinel=sentinel)
        offline_enroll_log.process_offline_enrollment_logs(start_ts=start_ts)
        if check_if_script_runs_too_long(start_ts):
            logging.info('Script is running too long. Saving progress and exit.')
            return

    logging.info('Script finished. Sent events: {}'.format(sentinel.successful_sent_events_number))


def get_log_types():
    """Extract Cisco Duo logging endpoints from environment variables."""
    res = str(os.environ.get('CISCO_DUO_LOG_TYPES', ''))
    if not res:
        res = 'trust_monitor,authentication,administrator,telephony,offline_enrollment, activity'
    return [x.lower().strip() for x in res.split(',')]


def check_if_script_runs_too_long(start_ts):
    """Check if difference between 'start_ts' and current time is greater than 'MAX_SCRIPT_EXEC_TIME_MINUTES'."""
    return math.floor(time.time()) - start_ts > int(MAX_SCRIPT_EXEC_TIME_MINUTES * 60 * 0.85)
