"""
Cisco Duo Offline Enrollment Log class and methods
"""
from __future__ import annotations
import math
import time
import logging
from singleton import Singleton
from typing import Iterable
from main import check_if_script_runs_too_long
from base import DuoLogBase, DuoException


class OfflineEnrollmentLog(DuoLogBase, metaclass=Singleton):
    """Cisco Duo Offline Enrollment Log class"""

    def get_offline_enrollment_logs(self, mintime: int) -> Iterable[dict]:
        """Retrieves offline enrollment logs."""
        logging.info('Making offline_enrollment logs request: mintime={}'.format(mintime))
        events: list = []
        try:
            events = self.admin_api.get_offline_log(mintime)
        except DuoException as err:
            logging.warning('Error while getting offline_enrollment logs- {}'.format(err))
            if err.status == 429:
                logging.warning('429 exception occurred, trying retry after 60 seconds')
                time.sleep(60)
                events = self.admin_api.get_offline_log(mintime)

        if events is not None:
            logging.info('Obtained {} offline_enrollment events'.format(len(events)))

        else:
            logging.error('Error while getting offline_enrollment logs')
        return events

    def process_offline_enrollment_logs(self, start_ts) -> None:
        """Process offline enrollment logs."""
        limit = 1000
        logging.info('Start processing offline_enrollment logs')

        logging.info('Getting last timestamp')
        mintime = self.state_manager.get()
        if mintime:
            logging.info('Last timestamp is {}'.format(mintime))
            mintime = int(mintime) + 1
        else:
            logging.info('Last timestamp is not known. Getting data for last 24h')
            mintime = math.floor(time.time() - 86400)

        last_ts = None

        events = self.get_offline_enrollment_logs(mintime=mintime)

        for event in events:
            last_ts = event['timestamp']
            self.sentinel.send(event)

        self.sentinel.flush()

        if last_ts:
            logging.info('Saving offline_enrollment logs last timestamp {}'.format(last_ts))
            self.state_manager.post(str(last_ts))

        while len(events) == limit:
            mintime = last_ts
            mintime += 1
            logging.info('Making offline_enrollment logs request: mintime={}'.format(mintime))
            try:
                events = self.admin_api.get_offline_log(mintime)
            except DuoException as ex:
                logging.warning('Error while getting offline_enrollment logs - {}'.format(ex))
                if ex.status == 429:
                    logging.warning('429 exception occurred, trying retry after 60 seconds')
                    time.sleep(60)
                    events = self.admin_api.get_offline_log(mintime)

            if events is not None:
                logging.info('Obtained {} offline_enrollment events'.format(len(events)))

            else:
                logging.info('Events returned as null in offline_enrollment logs')

            for event in events:
                last_ts = event['timestamp']
                self.sentinel.send(event)

            self.sentinel.flush()

            if last_ts:
                logging.info('Saving offline_enrollment logs last timestamp {}'.format(last_ts))
                self.state_manager.post(str(last_ts))

            if check_if_script_runs_too_long(start_ts):
                logging.info('Script is running too long. Saving progress and exit.')
                return
