"""
Cisco Duo Telephony Log class and methods
"""
from __future__ import annotations
import math
import time
import logging
from singleton import Singleton
from typing import Iterable
from main import check_if_script_runs_too_long, MAX_SYNC_WINDOW_PER_RUN_MINUTES
from base import DuoLogBase, DuoException


class TelephonyLog(DuoLogBase, metaclass=Singleton):
    """Cisco Duo Telephony Log class"""

    def get_tele_logs(self, mintime: int) -> Iterable[dict]:
        """Retrieves Cisco Duo telephony logs based on timestamp."""
        logging.info('Making telephony logs request: mintime={}'.format(mintime))
        events: list = []
        try:
            events = self.admin_api.get_telephony_log(mintime)
        except DuoException as err:
            logging.warning('Error while getting telephony logs - {}'.format(err))
            if err.status == 429:
                logging.warning('429 exception occurred, trying retry after 60 seconds')
                time.sleep(60)
                events = self.admin_api.get_telephony_log(mintime)

        if events is not None:
            logging.info('Obtained {} tele events'.format(len(events)))
        else:
            logging.error('Error while getting telephony logs')
        return events

    def process_telephony_logs(self, start_ts) -> None:
        """Process telephony logs."""
        limit = 1000
        logging.info('Start processing telephony logs')

        logging.info('Getting last timestamp')
        mintime = self.state_manager.get()
        if mintime:
            logging.info('Last timestamp is {}'.format(mintime))
            mintime = int(mintime) + 1
        else:
            logging.info('Last timestamp is not known. Getting data for last 24h')
            mintime = math.floor(time.time() - 86400)

        last_ts = None

        events = self.get_tele_logs(mintime=mintime)

        for event in events:
            last_ts = event['timestamp']
            self.sentinel.send(event)

        self.sentinel.flush()

        if last_ts:
            logging.info('Saving telephony logs last timestamp {}'.format(last_ts))
            self.state_manager.post(str(last_ts))

        while len(events) == limit:  # noqa: type
            mintime = last_ts
            mintime += 1
            logging.info('Making telephony logs request: mintime={}'.format(mintime))
            try:
                events = self.admin_api.get_telephony_log(mintime)
            except DuoException as ex:
                logging.warning('Error while getting telephony logs - {}'.format(ex))
                if ex.status == 429:
                    logging.warning('429 exception occurred, trying retry after 60 seconds')
                    time.sleep(60)
                    events = self.admin_api.get_telephony_log(mintime)

            if events is not None:
                logging.info('Obtained {} tele events'.format(len(events)))  # noqa: type

            else:
                logging.info('Events returned as null in telephony logs')

            for event in events:
                last_ts = event['timestamp']
                self.sentinel.send(event)

            self.sentinel.flush()

            if last_ts:
                logging.info('Saving telephony logs last timestamp {}'.format(last_ts))
                self.state_manager.post(str(last_ts))

            if check_if_script_runs_too_long(start_ts):
                logging.info('Script is running too long. Saving progress and exit.')
                return

