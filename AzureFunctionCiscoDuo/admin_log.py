"""
Cisco Duo Admin Log class and methods
"""
from __future__ import annotations
import math
import time
import logging
from singleton import Singleton
from typing import Iterable
from main import check_if_script_runs_too_long
from base import DuoLogBase, DuoException


class AdminLog(DuoLogBase, metaclass=Singleton):
    """Cisco Duo Admin Log class"""

    def get_admin_logs(self, mintime: int) -> Iterable['dict']:
        """Retrieves Cisco Duo administrator logs based on timestamp."""
        logging.info('Making administrator logs request: mintime={}'.format(mintime))
        events: list = []
        try:
            events = self.admin_api.get_administrator_log(mintime)
        except DuoException as err:
            logging.warning('Error while getting administrator logs- {}'.format(err))
            if err.status == 429:
                logging.warning('429 exception occurred, trying retry after 60 seconds')
                time.sleep(60)
                events = self.admin_api.get_administrator_log(mintime)

        if events is not None:
            logging.info('Obtained {} admin events'.format(len(events)))

        else:
            logging.error('Error while getting administrator logs')
        return events

    def process_admin_logs(self, start_ts) -> None:
        """Process administrator action logs."""
        limit = 1000
        logging.info('Start processing administrator logs')

        logging.info('Getting last timestamp')
        mintime = self.state_manager.get()
        if mintime:
            logging.info('Last timestamp is {}'.format(mintime))
            mintime = int(mintime) + 1
        else:
            logging.info('Last timestamp is not known. Getting data for last 24h')
            mintime = math.floor(time.time() - 86400)

        last_ts = None
        events = self.get_admin_logs(mintime=mintime)

        for event in events:
            last_ts = event['timestamp']
            self.sentinel.send(event)

        self.sentinel.flush()

        if last_ts:
            logging.info('Saving admin logs last timestamp {}'.format(last_ts))
            self.state_manager.post(str(last_ts))

        while len(events) == limit:  # noqa: type
            mintime = last_ts
            mintime += 1
            logging.info('Making administrator logs request: mintime={}'.format(mintime))
            try:
                events = self.admin_api.get_administrator_log(mintime)
            except DuoException as ex:
                logging.warning('Error while getting administrator logs- {}'.format(ex))
                if ex.status == 429:
                    logging.warning('429 exception occurred, trying retry after 60 seconds')
                    time.sleep(60)
                    events = self.admin_api.get_administrator_log(mintime)

            if events is not None:
                logging.info('Obtained {} admin events'.format(len(events)))  # noqa: type

            else:
                logging.info('Events returned as null in administrator logs')

            for event in events:
                last_ts = event['timestamp']
                self.sentinel.send(event)

            self.sentinel.flush()

            if last_ts:
                logging.info('Saving admin logs last timestamp {}'.format(last_ts))
                self.state_manager.post(str(last_ts))

            if check_if_script_runs_too_long(start_ts):
                logging.info('Script is running too long. Saving progress and exit.')
                return
