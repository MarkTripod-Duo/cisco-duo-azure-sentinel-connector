"""
Cisco Duo Authentication Log class and methods
"""
from __future__ import annotations
import math
import time
import logging
from singleton import Singleton
from main import check_if_script_runs_too_long, MAX_SYNC_WINDOW_PER_RUN_MINUTES
from base import DuoLogBase, DuoException


class AuthLog(DuoLogBase, metaclass=Singleton):
    """Cisco Duo User Authentication Log class and methods"""

    def get_auth_logs(self, mintime: int, maxtime: int):
        """Retrieve user authentication logs."""
        limit = 1000
        logging.info('Making authentication logs request: mintime={}, maxtime={}'.format(mintime, maxtime))
        res = None
        try:
            res = self.admin_api.get_authentication_log(api_version=2, mintime=mintime, maxtime=maxtime,
                                                        limit=str(limit), sort='ts:asc')
        except DuoException as status:
            logging.warning('Error while getting authentication logs- {}'.format(status))
            if status.status == 429:
                logging.warning('429 exception occurred, trying retry after 60 seconds')
                time.sleep(60)
                res = self.admin_api.get_authentication_log(api_version=2, mintime=mintime, maxtime=maxtime,
                                                            limit=str(limit), sort='ts:asc')

        if res is not None:
            events = res['authlogs']
            next_offset = res['metadata']['next_offset']
            logging.info('Obtained {} auth events'.format(len(events)))
        else:
            logging.error('Error while getting authentication logs')
            events = None
            next_offset = None
        return events, next_offset

    def process_auth_logs(self, start_ts) -> None:
        """Process user authentication logs."""
        limit = 1000
        logging.info('Start processing authentication logs')

        logging.info('Getting last timestamp')
        mintime = self.state_manager.get()
        if mintime:
            logging.info('Last timestamp is {}'.format(mintime))
            mintime = int(mintime) + 1
        else:
            logging.info('Last timestamp is not known. Getting data for last 24h')
            mintime = math.floor(time.time() - 86400) * 1000

        maxtime = math.floor(time.time() - 120) * 1000
        diff = maxtime - mintime
        max_window = int(MAX_SYNC_WINDOW_PER_RUN_MINUTES) * 60000
        if diff > max_window:
            maxtime = mintime + max_window
            logging.warning(
                    'Ingestion is lagging for authentication logs, limiting synchronization window to {}'.format(
                            max_window))

        events, next_offset = self.get_auth_logs(mintime=mintime, maxtime=maxtime)

        for event in events:
            self.sentinel.send(event)

        self.sentinel.flush()

        logging.info('Saving auth logs last timestamp {}'.format(maxtime))
        self.state_manager.post(str(maxtime))

        while len(events) == limit:
            if next_offset and next_offset is not None:
                next_offset = ','.join(next_offset)
            else:
                break
            logging.info('Making authentication logs request: next_offset={}'.format(next_offset))

            response = None
            try:
                response = self.admin_api.get_authentication_log(api_version=2, mintime=mintime, maxtime=maxtime,
                                                                 limit=str(limit), sort='ts:asc',
                                                                 next_offset=next_offset)
                logging.info('Response received {}'.format(response))
            except DuoException as ex:
                logging.warning('Error in while loop while getting authentication logs- {}'.format(ex))
                if ex.status == 429:
                    logging.info('429 exception occurred, trying retry after 60 seconds')
                    time.sleep(60)
                    response = self.admin_api.get_authentication_log(api_version=2, mintime=mintime, maxtime=maxtime,
                                                                     limit=str(limit), sort='ts:asc',
                                                                     next_offset=next_offset)

            if response is not None:
                events = response['authlogs']
                logging.info('Obtained {} auth events'.format(len(events)))
            else:
                logging.info('returned response as Null')

            for event in events:
                self.sentinel.send(event)
            self.sentinel.flush()

            logging.info('Saving auth logs last timestamp {}'.format(maxtime))
            self.state_manager.post(str(maxtime))

            if check_if_script_runs_too_long(start_ts):
                logging.info('Script is running too long. Saving progress and exit.')
                return
