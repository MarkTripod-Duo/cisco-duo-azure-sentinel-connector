"""
Cisco Duo Trust Monitor Log class and methods
"""
from __future__ import annotations
import math
import time
import logging
from singleton import Singleton
from main import MAX_SYNC_WINDOW_PER_RUN_MINUTES
from base import DuoLogBase


class TrustMonitorLog(DuoLogBase, metaclass=Singleton):
    """Cisco Duo Trust Monitor Log class and methods"""

    def process_trust_monitor_events(self) -> None:
        """Process Trust Monitor events."""
        logging.info('Start processing trust_monitor logs')

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
            logging.warning('Ingestion is lagging for trust_monitor logs, limiting synchronization window to {}'.format(
                max_window))

        logging.info('Making trust_monitor logs request: mintime={}, maxtime={}'.format(mintime, maxtime))
        for event in self.admin_api.get_trust_monitor_events_iterator(mintime=mintime, maxtime=maxtime):
            self.sentinel.send(event)
        self.sentinel.flush()

        logging.info('Saving trust_monitor logs last timestamp {}'.format(maxtime))
        self.state_manager.post(str(maxtime))
