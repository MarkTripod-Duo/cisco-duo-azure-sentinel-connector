"""
Base class for the Cisco Duo Admin API log extraction endpoints
"""
from __future__ import annotations
import math
import time
import logging
from singleton import Singleton
from main import check_if_script_runs_too_long, MAX_SYNC_WINDOW_PER_RUN_MINUTES
from sentinel_connector import AzureSentinelConnector
from state_manager import StateManager


class DuoException(Exception):
    """Cisco Duo Exception for capturing rate limit responses"""
    status: int
    pass


class DuoLogBase:
    """Base Cisco Duo Admin API log extraction endpoint template"""

    def __init__(self, admin_api: duo_client.Admin, state_manager: StateManager, sentinel: AzureSentinelConnector, ):
        """Initialize the Activity Log class"""
        self.admin_api = admin_api
        self.state_manager = state_manager
        self.sentinel = sentinel

