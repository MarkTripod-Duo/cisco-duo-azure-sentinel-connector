"""
Singleton metaclass definition
"""
from __future__ import annotations

__all__ = ['Singleton']


class Singleton(type):
    """Singleton metaclass definition to be used to ensure singleton Cisco Duo Log endpoint instances are created."""
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]
