"""Connectors package for RedAgent."""
from redagent.connectors.base import BaseTargetConnector, TargetResponse
from redagent.connectors.callable import CallableTargetConnector
from redagent.connectors.mock import MockTargetConnector
from redagent.connectors.rest import RestTargetConnector

__all__ = [
    "BaseTargetConnector",
    "TargetResponse",
    "RestTargetConnector",
    "MockTargetConnector",
    "CallableTargetConnector",
]
