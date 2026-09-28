"""Ingestion layer: packet capture, parsing, demo traffic and event forwarding.

Modules that depend on Scapy (``parser``, ``capture``, ``demo``, ``daemon``)
are imported lazily by their callers so that the API can start without
loading Scapy.
"""

from app.ingestion.queue import EventQueue, QueueStats
from app.ingestion.sources import EventSink, EventSource, SourceStatus

__all__ = ["EventQueue", "EventSink", "EventSource", "QueueStats", "SourceStatus"]
