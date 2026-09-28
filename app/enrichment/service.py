"""Enrichment service: domain reputation, geolocation and DNS-answer correlation."""

from __future__ import annotations

import logging

from app.core.netutils import is_public_address
from app.enrichment.blocklist import DomainReputation
from app.enrichment.dns_cache import ResolutionCache
from app.enrichment.geo import GeoLocator
from app.models.events import DomainSource, NetworkEvent, PacketType
from app.models.processed import Enrichment

logger = logging.getLogger(__name__)


class EnrichmentService:
    """Adds metadata to events. Pure with respect to I/O (all lookups are local)."""

    def __init__(
        self,
        reputation: DomainReputation,
        geolocator: GeoLocator,
        resolution_cache: ResolutionCache,
    ) -> None:
        self._reputation = reputation
        self._geo = geolocator
        self._cache = resolution_cache

    def observe_dns_response(self, event: NetworkEvent) -> None:
        """Remember ``answer IP → queried domain`` from a DNS response."""
        if event.packet_type is not PacketType.DNS_RESPONSE or not event.domain:
            return
        for answer in event.dns_answers:
            self._cache.put(answer, event.domain, event.timestamp)

    def enrich(self, event: NetworkEvent) -> Enrichment:
        domain = event.domain
        source: DomainSource | None = DomainSource.DNS_QUERY if domain else None
        if domain is None and event.packet_type is PacketType.TCP_SYN:
            domain = self._cache.get(event.destination_ip, event.timestamp)
            if domain is not None:
                source = DomainSource.DNS_CACHE
        return Enrichment(
            country=self._locate(event.destination_ip),
            domain=domain,
            domain_source=source,
            blocklist_match=self._reputation.match(domain) if domain else None,
            destination_is_public=is_public_address(event.destination_ip),
        )

    def _locate(self, ip: str) -> str | None:
        try:
            return self._geo.locate(ip)
        except Exception:  # a broken plug-in geolocator must not stop the pipeline
            logger.exception("Geolocation failed")
            return None
