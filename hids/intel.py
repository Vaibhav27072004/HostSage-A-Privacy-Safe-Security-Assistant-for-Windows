from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from hids.config import ThreatIntelConfig
from hids.models import ThreatIntelRecord
from hids.parser import is_public_ip


def classify_risk(score: int) -> str:
    if score >= 75:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


@dataclass
class CachedIntel:
    record: ThreatIntelRecord
    expires_at: float


def _fetch_json(request: urllib.request.Request, timeout_seconds: int, max_retries: int) -> dict[str, object]:
    attempts = max(1, max_retries + 1)
    last_error: Exception | None = None

    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt == attempts - 1:
                break
            time.sleep(min(2**attempt, 2))

    raise RuntimeError(str(last_error) if last_error else "Unknown threat-intel error")


class BaseIntelProvider:
    provider_name = "disabled"

    def __init__(self, timeout_seconds: int, max_retries: int) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    def lookup(self, ip_address: str) -> ThreatIntelRecord:
        raise NotImplementedError


class AbuseIPDBProvider(BaseIntelProvider):
    provider_name = "abuseipdb"

    def __init__(self, api_key: str, timeout_seconds: int, max_retries: int) -> None:
        super().__init__(timeout_seconds=timeout_seconds, max_retries=max_retries)
        self.api_key = api_key.strip()

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def lookup(self, ip_address: str) -> ThreatIntelRecord:
        if not self.enabled:
            return ThreatIntelRecord(
                ip=ip_address,
                provider=self.provider_name,
                risk_label="LOW",
                risk_score=0,
                summary="AbuseIPDB API key not configured.",
            )

        query = urllib.parse.urlencode({"ipAddress": ip_address, "maxAgeInDays": 90})
        request = urllib.request.Request(
            f"https://api.abuseipdb.com/api/v2/check?{query}",
            headers={
                "Key": self.api_key,
                "Accept": "application/json",
                "User-Agent": "hostsage/1.0",
            },
            method="GET",
        )

        try:
            payload = _fetch_json(request, self.timeout_seconds, self.max_retries)
        except RuntimeError as exc:
            return ThreatIntelRecord(
                ip=ip_address,
                provider=self.provider_name,
                risk_label="LOW",
                risk_score=0,
                summary=f"AbuseIPDB lookup failed: {exc}",
            )

        data = payload.get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
        reports = int(data.get("totalReports", 0))
        country = data.get("countryCode", "unknown")
        return ThreatIntelRecord(
            ip=ip_address,
            provider=self.provider_name,
            risk_label=classify_risk(score),
            risk_score=score,
            summary=f"AbuseIPDB score={score}, reports={reports}, country={country}",
            raw=data,
        )


class VirusTotalProvider(BaseIntelProvider):
    provider_name = "virustotal"

    def __init__(self, api_key: str, timeout_seconds: int, max_retries: int) -> None:
        super().__init__(timeout_seconds=timeout_seconds, max_retries=max_retries)
        self.api_key = api_key.strip()

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def lookup(self, ip_address: str) -> ThreatIntelRecord:
        if not self.enabled:
            return ThreatIntelRecord(
                ip=ip_address,
                provider=self.provider_name,
                risk_label="LOW",
                risk_score=0,
                summary="VirusTotal API key not configured.",
            )

        request = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(ip_address)}",
            headers={
                "x-apikey": self.api_key,
                "Accept": "application/json",
                "User-Agent": "hostsage/1.0",
            },
            method="GET",
        )

        try:
            payload = _fetch_json(request, self.timeout_seconds, self.max_retries)
        except RuntimeError as exc:
            return ThreatIntelRecord(
                ip=ip_address,
                provider=self.provider_name,
                risk_label="LOW",
                risk_score=0,
                summary=f"VirusTotal lookup failed: {exc}",
            )

        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))

        if malicious > 0:
            score = min(100, 80 + malicious)
        elif suspicious > 0:
            score = min(100, 50 + (suspicious * 5))
        else:
            score = 5 if harmless > 0 else 0

        return ThreatIntelRecord(
            ip=ip_address,
            provider=self.provider_name,
            risk_label=classify_risk(score),
            risk_score=score,
            summary=f"VirusTotal malicious={malicious}, suspicious={suspicious}, harmless={harmless}",
            raw=payload.get("data", {}),
        )


class ThreatIntelClient:
    def __init__(self, config: ThreatIntelConfig) -> None:
        self._providers: list[BaseIntelProvider] = [
            AbuseIPDBProvider(config.abuseipdb_api_key, config.timeout_seconds, config.max_retries),
            VirusTotalProvider(config.virustotal_api_key, config.timeout_seconds, config.max_retries),
        ]
        self._cache_ttl_seconds = config.cache_ttl_seconds
        self._cache: dict[str, CachedIntel] = {}

    def lookup(self, ip_address: str) -> ThreatIntelRecord:
        if not is_public_ip(ip_address):
            return ThreatIntelRecord(
                ip=ip_address,
                provider="local",
                risk_label="LOW",
                risk_score=0,
                summary="Private or non-routable address.",
            )

        cached = self._cache.get(ip_address)
        now = time.time()
        if cached and cached.expires_at > now:
            return cached.record

        enabled_providers = [provider for provider in self._providers if getattr(provider, "enabled", False)]
        if not enabled_providers:
            record = ThreatIntelRecord(
                ip=ip_address,
                provider="disabled",
                risk_label="LOW",
                risk_score=0,
                summary="Threat intelligence disabled. Configure AbuseIPDB or VirusTotal API keys to enrich alerts.",
            )
            self._cache[ip_address] = CachedIntel(record=record, expires_at=now + self._cache_ttl_seconds)
            return record

        results = [provider.lookup(ip_address) for provider in enabled_providers]
        best_result = max(results, key=lambda record: record.risk_score)
        self._cache[ip_address] = CachedIntel(record=best_result, expires_at=now + self._cache_ttl_seconds)
        return best_result
