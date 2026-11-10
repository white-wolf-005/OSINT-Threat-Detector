import asyncio
import os
import re
import socket
from typing import Any

import aiohttp

from src.core.logger import setup_logger

logger = setup_logger("osint.engine")


class OSINTScanner:
    def __init__(self) -> None:
        self.ip_api_url: str = "http://ip-api.com/json/"
        self.ip_api_fields: str = (
            "status,message,country,countryCode,regionName,city,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
        )
        self.shodan_idb_url: str = "https://internetdb.shodan.io/"
        self.hibp_url: str = "https://haveibeenpwned.com/api/v3/breachedaccount/"
        self.otx_url: str = "https://otx.alienvault.com/api/v1/indicators/"
        self.hibp_key: str = os.getenv("HIBP_API_KEY", "").strip()
        self.otx_key: str = os.getenv("OTX_API_KEY", "").strip()

    def classify_target(self, target: str) -> str:
        ip_pattern: re.Pattern[str] = re.compile(
            r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
        )
        email_pattern: re.Pattern[str] = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$")

        if ip_pattern.match(target):
            return "IPv4"
        if email_pattern.match(target):
            return "email"
        return "domain"

    async def resolve_domain_to_ip(self, target: str) -> str | None:
        try:
            loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
            addr_info: list[Any] = await asyncio.wait_for(
                loop.getaddrinfo(target, None, family=socket.AF_INET),
                timeout=4.0,
            )
            if addr_info:
                resolved_ip: str = str(addr_info[0][4][0])
                logger.info(f"Resolved domain {target} to IPv4 {resolved_ip}")
                return resolved_ip
        except Exception:
            logger.warning(f"DNS resolution failed for domain: {target}")
        return None

    async def fetch_ip_info(self, session: aiohttp.ClientSession, target: str) -> dict[str, Any]:
        url: str = f"{self.ip_api_url}{target}?fields={self.ip_api_fields}"
        try:
            timeout: aiohttp.ClientTimeout = aiohttp.ClientTimeout(total=6)
            async with session.get(url, timeout=timeout) as response:
                if response.status == 200:
                    data: dict[str, Any] = await response.json()
                    if data.get("status") == "success":
                        return {"source": "IP-API", "data": data, "error": None}
                    return {
                        "source": "IP-API",
                        "data": None,
                        "error": str(data.get("message", "Lookup unsuccessful")),
                    }
        except asyncio.TimeoutError:
            logger.warning(f"Timeout connecting to IP-API for target: {target}")
            return {"source": "IP-API", "data": None, "error": "Connection timeout"}
        except Exception:
            logger.error(f"IP-API request failed for target: {target}", exc_info=True)
        return {"source": "IP-API", "data": None, "error": "Request failed"}

    async def fetch_shodan_info(self, session: aiohttp.ClientSession, ip_target: str | None) -> dict[str, Any]:
        if not ip_target:
            return {"source": "Shodan IDB", "data": None, "error": "Unable to resolve IPv4 for Shodan lookup"}

        try:
            timeout: aiohttp.ClientTimeout = aiohttp.ClientTimeout(total=6)
            async with session.get(f"{self.shodan_idb_url}{ip_target}", timeout=timeout) as response:
                if response.status == 200:
                    raw_data: dict[str, Any] = await response.json()
                    normalized_data: dict[str, Any] = {
                        "ip": raw_data.get("ip", ip_target),
                        "ports": raw_data.get("ports") or [],
                        "vulns": raw_data.get("vulns") or [],
                        "hostnames": raw_data.get("hostnames") or [],
                        "cpes": raw_data.get("cpes") or [],
                        "tags": raw_data.get("tags") or [],
                    }
                    return {"source": "Shodan IDB", "data": normalized_data, "error": None}
                if response.status == 404:
                    return {
                        "source": "Shodan IDB",
                        "data": {
                            "ip": ip_target,
                            "ports": [],
                            "vulns": [],
                            "hostnames": [],
                            "cpes": [],
                            "tags": [],
                        },
                        "error": None,
                    }
        except asyncio.TimeoutError:
            logger.warning(f"Timeout connecting to Shodan IDB for IP: {ip_target}")
            return {"source": "Shodan IDB", "data": None, "error": "Connection timeout"}
        except Exception:
            logger.error(f"Shodan IDB request failed for IP: {ip_target}", exc_info=True)
        return {"source": "Shodan IDB", "data": None, "error": "Request failed"}

    async def fetch_hibp_leaks(self, session: aiohttp.ClientSession, target: str) -> dict[str, Any]:
        if not self.hibp_key:
            return {"source": "HaveIBeenPwned", "data": None, "error": "Missing HIBP_API_KEY in .env"}

        headers: dict[str, str] = {
            "hibp-api-key": self.hibp_key,
            "user-agent": "OSINT-Threat-Intelligence-Engine",
        }
        try:
            timeout: aiohttp.ClientTimeout = aiohttp.ClientTimeout(total=6)
            url: str = f"{self.hibp_url}{target}?truncateResponse=false"
            async with session.get(url, headers=headers, timeout=timeout) as response:
                if response.status == 200:
                    breaches: list[dict[str, Any]] = await response.json()
                    return {"source": "HaveIBeenPwned", "data": breaches, "error": None}
                if response.status == 404:
                    return {"source": "HaveIBeenPwned", "data": [], "error": None}
                if response.status == 401:
                    return {"source": "HaveIBeenPwned", "data": None, "error": "Invalid HIBP API Key"}
        except asyncio.TimeoutError:
            logger.warning(f"Timeout connecting to HIBP for target: {target}")
            return {"source": "HaveIBeenPwned", "data": None, "error": "Connection timeout"}
        except Exception:
            logger.error(f"HIBP request failed for target: {target}", exc_info=True)
        return {"source": "HaveIBeenPwned", "data": None, "error": "Request failed"}

    async def fetch_otx_threats(
        self,
        session: aiohttp.ClientSession,
        target: str,
        target_type: str,
    ) -> dict[str, Any]:
        headers: dict[str, str] = {"User-Agent": "OSINT-Threat-Intelligence-Engine"}
        if self.otx_key:
            headers["X-OTX-API-KEY"] = self.otx_key

        otx_section: str = "IPv4" if target_type == "IPv4" else "domain"
        url: str = f"{self.otx_url}{otx_section}/{target}/general"

        try:
            timeout: aiohttp.ClientTimeout = aiohttp.ClientTimeout(total=6)
            async with session.get(url, headers=headers, timeout=timeout) as response:
                if response.status == 200:
                    data: dict[str, Any] = await response.json()
                    pulse_info: dict[str, Any] = data.get("pulse_info") or {}
                    pulse_count: int = int(pulse_info.get("count", 0))
                    pulses_list: list[dict[str, Any]] = pulse_info.get("pulses") or []
                    pulse_names: list[str] = [
                        str(p.get("name")) for p in pulses_list[:5] if p.get("name")
                    ]
                    reputation: int = int(data.get("reputation") or 0)
                    return {
                        "source": "AlienVault OTX",
                        "data": {
                            "pulses_found": pulse_count,
                            "reputation": reputation,
                            "recent_pulses": pulse_names,
                            "country": data.get("country_name"),
                            "asn": data.get("asn"),
                        },
                        "error": None,
                    }
                if response.status == 401:
                    return {"source": "AlienVault OTX", "data": None, "error": "Invalid OTX API Key"}
                if response.status == 404:
                    return {
                        "source": "AlienVault OTX",
                        "data": {"pulses_found": 0, "reputation": 0, "recent_pulses": []},
                        "error": None,
                    }
        except asyncio.TimeoutError:
            logger.warning(f"Timeout connecting to AlienVault OTX for target: {target}")
            return {"source": "AlienVault OTX", "data": None, "error": "Connection timeout"}
        except Exception:
            logger.error(f"AlienVault OTX request failed for target: {target}", exc_info=True)
        return {"source": "AlienVault OTX", "data": None, "error": "Request failed"}

    def _calculate_risk_level(self, score: int) -> str:
        if score >= 75:
            return "CRITICAL"
        if score >= 45:
            return "HIGH"
        if score >= 20:
            return "MEDIUM"
        return "LOW"

    async def analyze(self, session: aiohttp.ClientSession, target: str) -> dict[str, Any]:
        clean_target: str = target.strip().lower()
        target_type: str = self.classify_target(clean_target)
        resolved_ip: str | None = clean_target if target_type == "IPv4" else None

        if target_type == "domain":
            resolved_ip = await self.resolve_domain_to_ip(clean_target)

        tasks: list[Any] = []
        if target_type == "email":
            tasks.append(self.fetch_hibp_leaks(session, clean_target))
        else:
            tasks.append(self.fetch_ip_info(session, resolved_ip or clean_target))
            tasks.append(self.fetch_shodan_info(session, resolved_ip))
            tasks.append(self.fetch_otx_threats(session, clean_target, target_type))

        raw_results: list[Any] = await asyncio.gather(*tasks, return_exceptions=True)

        threat_score: int = 0
        normalized_results: list[dict[str, Any]] = []

        for res in raw_results:
            if isinstance(res, dict):
                normalized_results.append(res)
                if res.get("error") is None and isinstance(res.get("data"), (dict, list)):
                    source_name: str = str(res.get("source", ""))
                    source_data: Any = res["data"]

                    if source_name == "AlienVault OTX" and isinstance(source_data, dict):
                        pulses: int = int(source_data.get("pulses_found", 0))
                        threat_score += min(pulses * 8, 45)

                    elif source_name == "HaveIBeenPwned" and isinstance(source_data, list):
                        breaches_count: int = len(source_data)
                        threat_score += min(breaches_count * 15, 90)

                    elif source_name == "Shodan IDB" and isinstance(source_data, dict):
                        ports: list[int] = source_data.get("ports") or []
                        vulns: list[str] = source_data.get("vulns") or []
                        high_risk_ports: set[int] = {21, 22, 23, 445, 1433, 3306, 3389, 5432, 6379, 27017}
                        exposed_risk_ports: set[int] = set(ports).intersection(high_risk_ports)
                        if exposed_risk_ports:
                            threat_score += min(len(exposed_risk_ports) * 15, 45)
                        if vulns:
                            threat_score += min(len(vulns) * 12, 50)

                    elif source_name == "IP-API" and isinstance(source_data, dict):
                        if source_data.get("proxy"):
                            threat_score += 20
                        if source_data.get("hosting"):
                            threat_score += 10
            else:
                normalized_results.append({"source": "Unknown", "data": None, "error": str(res)})

        bounded_score: int = min(threat_score, 100)
        risk_level: str = self._calculate_risk_level(bounded_score)

        return {
            "target": clean_target,
            "resolved_ip": resolved_ip,
            "type": target_type,
            "threat_score": bounded_score,
            "risk_level": risk_level,
            "sources_checked": len(tasks),
            "results": normalized_results,
        }