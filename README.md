# OSINT Threat Analyzer

![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6?logo=typescript&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-High%20Performance-009688?logo=fastapi&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-In--Memory%20Cache-DC382D?logo=redis&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Persistence-4169E1?logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED?logo=docker&logoColor=white)

[🇷🇺 Читать на русском](README_RU.md)

**OSINT Threat Analyzer** is a high-throughput asynchronous threat intelligence microservice and interactive reconnaissance platform engineered with **TypeScript**, **FastAPI (Python 3.12)**, **Redis**, and **PostgreSQL (SQLAlchemy 2.0)**.

It automates SOC and security investigations across **IPv4 addresses**, **domains**, and **email identities**. Instead of manual lookups, the engine queries multiple distributed intelligence feeds concurrently:
- **Shodan InternetDB:** Passive port enumeration, service fingerprinting, CPEs, and known CVE vulnerability correlation.
- **AlienVault OTX:** Active threat pulse correlation and global indicator reputation.
- **IP-API BGP/ASN Telemetry:** Autonomous System Number (ASN) lookup, ISP attribution, reverse PTR, and proxy/VPN/datacenter detection.
- **HaveIBeenPwned (HIBP):** Credential breach exposure reconnaissance for email identities.

### Key Architectural Highlights
- **Strict TypeScript Frontend Suite (frontend/src/):** Modular client-side architecture featuring automatic IOC defanging/refanging, RFC 1918 private network guards, 3-pillar risk correlation matrices, interactive history filtering, and instant report export to **JSON**, **CSV**, and **Markdown**.
- **Asynchronous FastAPI Core:** Non-blocking I/O pipeline with async DNS resolution to correlate domain names directly against IP-indexed vulnerability databases.
- **Resilient Caching & Persistence:** Sub-millisecond Redis response caching with automatic graceful fallback and tuned SQLAlchemy 2.0 async connection pooling.
- **Hardened Infrastructure:** Containerized via Docker Compose behind Nginx with rate limiting and isolated internal networks.