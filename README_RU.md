# OSINT Threat Analyzer

![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6?logo=typescript&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-High%20Performance-009688?logo=fastapi&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-In--Memory%20Cache-DC382D?logo=redis&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Persistence-4169E1?logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED?logo=docker&logoColor=white)

[🇬🇧 Read in English](README.md)

**OSINT Threat Analyzer** — высокопроизводительный асинхронный микросервис киберразведки (Threat Intelligence) и интерактивный аналитический дашборд, разработанный на **TypeScript**, **FastAPI (Python 3.12)**, **Redis** и **PostgreSQL (SQLAlchemy 2.0)**.

Система автоматизирует расследования инцидентов информационной безопасности по **IPv4-адресам**, **доменам** и **email-адресам**, параллельно опрашивая несколько источников:
- **Shodan InternetDB:** пассивное сканирование открытых портов, определение сервисов и привязанных уязвимостей (CVE).
- **AlienVault OTX:** проверка индикаторов компрометации (IOC) по базам пульсов угроз.
- **IP-API BGP/ASN Телеметрия:** определение автономной системы (ASN), провайдера, гео-локации, PTR-записей и детект прокси/VPN/хостингов.
- **HaveIBeenPwned (HIBP):** проверка утечек учетных данных по email.

### Архитектурные особенности
- **Модульный фронтенд на строгом TypeScript (frontend/src/):** автоматический рефангинг IOC-индикаторов, блокировка локальных адресов RFC 1918, трехфакторная матрица оценки риска, фильтрация истории и экспорт отчетов в **JSON**, **CSV** и **Markdown**.
- **Асинхронное ядро FastAPI:** неблокирующие запросы с предварительным асинхронным DNS-резолвингом доменов для полного обогащения через Shodan IDB.
- **Отказоустойчивость:** кэширование в Redis с автоматическим фоллбэком (работает даже при отключенном Redis) и настроенный пул соединений SQLAlchemy 2.0.
- **Защита и изоляция:** полная контейнеризация в Docker с Nginx, защитой от DDoS (Rate Limiting) и закрытыми внутренними портами БД.