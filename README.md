# ssl-audit
SSL/HTTPS Audit – report similar to SSL Labs

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Build](https://img.shields.io/badge/build-passing-success.svg)]()

A lightweight Python tool for scanning HTTPS/TLS configuration — similar in spirit to SSL Labs, but fast and self-hosted.  
It checks supported TLS versions, certificate details, HTTP headers (HSTS), OCSP stapling, ALPN/HTTP2, and CAA records.

---

## 🚀 Features
- Detects supported TLS versions (1.0–1.3)
- Extracts certificate info (CN, SAN, issuer, validity, signature algorithm)
- Checks HSTS, HTTP/2, ALPN, and OCSP stapling
- Verifies weak/strong cipher support
- Assigns a simple A+–F grade based on security level

---

## 🧩 Usage

### Local run
```bash
python ssl_audit.py example.com --port 443

### Docker
```bash
docker build -t ssl-audit .
docker run --rm ssl-audit example.com --port 443
