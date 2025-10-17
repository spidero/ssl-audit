#!/usr/bin/env python3
from __future__ import print_function, annotations
"""
SSL Audit – minimal TLS/HTTPS scanner (inspired by SSL Labs style)

Usage:
  python ssl_audit.py example.com --port 443

Optional dependencies (for richer report):
  pip install cryptography pyopenssl dnspython httpx
"""

import argparse
import socket
import ssl
import sys
import datetime as dt
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ---------------- Utility ----------------

def eprint(*args):
    """Safe stderr output, also on older interpreters."""
    try:
        sys.stderr.write(" ".join(str(a) for a in args) + "\n")
    except Exception:
        pass

# Optional deps
try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
except Exception:
    x509 = None  # type: ignore
    rsa = None   # type: ignore
    ec = None    # type: ignore

try:
    import OpenSSL  # type: ignore
except Exception:
    OpenSSL = None  # type: ignore

try:
    import dns.resolver  # type: ignore
except Exception:
    dns = None  # type: ignore

try:
    import httpx  # type: ignore
except Exception:
    httpx = None  # type: ignore

# ---------------- Data model ----------------

@dataclass
class Finding:
    level: str  # INFO/WARN/FAIL
    message: str

@dataclass
class Report:
    host: str
    port: int
    ip: Optional[str] = None
    tls_versions: List[str] = field(default_factory=list)
    alpn: List[str] = field(default_factory=list)
    http2_ok: Optional[bool] = None
    hsts: Optional[str] = None
    status_code: Optional[int] = None
    server_header: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_san: List[str] = field(default_factory=list)
    cert_issuer: Optional[str] = None
    cert_not_before: Optional[dt.datetime] = None
    cert_not_after: Optional[dt.datetime] = None
    cert_sig_alg: Optional[str] = None
    cert_pubkey: Optional[str] = None
    chain_len: Optional[int] = None
    ocsp_stapling: Optional[bool] = None
    caa: List[str] = field(default_factory=list)
    weak_dhe_supported: Optional[bool] = None
    strong_ecdhe_supported: Optional[bool] = None
    # Enumerated ciphers per TLS version
    tls12_ciphers: List[str] = field(default_factory=list)
    tls13_ciphers: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    def add(self, level: str, msg: str):
        self.findings.append(Finding(level, msg))

# ---------------- Core helpers ----------------

def resolve_ip(host: str) -> str:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    for fam, _, _, _, sa in infos:
        if fam == socket.AF_INET:
            return sa[0]
    return infos[0][4][0]

def try_handshake(host: str, port: int,
                  minver: 'ssl.TLSVersion', maxver: 'ssl.TLSVersion',
                  ciphers: Optional[str] = None,
                  alpn: Optional[List[str]] = None) -> Tuple[bool, Optional[str]]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = minver
    ctx.maximum_version = maxver
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if ciphers:
        try:
            ctx.set_ciphers(ciphers)
        except Exception:
            pass
    if alpn:
        try:
            ctx.set_alpn_protocols(alpn)
        except Exception:
            pass
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return True, ssock.selected_alpn_protocol()
    except Exception:
        return False, None

def fetch_http_headers(host: str, port: int) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """Simple GET / to capture response headers (HTTP/1.1)."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                req = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Connection: close\r\n"
                    f"User-Agent: ssl-audit/1.1\r\n\r\n"
                ).encode()
                ssock.sendall(req)
                raw = b""
                while True:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
        header_blob = raw.split(b"\r\n\r\n", 1)[0].decode(errors="ignore")
        lines = header_blob.split("\r\n")
        status = None
        server = None
        hsts = None
        if lines:
            first = lines[0]
            try:
                status = int(first.split()[1])
            except Exception:
                pass
        for line in lines[1:]:
            k, _, v = line.partition(":")
            if not v:
                continue
            lk = k.lower()
            if lk == "server":
                server = v.strip()
            if lk == "strict-transport-security":
                hsts = v.strip()
        return status, server, hsts
    except Exception:
        return None, None, None

def parse_cert_with_stdlib(host: str, port: int) -> Tuple[Optional[dict], Optional[bytes]]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()
                return cert, der
    except Exception:
        return None, None

def enrich_cert_with_crypto(rep: Report, der: bytes):
    if not x509 or not der:
        return
    cert = x509.load_der_x509_certificate(der)
    # signature
    try:
        rep.cert_sig_alg = cert.signature_hash_algorithm.name  # type: ignore[attr-defined]
    except Exception:
        rep.cert_sig_alg = None
    # public key
    try:
        pub = cert.public_key()
        if rsa and isinstance(pub, rsa.RSAPublicKey):  # type: ignore[attr-defined]
            rep.cert_pubkey = f"RSA {pub.key_size} bits"
        elif ec and isinstance(pub, ec.EllipticCurvePublicKey):  # type: ignore[attr-defined]
            rep.cert_pubkey = f"EC {pub.curve.name}"
        else:
            rep.cert_pubkey = pub.__class__.__name__
    except Exception:
        rep.cert_pubkey = None

def get_chain_and_ocsp_with_pyopenssl(host: str, port: int) -> Tuple[Optional[int], Optional[bool]]:
    if not OpenSSL:
        return None, None
    try:
        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLS_CLIENT_METHOD)
        ctx.set_verify(OpenSSL.SSL.VERIFY_NONE, lambda *args: True)
        sock = socket.create_connection((host, port), timeout=6)
        conn = OpenSSL.SSL.Connection(ctx, sock)
        conn.set_tlsext_host_name(host.encode())
        try:
            conn.request_ocsp()
        except Exception:
            pass
        conn.set_connect_state()
        conn.do_handshake()
        chain = conn.get_peer_cert_chain() or []
        ocsp = False
        try:
            ocsp = bool(conn.get_ocsp_response())
        except Exception:
            pass
        try:
            conn.shutdown()
        except Exception:
            pass
        conn.close()
        sock.close()
        return len(chain), ocsp
    except Exception:
        return None, None

def query_caa(host: str) -> List[str]:
    out: List[str] = []
    if dns is None:
        return out
    try:
        answers = dns.resolver.resolve(host, 'CAA')
        for r in answers:  # type: ignore
            out.append(str(r))
    except Exception:
        parts = host.split('.')
        for i in range(1, len(parts)):
            zone = '.'.join(parts[i:])
            try:
                answers = dns.resolver.resolve(zone, 'CAA')
                for r in answers:  # type: ignore
                    out.append(f"{zone}: {r}")
                break
            except Exception:
                continue
    return out

# ---------------- Cipher enumeration ----------------

# Reasonable TLS 1.2 cipher candidates (extend as needed)
TLS12_CANDIDATES = [
    # AEAD GCM suites
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES128-GCM-SHA256',
    # ChaCha20 (if OpenSSL supports)
    'ECDHE-ECDSA-CHACHA20-POLY1305',
    'ECDHE-RSA-CHACHA20-POLY1305',
    # CBC fallbacks (not recommended, but checked)
    'ECDHE-RSA-AES256-SHA384',
    'ECDHE-RSA-AES128-SHA256',
]

# TLS 1.3 cipher candidates (names per RFC; controlled via set_ciphersuites)
TLS13_CANDIDATES = [
    'TLS_AES_256_GCM_SHA384',
    'TLS_AES_128_GCM_SHA256',
    'TLS_CHACHA20_POLY1305_SHA256',
]

def enumerate_ciphers(host: str, port: int) -> tuple[list[str], list[str]]:
    """Probe which ciphers the server accepts for TLS 1.2 and TLS 1.3.
    Returns (tls12_supported, tls13_supported)."""
    tls12_ok: list[str] = []
    tls13_ok: list[str] = []

    # TLS 1.2: force a single cipher each time
    for name in TLS12_CANDIDATES:
        ok, _ = try_handshake(host, port,
                              ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2,
                              ciphers=name)
        if ok:
            tls12_ok.append(name)

    # TLS 1.3: prefer limiting via set_ciphersuites, else record negotiated
    try:
        for name in TLS13_CANDIDATES:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_ciphersuites(name)  # type: ignore[attr-defined]
            except Exception:
                pass
            try:
                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        sel = ssock.cipher()  # (name, proto, bits)
                        if sel and sel[0] and sel[0] not in tls13_ok:
                            tls13_ok.append(sel[0])
            except Exception:
                continue
    except Exception:
        pass

    return tls12_ok, tls13_ok

# ---------------- Runner ----------------

def run(host: str, port: int) -> Report:
    rep = Report(host=host, port=port)
    try:
        rep.ip = resolve_ip(host)
    except Exception:
        rep.ip = None

    # TLS versions support tests
    tests = [
        ('TLS1.0', ssl.TLSVersion.TLSv1),
        ('TLS1.1', ssl.TLSVersion.TLSv1_1),
        ('TLS1.2', ssl.TLSVersion.TLSv1_2),
        ('TLS1.3', ssl.TLSVersion.TLSv1_3),
    ]
    for name, ver in tests:
        ok, _ = try_handshake(host, port, ver, ver)
        if ok:
            rep.tls_versions.append(name)

    # ALPN probing
    for proto in ['h2', 'http/1.1']:
        ok, selected = try_handshake(host, port,
                                     ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.MAXIMUM_SUPPORTED,
                                     alpn=[proto])
        if ok and selected == proto:
            rep.alpn.append(proto)

    # HTTP/2 validation (if httpx present)
    if httpx is not None and 'h2' in rep.alpn:
        try:
            with httpx.Client(http2=True, verify=True, timeout=5.0) as client:
                r = client.get(f"https://{host}:{port}/")
                rep.http2_ok = (r.http_version == 'HTTP/2')
        except Exception:
            rep.http2_ok = False

    # Headers
    rep.status_code, rep.server_header, rep.hsts = fetch_http_headers(host, port)

    # Certificate (stdlib)
    cert_dict, der = parse_cert_with_stdlib(host, port)
    if cert_dict:
        # subject CN
        subj = cert_dict.get('subject', ())
        cn = None
        for rdn in subj:
            for k, v in rdn:
                if k == 'commonName':
                    cn = v
        rep.cert_subject = cn
        # SAN
        san = cert_dict.get('subjectAltName', ())
        rep.cert_san = [v for (t, v) in san if t == 'DNS']
        # issuer
        iss = cert_dict.get('issuer', ())
        issuer_cn = None
        for rdn in iss:
            for k, v in rdn:
                if k == 'commonName':
                    issuer_cn = v
        rep.cert_issuer = issuer_cn
        # validity
        try:
            from datetime import datetime
            fmt = '%b %d %H:%M:%S %Y %Z'
            rep.cert_not_before = datetime.strptime(cert_dict['notBefore'], fmt)
            rep.cert_not_after = datetime.strptime(cert_dict['notAfter'], fmt)
        except Exception:
            pass

    if der:
        enrich_cert_with_crypto(rep, der)

    # Chain & OCSP (pyOpenSSL)
    rep.chain_len, rep.ocsp_stapling = get_chain_and_ocsp_with_pyopenssl(host, port)

    # CAA
    rep.caa = query_caa(host)

    # Cipher spot checks
    weak_dhe = 'DHE-RSA-AES256-SHA'
    ok, _ = try_handshake(host, port, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2, ciphers=weak_dhe)
    rep.weak_dhe_supported = ok

    strong = 'ECDHE-RSA-AES128-GCM-SHA256'
    ok, _ = try_handshake(host, port, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2, ciphers=strong)
    rep.strong_ecdhe_supported = ok

    # Full cipher enumeration (always collected now)
    rep.tls12_ciphers, rep.tls13_ciphers = enumerate_ciphers(host, port)

    return rep

# ---------------- Output ----------------

def print_report(rep: Report):
    print("="*68)
    print(f"SSL Audit for {rep.host}:{rep.port}  (IP: {rep.ip or '?'} )")
    print("="*68)

    print("[TLS]")
    print(f"  TLS versions: {', '.join(rep.tls_versions) or 'none'}")
    print(f"  ALPN: {', '.join(rep.alpn) or 'none'}  | HTTP/2 supported: {rep.http2_ok}")
    print(f"  Weak DHE accepted: {rep.weak_dhe_supported} | Strong ECDHE accepted: {rep.strong_ecdhe_supported}")
    if rep.tls12_ciphers:
        print(f"  TLS 1.2 ciphers accepted ({len(rep.tls12_ciphers)}): {', '.join(rep.tls12_ciphers)}")
    if rep.tls13_ciphers:
        print(f"  TLS 1.3 ciphers accepted ({len(rep.tls13_ciphers)}): {', '.join(rep.tls13_ciphers)}")
    print()

    print("[HTTP]")
    print(f"  GET / -> status: {rep.status_code} | Server: {rep.server_header} | HSTS: {rep.hsts}")
    print()

    print("[Certificate]")
    print(f"  Subject CN: {rep.cert_subject}")
    if rep.cert_san:
        print(f"  SAN: {', '.join(rep.cert_san)}")
    print(f"  Issuer: {rep.cert_issuer}")
    if rep.cert_not_before and rep.cert_not_after:
        print(f"  Valid: {rep.cert_not_before} -> {rep.cert_not_after}")
    print(f"  Public key: {rep.cert_pubkey} | Sig alg: {rep.cert_sig_alg}")
    print(f"  Chain length: {rep.chain_len} | OCSP stapling: {rep.ocsp_stapling}")
    if rep.caa:
        print(f"  CAA: {' | '.join(rep.caa)}")
    else:
        print("  CAA: none")
    print()

    if rep.findings:
        print("[Findings]")
        for f in rep.findings:
            print(f"  - {f.level}: {f.message}")
        print()

    print("End of report.\n")

# ---------------- CLI ----------------

def main():
    ap = argparse.ArgumentParser(description="SSL Audit – minimal TLS/HTTPS scanner")
    ap.add_argument('host', nargs='?', help='Domain or host to test')
    ap.add_argument('--port', type=int, default=443, help='Port number (default: 443)')
    args = ap.parse_args()

    if not args.host:
        eprint('Error: specify host name')
        sys.exit(2)

    rep = run(args.host, args.port)
    print_report(rep)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
