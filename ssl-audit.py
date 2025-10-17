#!/usr/bin/env python3
from __future__ import print_function, annotations
"""
TLS/HTTPS Audit – report similar to SSL Labs

Usage:
  python tls_audit.py example.com --port 443
  python tls_audit.py --self-test

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
    tls_versions: List[str] = field(default_factory=list)  # negotiated successfully
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
    findings: List[Finding] = field(default_factory=list)
    grade: Optional[str] = None

    def add(self, level: str, msg: str):
        self.findings.append(Finding(level, msg))

# ---------------- Core helpers ----------------

def resolve_ip(host: str) -> str:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    # prefer IPv4 first for readability
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
    """Simple GET / to capture headers (HTTP/1.1 only)."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                req = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Connection: close\r\n"
                    f"User-Agent: tls-audit/1.1\r\n\r\n"
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
            if k.lower() == "server":
                server = v.strip()
            if k.lower() == "strict-transport-security":
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
        # fallback to parent zone(s)
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

# ---------------- Scoring ----------------

def score(rep: Report) -> str:
    points = 100
    # TLS versions
    if 'TLS1.0' in rep.tls_versions or 'TLS1.1' in rep.tls_versions:
        rep.add('FAIL', 'Server accepts obsolete TLS 1.0/1.1')
        points -= 25
    if 'TLS1.2' not in rep.tls_versions:
        rep.add('FAIL', 'TLS 1.2 not supported')
        points -= 40
    if 'TLS1.3' not in rep.tls_versions:
        rep.add('WARN', 'TLS 1.3 missing')
        points -= 10
    # HSTS
    if not rep.hsts:
        rep.add('WARN', 'No HSTS header')
        points -= 5
    # ALPN/HTTP2
    if 'h2' not in rep.alpn:
        rep.add('WARN', 'HTTP/2 (h2) not advertised in ALPN')
        points -= 3
    # Weak DHE
    if rep.weak_dhe_supported:
        rep.add('FAIL', 'Weak DHE accepted (e.g. 1024-bit)')
        points -= 25
    # OCSP stapling
    if rep.ocsp_stapling is False:
        rep.add('WARN', 'OCSP stapling not supported')
        points -= 3
    # CAA
    if not rep.caa:
        rep.add('INFO', 'No CAA records (optional)')

    # map to grade
    if points >= 95:
        return 'A+'
    if points >= 90:
        return 'A'
    if points >= 80:
        return 'A-'
    if points >= 70:
        return 'B'
    if points >= 60:
        return 'C'
    if points >= 50:
        return 'D'
    return 'F'

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

    # Final grade
    rep.grade = score(rep)
    return rep

# ---------------- Output ----------------

def print_report(rep: Report):
    print("="*68)
    print(f"TLS/HTTPS Audit for {rep.host}:{rep.port}  (IP: {rep.ip or '?'} )")
    print("="*68)
    print(f"Grade: {rep.grade}")
    print()

    print("[TLS]")
    print(f"  TLS versions: {', '.join(rep.tls_versions) or 'none'}")
    print(f"  ALPN: {', '.join(rep.alpn) or 'none'}  | HTTP/2 supported: {rep.http2_ok}")
    print(f"  Weak DHE accepted: {rep.weak_dhe_supported} | Strong ECDHE accepted: {rep.strong_ecdhe_supported}")
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

# ---------------- Self-tests ----------------

def run_self_tests() -> int:
    ok = True

    # 1) Grade mapping sanity (should be A- or better)
    r = Report(host="test", port=443)
    r.tls_versions = ['TLS1.2', 'TLS1.3']
    r.hsts = 'max-age=0'
    r.alpn = ['h2']
    r.weak_dhe_supported = False
    r.ocsp_stapling = True
    grade = score(r)
    if grade not in {'A+', 'A', 'A-'}:
        print("[SELFTEST] expected >=A-, got:", grade)
        ok = False

    # 2) Missing TLS1.2 should be F
    r2 = Report(host="t", port=443)
    r2.tls_versions = ['TLS1.0']
    grade2 = score(r2)
    if grade2 != 'F':
        print("[SELFTEST] missing TLS1.2 should result in F, got:", grade2)
        ok = False

    # 3) Printing should not raise
    try:
        print_report(Report(host="dummy", port=443))
    except Exception as e:
        print("[SELFTEST] print_report exception:", e)
        ok = False

    # 4) Weak DHE should avoid top grade
    r3 = Report(host="x", port=443)
    r3.tls_versions = ['TLS1.2', 'TLS1.3']
    r3.hsts = 'max-age=0'
    r3.alpn = ['h2']
    r3.weak_dhe_supported = True
    r3.ocsp_stapling = True
    grade3 = score(r3)
    if grade3 in {'A+', 'A'}:
        print("[SELFTEST] weak DHE should not get A/A+, got:", grade3)
        ok = False

    print("[SELFTEST] result:", "OK" if ok else "FAIL")
    return 0 if ok else 1

# ---------------- CLI ----------------

def main():
    ap = argparse.ArgumentParser(description="TLS/HTTPS audit (mini SSL Labs)")
    ap.add_argument('host', nargs='?', help='Domain or host to test')
    ap.add_argument('--port', type=int, default=443, help='Port number (default: 443)')
    ap.add_argument('--self-test', action='store_true', help='Run internal self-tests without network')
    args = ap.parse_args()

    if args.self_test:
        sys.exit(run_self_tests())

    if not args.host:
        eprint('Error: specify host or use --self-test')
        sys.exit(2)

    rep = run(args.host, args.port)
    print_report(rep)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

