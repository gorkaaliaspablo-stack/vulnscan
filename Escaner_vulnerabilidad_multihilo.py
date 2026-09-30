#!/usr/bin/env python3
"""
vulnscan — Escáner de red asíncrono con detección de versiones y consulta de CVEs.

Flujo:
  1. Expande los objetivos (IP, CIDR, rangos, hostnames) y los puertos.
  2. Escanea con asyncio (pool de workers + conexiones TCP no bloqueantes).
  3. Captura banners (SSH, FTP, SMTP, HTTP/HTTPS, MySQL...) y extrae producto/versión.
  4. Consulta la API 2.0 de NVD (NIST) por cada producto/versión detectado.
  5. Exporta un informe estructurado en JSON o HTML.

USO ÉTICO: escanea únicamente sistemas de tu propiedad o para los que tengas
autorización explícita y por escrito. Un escaneo no autorizado puede ser ilegal.
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

import requests

VERSION = "1.0.0"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
QUIET = False

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993,
    995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017,
]
HTTP_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9443}
TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443}


def log(msg: str) -> None:
    if not QUIET:
        print(msg, file=sys.stderr, flush=True)


# ──────────────────────────────────────────────────────────────────────────────
# Modelos de datos
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class Component:
    product: str
    version: str
    cpes: list[str]


@dataclass
class Service:
    port: int
    protocol: str = "tcp"
    name: str = "unknown"
    tls: Optional[str] = None
    banner: str = ""
    components: list[Component] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)
    cve_total: int = 0
    cve_by_severity: dict[str, int] = field(default_factory=dict)
    cve_error: Optional[str] = None


# ──────────────────────────────────────────────────────────────────────────────
# Parsing de objetivos y puertos
# ──────────────────────────────────────────────────────────────────────────────
def parse_ports(spec: str) -> list[int]:
    if spec.strip().lower() == "top":
        return list(TOP_PORTS)
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
            if a > b:
                a, b = b, a
            ports.update(range(a, b + 1))
        else:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Los puertos deben estar entre 1 y 65535")
    return sorted(ports)


def expand_target(target: str) -> list[str]:
    """Acepta: 10.0.0.5 | 10.0.0.0/24 | 10.0.0.1-50 | 10.0.0.1-10.0.0.20 | host.example.com"""
    t = target.strip()
    if "/" in t:
        net = ipaddress.ip_network(t, strict=False)
        if net.num_addresses > 2**20:
            raise ValueError(f"Rango demasiado grande: {t}")
        hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
        return [str(h) for h in hosts]

    if "-" in t:
        left, right = t.split("-", 1)
        try:
            start = ipaddress.ip_address(left)
            if "." in right or ":" in right:
                end = ipaddress.ip_address(right)
            else:
                end = ipaddress.ip_address(f"{left.rsplit('.', 1)[0]}.{right}")
            if int(end) < int(start) or int(end) - int(start) > 2**20:
                raise ValueError(f"Rango inválido: {t}")
            return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
        except ValueError as exc:
            if "Rango" in str(exc):
                raise
            # no era un rango de IPs: puede ser un hostname con guion

    try:
        return [str(ipaddress.ip_address(t))]
    except ValueError:
        pass
    try:
        info = socket.getaddrinfo(t, None, socket.AF_INET)
        return [info[0][4][0]]
    except socket.gaierror as exc:
        raise ValueError(f"No se pudo resolver '{t}': {exc}") from exc


def safe_concurrency(requested: int) -> int:
    """Limita la concurrencia al máximo de descriptores de archivo disponibles."""
    try:
        import resource  # solo Unix

        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft != resource.RLIM_INFINITY:
            allowed = max(10, soft - 64)
            if requested > allowed:
                log(f"[!] Concurrencia reducida a {allowed} por ulimit -n ({soft})")
                return allowed
    except (ImportError, ValueError, OSError):
        pass
    return requested


# ──────────────────────────────────────────────────────────────────────────────
# Sockets asíncronos y banner grabbing
# ──────────────────────────────────────────────────────────────────────────────
def _tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # es un escáner: queremos hablar con cualquier servidor
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except (ssl.SSLError, ValueError, AttributeError):
        pass
    return ctx


async def _open(host: str, port: int, timeout: float, tls: bool = False):
    kwargs = {"ssl": _tls_context(), "server_hostname": host} if tls else {}
    return await asyncio.wait_for(asyncio.open_connection(host, port, **kwargs), timeout)


async def _close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 2)
    except Exception:
        pass


async def _read(reader: asyncio.StreamReader, timeout: float, limit: int = 4096) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(limit), timeout)
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return b""


async def _http_probe(host: str, reader, writer, timeout: float) -> bytes:
    request = (
        f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: vulnscan/{VERSION}\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n"
    )
    try:
        writer.write(request.encode())
        await asyncio.wait_for(writer.drain(), timeout)
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return b""
    data = b""
    deadline = time.monotonic() + timeout
    while b"\r\n\r\n" not in data and len(data) < 8192:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        chunk = await _read(reader, remaining)
        if not chunk:
            break
        data += chunk
    return data


def _parse_mysql_handshake(data: bytes) -> Optional[str]:
    """El servidor MySQL habla primero: paquete con protocolo 10 y versión terminada en NUL."""
    if len(data) > 6 and data[4] == 0x0A and re.match(rb"\d+\.\d+", data[5:12]):
        end = data.find(b"\x00", 5)
        if end > 5:
            ver = data[5:end].decode("latin-1", "replace")
            if ver.startswith("5.5.5-") and "MariaDB" in ver:
                ver = ver[6:]
            return ver
    return None


# Firmas: (regex con grupo 'v' [y opcional 'u'], producto, [(vendor, producto_cpe)])
_RAW_SIGNATURES = [
    (r"OpenSSH[_ ](?P<v>\d+\.\d+)(?:p(?P<u>\d+))?", "OpenSSH", [("openbsd", "openssh")]),
    (r"Apache/(?P<v>\d+\.\d+\.\d+)", "Apache httpd", [("apache", "http_server")]),
    (r"nginx/(?P<v>\d+\.\d+\.\d+)", "nginx", [("f5", "nginx"), ("nginx", "nginx")]),
    (r"Microsoft-IIS/(?P<v>\d+\.\d+)", "Microsoft IIS", [("microsoft", "internet_information_services")]),
    (r"lighttpd/(?P<v>\d+\.\d+\.\d+)", "lighttpd", [("lighttpd", "lighttpd")]),
    (r"Jetty[/( ](?P<v>\d+\.\d+\.\d+)", "Eclipse Jetty", [("eclipse", "jetty")]),
    (r"PHP/(?P<v>\d+\.\d+\.\d+)", "PHP", [("php", "php")]),
    (r"vsFTPd (?P<v>\d+\.\d+\.\d+)", "vsftpd", [("vsftpd_project", "vsftpd")]),
    (r"ProFTPD (?P<v>\d+\.\d+\.\d+)", "ProFTPD", [("proftpd", "proftpd")]),
    (r"Exim (?P<v>\d+\.\d+(?:\.\d+)?)", "Exim", [("exim", "exim")]),
    (r"Sendmail (?P<v>\d+\.\d+\.\d+)", "Sendmail", [("sendmail", "sendmail")]),
    (r"(?P<v>\d+\.\d+\.\d+)-MariaDB", "MariaDB", [("mariadb", "mariadb")]),
    (r"MySQL (?:handshake: )?(?P<v>\d+\.\d+\.\d+)", "MySQL", [("oracle", "mysql")]),
]
SIGNATURES = [(re.compile(rx, re.I), prod, cands) for rx, prod, cands in _RAW_SIGNATURES]
DISTRO_RE = re.compile(r"Ubuntu|Debian|Raspbian|CentOS|Red Hat|RHEL|Fedora|Rocky|Alma", re.I)


def detect_components(text: str) -> list[Component]:
    found: list[Component] = []
    for rx, product, candidates in SIGNATURES:
        m = rx.search(text)
        if not m:
            continue
        version = m.group("v")
        update = f"p{m.group('u')}" if "u" in rx.groupindex and m.group("u") else None
        cpes = [
            f"cpe:2.3:a:{vendor}:{prod}:{version}:{update or '*'}:*:*:*:*:*:*"
            for vendor, prod in candidates
        ]
        found.append(Component(product, version + (update or ""), cpes))
    if any(c.product == "MariaDB" for c in found):
        found = [c for c in found if c.product != "MySQL"]
    return found


def identify_service(port: int, text: str, tls: bool) -> str:
    up = text.upper()
    if text.startswith("HTTP/"):
        return "https" if tls else "http"
    if text.startswith("SSH-"):
        return "ssh"
    if text.startswith("220"):
        return "smtp" if ("SMTP" in up or port in (25, 465, 587)) else "ftp"
    if text.startswith("+OK"):
        return "pop3"
    if text.startswith("* OK") or text.startswith("* PREAUTH"):
        return "imap"
    if text.startswith("MySQL handshake"):
        return "mysql"
    return _service_by_port(port)


def _service_by_port(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def _clean(text: str) -> str:
    text = text.replace("\r", "")
    return "".join(ch if (ch.isprintable() or ch == "\n") else "." for ch in text).strip()[:512]


async def fingerprint(host, port, timeout, banner_timeout, reader, writer) -> Service:
    svc = Service(port=port)
    tls_active = False

    if port in TLS_PORTS:
        await _close(writer)
        try:
            reader, writer = await _open(host, port, timeout, tls=True)
            tls_active = True
            ssl_obj = writer.get_extra_info("ssl_object")
            svc.tls = ssl_obj.version() if ssl_obj else "TLS"
        except (asyncio.TimeoutError, OSError, ssl.SSLError):
            try:  # el puerto estaba abierto pero no habla TLS: reintenta en claro
                reader, writer = await _open(host, port, timeout)
            except (asyncio.TimeoutError, OSError):
                svc.name = _service_by_port(port)
                return svc

    try:
        if port in HTTP_PORTS:
            data = await _http_probe(host, reader, writer, banner_timeout)
        else:
            data = await _read(reader, banner_timeout)  # SSH/FTP/SMTP/MySQL hablan primero
            if not data:  # si el servicio calla, probamos HTTP por si acaso
                data = await _http_probe(host, reader, writer, banner_timeout)
    finally:
        await _close(writer)

    mysql_ver = _parse_mysql_handshake(data)
    raw = f"MySQL handshake: {mysql_ver}" if mysql_ver else data.decode("latin-1", "replace")
    text = _clean(raw)

    svc.banner = text
    svc.name = identify_service(port, text, tls_active)
    svc.components = detect_components(text)
    if svc.components and (m := DISTRO_RE.search(text)):
        svc.notes.append(
            f"Distribución detectada ({m.group(0)}): las distros parchean por backport sin "
            "cambiar el número de versión, así que parte de los CVEs pueden ser falsos positivos."
        )
    return svc


async def scan_port(host: str, port: int, timeout: float, banner_timeout: float) -> Optional[Service]:
    try:
        reader, writer = await _open(host, port, timeout)
    except (asyncio.TimeoutError, OSError):
        return None  # cerrado o filtrado
    return await fingerprint(host, port, timeout, banner_timeout, reader, writer)


async def scan_all(targets, ports, concurrency, timeout, banner_timeout) -> dict[str, list[Service]]:
    """Pool de workers con cola acotada: memoria constante aunque el rango sea enorme."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=concurrency * 4)
    results: dict[str, list[Service]] = defaultdict(list)
    state = {"done": 0}
    total = len(targets) * len(ports)

    async def worker():
        while True:
            item = await queue.get()
            if item is None:
                return
            host, port = item
            try:
                svc = await scan_port(host, port, timeout, banner_timeout)
                if svc:
                    results[host].append(svc)
                    ver = ", ".join(f"{c.product} {c.version}" for c in svc.components)
                    log(f"\r[+] {host}:{port:<5} abierto  {svc.name:<8} {ver}".ljust(70))
            except Exception as exc:  # un fallo aislado no debe matar al worker
                log(f"\r[!] {host}:{port} error inesperado: {exc!r}")
            finally:
                state["done"] += 1

    async def progress():
        while True:
            await asyncio.sleep(0.5)
            pct = 100 * state["done"] / total if total else 100
            print(f"\r[*] Progreso: {state['done']}/{total} ({pct:.0f}%)", end="", file=sys.stderr, flush=True)

    workers = [asyncio.create_task(worker()) for _ in range(concurrency)]
    ticker = asyncio.create_task(progress()) if (not QUIET and sys.stderr.isatty()) else None
    try:
        for host in targets:
            for port in ports:
                await queue.put((host, port))
        for _ in workers:
            await queue.put(None)
        await asyncio.gather(*workers)
    finally:
        if ticker:
            ticker.cancel()
            print(file=sys.stderr)
    return results


# ──────────────────────────────────────────────────────────────────────────────
# Cliente NVD (CVE)
# ──────────────────────────────────────────────────────────────────────────────
def _parse_cve(item: dict) -> Optional[dict]:
    cve = item.get("cve", {})
    if cve.get("vulnStatus") == "Rejected":
        return None
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score = severity = vector = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            data = m.get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or m.get("baseSeverity")
            vector = data.get("vectorString")
            break
    return {
        "id": cve.get("id"),
        "score": score,
        "severity": (severity or "UNKNOWN").upper(),
        "vector": vector,
        "published": (cve.get("published") or "")[:10],
        "description": (desc[:300] + "…") if len(desc) > 300 else desc,
        "kev": bool(cve.get("cisaExploitAdd")),  # explotada activamente (catálogo CISA KEV)
        "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
    }


class NVDClient:
    """Cliente con rate limiting (5 req/30 s sin clave, 50 req/30 s con clave), caché y reintentos."""

    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        self.timeout = timeout
        self.min_interval = 0.7 if api_key else 6.5
        self._last = 0.0
        self._cache: dict[str, tuple[list[dict], Optional[str]]] = {}
        self.session = requests.Session()
        self.session.headers["User-Agent"] = f"vulnscan/{VERSION}"
        if api_key:
            self.session.headers["apiKey"] = api_key

    def _throttle(self) -> None:
        wait = self._last + self.min_interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def query(self, cpe: str) -> tuple[list[dict], Optional[str]]:
        if cpe in self._cache:
            return self._cache[cpe]
        params = {"virtualMatchString": cpe, "resultsPerPage": 2000}
        error: Optional[str] = None
        for attempt in range(1, 5):
            self._throttle()
            try:
                resp = self.session.get(NVD_URL, params=params, timeout=self.timeout)
            except requests.RequestException as exc:
                error = f"error de red ({exc.__class__.__name__})"
                time.sleep(2 * attempt)
                continue
            if resp.status_code == 200:
                try:
                    payload = resp.json()
                except ValueError:
                    error = "respuesta no válida"
                    continue
                vulns = [v for v in (_parse_cve(i) for i in payload.get("vulnerabilities", [])) if v]
                self._cache[cpe] = (vulns, None)
                return self._cache[cpe]
            if resp.status_code == 404:
                self._cache[cpe] = ([], None)
                return self._cache[cpe]
            if resp.status_code in (403, 429, 503):
                error = f"HTTP {resp.status_code} (límite de tasa o servicio saturado)"
                time.sleep(10 * attempt)
                continue
            error = f"HTTP {resp.status_code}"
            break
        return [], error


def enrich_with_cves(results: dict[str, list[Service]], nvd: NVDClient, max_cves: int) -> None:
    pending = sorted({cpe for svcs in results.values() for s in svcs for c in s.components for cpe in c.cpes})
    log(f"[*] Consultando NVD: {len(pending)} CPE(s) únicos (~{len(pending) * nvd.min_interval:.0f} s)")
    for i, cpe in enumerate(pending, 1):
        log(f"    [{i}/{len(pending)}] {cpe}")
        nvd.query(cpe)

    for svcs in results.values():
        for svc in svcs:
            merged: dict[str, dict] = {}
            errors: list[str] = []
            for comp in svc.components:
                for cpe in comp.cpes:
                    vulns, err = nvd.query(cpe)  # respuestas ya en caché
                    if err:
                        errors.append(err)
                    for v in vulns:
                        merged.setdefault(v["id"], {**v, "component": f"{comp.product} {comp.version}"})
            ordered = sorted(merged.values(), key=lambda v: (v["kev"], v["score"] or 0.0), reverse=True)
            counts: dict[str, int] = defaultdict(int)
            for v in ordered:
                counts[v["severity"]] += 1
            svc.cve_total = len(ordered)
            svc.cve_by_severity = dict(counts)
            svc.vulnerabilities = ordered[:max_cves]
            if errors and not ordered:
                svc.cve_error = errors[0]


# ──────────────────────────────────────────────────────────────────────────────
# Informes
# ──────────────────────────────────────────────────────────────────────────────
def build_report(args, targets, ports, results, duration) -> dict:
    hosts = []
    sev_total: dict[str, int] = defaultdict(int)
    open_ports = versions = cves = 0
    for addr in sorted(results, key=ipaddress.ip_address):
        services = sorted(results[addr], key=lambda s: s.port)
        for s in services:
            open_ports += 1
            versions += bool(s.components)
            cves += s.cve_total
            for sev, n in s.cve_by_severity.items():
                sev_total[sev] += n
        hosts.append({"address": addr, "services": [asdict(s) for s in services]})
    return {
        "tool": "vulnscan",
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scan": {
            "targets": args.targets,
            "hosts_scanned": len(targets),
            "ports_scanned": len(ports),
            "duration_seconds": round(duration, 1),
            "cve_lookup": not args.no_cve,
        },
        "summary": {
            "hosts_with_open_ports": len(hosts),
            "open_ports": open_ports,
            "services_with_version": versions,
            "cves_found": cves,
            "cves_by_severity": dict(sev_total),
        },
        "hosts": hosts,
    }


HTML_TEMPLATE = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe vulnscan — {{ r.generated_at }}</title>
<style>
:root{--bg:#f5f6f8;--fg:#1b2230;--muted:#5c6779;--card:#fff;--line:#dde1e8;--code:#eef0f4;
--CRITICAL:#8e0f1c;--HIGH:#d9480f;--MEDIUM:#b57e00;--LOW:#2b8a3e;--UNKNOWN:#6b7280}
@media (prefers-color-scheme:dark){:root{--bg:#11151b;--fg:#e6e9ee;--muted:#98a2b3;--card:#1a2029;--line:#2b3441;--code:#232b36}}
*{box-sizing:border-box}
body{margin:0;padding:24px;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto}
h1{margin:0 0 4px;font-size:1.6rem} h2{margin:32px 0 12px;font-size:1.2rem;font-family:ui-monospace,Menlo,monospace}
.muted{color:var(--muted)} .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.card b{display:block;font-size:1.7rem}
details.svc{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:10px 0;padding:10px 14px}
details.svc>summary{cursor:pointer;font-family:ui-monospace,Menlo,monospace}
pre{background:var(--code);padding:10px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;font-size:.85rem}
.badge{display:inline-block;color:#fff;border-radius:999px;padding:1px 9px;font-size:.78rem;font-weight:600;white-space:nowrap}
.tag{background:var(--code);border-radius:4px;padding:0 6px;font-size:.78rem}
.sev-CRITICAL{background:var(--CRITICAL)} .sev-HIGH{background:var(--HIGH)} .sev-MEDIUM{background:var(--MEDIUM)}
.sev-LOW{background:var(--LOW)} .sev-UNKNOWN{background:var(--UNKNOWN)}
.scroll{overflow-x:auto} table{border-collapse:collapse;width:100%;min-width:640px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top;font-size:.9rem}
.note{border-left:3px solid var(--MEDIUM);padding-left:10px;color:var(--muted)}
a{color:inherit} footer{margin-top:40px;font-size:.85rem}
</style>
</head>
<body><main>
<h1>Informe de escaneo de vulnerabilidades</h1>
<p class="muted">Generado {{ r.generated_at }} · Objetivos: {{ r.scan.targets|join(', ') }} ·
{{ r.scan.hosts_scanned }} host(s) × {{ r.scan.ports_scanned }} puerto(s) · {{ r.scan.duration_seconds }} s</p>

<div class="cards">
  <div class="card"><b>{{ r.summary.hosts_with_open_ports }}</b>hosts con puertos abiertos</div>
  <div class="card"><b>{{ r.summary.open_ports }}</b>puertos abiertos</div>
  <div class="card"><b>{{ r.summary.services_with_version }}</b>versiones identificadas</div>
  <div class="card"><b>{{ r.summary.cves_found }}</b>CVEs asociados</div>
  {% for sev in ['CRITICAL','HIGH','MEDIUM','LOW'] %}{% if r.summary.cves_by_severity.get(sev) %}
  <div class="card"><b style="color:var(--{{ sev }})">{{ r.summary.cves_by_severity[sev] }}</b>{{ sev }}</div>
  {% endif %}{% endfor %}
</div>

{% for h in r.hosts %}
<h2>{{ h.address }}</h2>
{% for s in h.services %}
<details class="svc" {% if s.vulnerabilities %}open{% endif %}>
  <summary><strong>{{ s.port }}/{{ s.protocol }}</strong> {{ s.name }}
    {% if s.tls %}<span class="tag">{{ s.tls }}</span>{% endif %}
    {% for c in s.components %}· {{ c.product }} {{ c.version }} {% endfor %}
    {% if s.cve_total %}<span class="badge sev-{{ 'CRITICAL' if s.cve_by_severity.get('CRITICAL') else 'HIGH' if s.cve_by_severity.get('HIGH') else 'MEDIUM' if s.cve_by_severity.get('MEDIUM') else 'LOW' }}">{{ s.cve_total }} CVE</span>{% endif %}
  </summary>
  {% if s.banner %}<pre>{{ s.banner }}</pre>{% endif %}
  {% for n in s.notes %}<p class="note">{{ n }}</p>{% endfor %}
  {% if s.cve_error %}<p class="note">No se pudo consultar NVD: {{ s.cve_error }}</p>{% endif %}
  {% if s.vulnerabilities %}
  <div class="scroll"><table>
    <thead><tr><th>CVE</th><th>Severidad</th><th>Publicado</th><th>Componente</th><th>Descripción</th></tr></thead>
    <tbody>
    {% for v in s.vulnerabilities %}
    <tr>
      <td><a href="{{ v.url }}" target="_blank" rel="noopener">{{ v.id }}</a>
          {% if v.kev %}<br><span class="badge sev-CRITICAL" title="Catálogo CISA KEV">explotada</span>{% endif %}</td>
      <td><span class="badge sev-{{ v.severity }}">{{ v.severity }} {{ v.score if v.score is not none else '—' }}</span></td>
      <td>{{ v.published }}</td><td>{{ v.component }}</td><td>{{ v.description }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table></div>
  {% if s.cve_total > s.vulnerabilities|length %}
  <p class="muted">Mostrando {{ s.vulnerabilities|length }} de {{ s.cve_total }} CVEs (ordenados por explotación activa y gravedad).</p>
  {% endif %}
  {% endif %}
</details>
{% endfor %}
{% else %}
<p class="muted">No se encontraron puertos abiertos.</p>
{% endfor %}

<footer class="muted">
  La detección se basa en banners, que pueden estar ocultos o falsificados. Los CVEs listados corresponden a la
  versión anunciada y deben verificarse manualmente (backports, configuración, mitigaciones). Datos: NVD (NIST).
</footer>
</main></body></html>
"""


def write_html(report: dict, path: str) -> None:
    from jinja2 import Environment  # import perezoso: solo se necesita para HTML

    env = Environment(autoescape=True, trim_blocks=True, lstrip_blocks=True)
    html = env.from_string(HTML_TEMPLATE).render(r=report)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)


def write_json(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)


def print_summary(report: dict) -> None:
    s = report["summary"]
    print(f"\n=== Resumen: {s['open_ports']} puertos abiertos en {s['hosts_with_open_ports']} host(s), "
          f"{s['cves_found']} CVEs asociados ===")
    for h in report["hosts"]:
        print(f"\n{h['address']}")
        for svc in h["services"]:
            comps = ", ".join(f"{c['product']} {c['version']}" for c in svc["components"]) or "-"
            cve = f"{svc['cve_total']} CVE" if svc["cve_total"] else ""
            print(f"  {svc['port']:>5}/tcp  {svc['name']:<8} {comps:<32} {cve}")
            for v in svc["vulnerabilities"][:3]:
                score = v["score"] if v["score"] is not None else "-"
                print(f"           - {v['id']}  [{v['severity']} {score}]  {v['description'][:70]}")


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="vulnscan",
        description="Escáner de red asíncrono con detección de versiones y consulta de CVEs en NVD.",
        epilog="Ejemplo: vulnscan.py 192.168.1.0/24 -p 1-1024 -o informe.html",
    )
    p.add_argument("targets", nargs="+", help="IP, CIDR (10.0.0.0/24), rango (10.0.0.1-50) u hostname")
    p.add_argument("-p", "--ports", default="top", help="'top', lista (22,80) o rangos (1-1024). Por defecto: top")
    p.add_argument("-c", "--concurrency", type=int, default=500, help="Conexiones simultáneas (500)")
    p.add_argument("-t", "--timeout", type=float, default=1.5, help="Timeout de conexión en segundos (1.5)")
    p.add_argument("--banner-timeout", type=float, default=2.0, help="Espera de banner en segundos (2.0)")
    p.add_argument("--no-cve", action="store_true", help="Omitir la consulta a NVD")
    p.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"),
                   help="Clave de la API de NVD (o variable NVD_API_KEY): sube el límite de peticiones")
    p.add_argument("--max-cves", type=int, default=10, help="CVEs máximos listados por servicio (10)")
    p.add_argument("-o", "--output", help="Archivo de informe (.json o .html)")
    p.add_argument("-f", "--format", choices=["json", "html"], help="Formato (por defecto, según la extensión)")
    p.add_argument("-q", "--quiet", action="store_true", help="Sin progreso ni mensajes en stderr")
    return p.parse_args()


async def amain(args: argparse.Namespace) -> dict:
    started = time.monotonic()
    targets: list[str] = []
    for t in args.targets:
        targets.extend(expand_target(t))
    targets = list(dict.fromkeys(targets))
    ports = parse_ports(args.ports)
    concurrency = safe_concurrency(max(1, args.concurrency))

    log(f"[*] {len(targets)} host(s) × {len(ports)} puerto(s) = {len(targets) * len(ports)} sondeos "
        f"(concurrencia {concurrency})")
    results = await scan_all(targets, ports, concurrency, args.timeout, args.banner_timeout)

    if not args.no_cve and any(s.components for svcs in results.values() for s in svcs):
        if not args.nvd_api_key:
            log("[i] Sin clave de NVD: límite de ~5 consultas/30 s. Consigue una gratis en nvd.nist.gov/developers")
        nvd = NVDClient(args.nvd_api_key)
        await asyncio.to_thread(enrich_with_cves, results, nvd, args.max_cves)

    return build_report(args, targets, ports, results, time.monotonic() - started)


def main() -> int:
    global QUIET
    args = parse_args()
    QUIET = args.quiet
    log("[!] Usa esta herramienta solo en sistemas propios o con autorización expresa.")
    try:
        report = asyncio.run(amain(args))
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrumpido por el usuario.", file=sys.stderr)
        return 130

    print_summary(report)
    if args.output:
        fmt = args.format or ("html" if args.output.lower().endswith((".html", ".htm")) else "json")
        (write_html if fmt == "html" else write_json)(report, args.output)
        print(f"\n[✓] Informe {fmt.upper()} guardado en {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())