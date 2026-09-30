# vulnscan — Escáner de vulnerabilidades de red multihilo (asyncio)

Escanea puertos TCP, captura banners, identifica producto/versión y consulta la
API 2.0 de NVD (NIST) para listar los CVEs asociados. Exporta a JSON o HTML.

> ⚠️ Úsalo solo en sistemas propios o con autorización escrita. Para practicar
> puedes usar `scanme.nmap.org` (permitido por el proyecto Nmap, con moderación),
> tu propia red doméstica o laboratorios como Metasploitable/DVWA en una VM.

## Instalación
    pip install -r requirements.txt        # Python 3.9+

## Uso
    python vulnscan.py 192.168.1.10                        # puertos "top"
    python vulnscan.py 192.168.1.0/24 -p 1-1024 -o informe.html
    python vulnscan.py 10.0.0.1-50 -p 22,80,443 -o informe.json
    python vulnscan.py scanme.nmap.org --nvd-api-key TU_CLAVE
    python vulnscan.py 127.0.0.1 --no-cve                  # solo escaneo + banners

Opciones útiles: `-c` concurrencia (500), `-t` timeout de conexión, `--banner-timeout`,
`--max-cves` por servicio, `-q` modo silencioso. La clave de NVD también puede ir en la
variable `NVD_API_KEY` (gratis en https://nvd.nist.gov/developers/request-an-api-key).

## Cómo funciona
| Fase | Técnica |
|------|---------|
| Escaneo | Pool de workers `asyncio` + cola acotada (memoria constante en rangos grandes) |
| Banners | SSH/FTP/SMTP/POP3/IMAP/MySQL hablan primero (lectura pasiva); HTTP(S) con `HEAD`; TLS sin verificación |
| Parsing | Regex → (producto, versión) → CPE 2.3 (`cpe:2.3:a:openbsd:openssh:8.9:p1:...`) |
| CVEs | NVD `virtualMatchString`, rate limiting (6.5 s sin clave / 0.7 s con clave), caché y reintentos |
| Informe | JSON estructurado o HTML (Jinja2, autoescape, tema claro/oscuro) |

## Limitaciones
- La versión anunciada en un banner puede estar oculta o falsificada.
- Ubuntu/Debian/RHEL parchean por *backport*: el número de versión no cambia, así que
  habrá falsos positivos (el informe lo avisa).
- Sin clave de NVD, cada producto distinto tarda ~6.5 s en consultarse.

## Ideas para ampliar
Detección de SO, más firmas (Redis, PostgreSQL, SMB), UDP, `python-nmap` como
motor alternativo, caché persistente de NVD (SQLite) y escaneo de TLS débil.
