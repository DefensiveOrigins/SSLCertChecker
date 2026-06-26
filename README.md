# check_ssl.py — Bulk SSL Certificate Checker

A command-line tool that reads a list of hostnames and checks the SSL/TLS
certificate on each one, reporting the common name, issuing CA, validity
dates, and a colour-coded status for any problems found.

---

## Requirements

- Python 3.10 or later
- [`cryptography`](https://pypi.org/project/cryptography/) — certificate parsing
- [`alive-progress`](https://pypi.org/project/alive-progress/) — animated progress bar

All other imports (`ssl`, `socket`, `csv`, `argparse`, `xml.etree.ElementTree`, `datetime`) are part of the Python standard library and require no installation.

---

## Installation

Running inside a virtual environment is recommended so the dependencies stay isolated from your system Python. The steps are the same on macOS and Linux; Windows users should swap `python3` for `py -3` and use backslashes where noted.

### Option A — Virtual environment (recommended)

```bash
# 1. Clone or download the project files into a directory
#    (check_ssl.py and requirements.txt must be in the same folder)

# 2. Create a virtual environment in that directory
python3 -m venv .venv

# 3. Activate it
#    macOS / Linux:
source .venv/bin/activate
#    Windows (Command Prompt):
.venv\Scripts\activate.bat
#    Windows (PowerShell):
.venv\Scripts\Activate.ps1

# 4. Install dependencies from the requirements file
pip install -r requirements.txt

# 5. Run the tool
python check_ssl.py hosts.txt
```

The virtual environment only needs to be **created once** (steps 2 and 4). On subsequent uses just activate it (step 3) and run.

To deactivate the environment when you are done:

```bash
deactivate
```

### Option B — System-wide install

If you prefer not to use a virtual environment, install the dependencies directly:

```bash
pip install -r requirements.txt
```

Or install packages individually:

```bash
pip install cryptography alive-progress
```

---

## Quick Start

```bash
# Plain-text hosts file
python check_ssl.py hosts.txt

# Nessus XML export
python check_ssl.py scan.nessus
```

---

## Hosts File Format

Create a plain-text file with one host per line. The port is optional and
defaults to **443** when omitted. Lines beginning with `#` are treated as
comments and ignored.

```
# Production endpoints
example.com
www.example.com:443

# Non-standard ports
internal-app.corp:8443
api-gateway.internal:4443

# Deliberately bad certs (for testing)
expired.badssl.com
self-signed.badssl.com
```

---

## Usage

```
python check_ssl.py HOSTS_FILE [options]
```

### Positional argument

| Argument | Description |
|---|---|
| `HOSTS_FILE` | Path to the hosts file described above |

### Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--timeout SECONDS` | `-t` | `5` | TCP connection timeout per host, in seconds |
| `--warn-days DAYS` | `-w` | `30` | Warn when a certificate expires within this many days |
| `--verbose` | `-v` | off | Show a detailed multi-line block per host instead of the condensed table |
| `--csv FILE` | | | Export results to a CSV file; can be combined with console output |
| `--no-color` | | off | Disable ANSI colour output (auto-disabled when stdout is not a TTY) |
| `--help` | `-h` | | Show help and exit |

---

## Examples

```bash
# Basic scan using all defaults
python check_ssl.py hosts.txt

# Longer timeout and 60-day expiry warning window
python check_ssl.py hosts.txt --timeout 10 --warn-days 60

# Detailed per-host output
python check_ssl.py hosts.txt --verbose

# Save results to a CSV file
python check_ssl.py hosts.txt --csv report.csv

# Verbose output + CSV export, no colour (good for CI logs)
python check_ssl.py hosts.txt --verbose --csv report.csv --no-color

# Pipe-friendly — colour is suppressed automatically
python check_ssl.py hosts.txt | tee scan.log
```

---

## Output

### Default (condensed table)

One row per host. Long values are truncated with `…`. The STATUS column is
colour-coded (see table below).

```
HOST:PORT                       COMMON NAME                CA / ISSUER                VALID FROM   VALID TO     STATUS
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
google.com:443                  *.google.com               WR2                        2025-04-07   2025-06-30   OK (4d left)
expired.badssl.com:443          *.badssl.com               DigiCert SHA2 Secure Se…   2015-04-09   2015-04-12   Expired
self-signed.badssl.com:443      *.badssl.com               *.badssl.com               2024-08-05   2026-08-05   Self-signed
internal.corp:8443              internal.corp              internal.corp              2024-01-01   2026-01-01   Self-signed
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  ⚠  3 issue(s) found:
     • expired.badssl.com:443       →  Expired
     • self-signed.badssl.com:443   →  Self-signed
     • internal.corp:8443           →  Self-signed
```

### Verbose (`--verbose`)

A labelled block per host with full-length values, including inline
annotations for self-signed and untrusted CAs.

```
──────────────────────────────────────────────────────────────
  Host   : self-signed.badssl.com:443
  CN     : *.badssl.com
  CA     : *.badssl.com  ◀ self-signed
  From   : 2024-08-05 21:58 UTC
  To     : 2026-08-05 21:58 UTC
  Status : Self-signed
```

### Status codes and colours

| Status | Colour | Meaning |
|---|---|---|
| `OK` | Green | Valid, trusted CA, not near expiry |
| `Expiring in Nd` | Yellow | Valid but expires within `--warn-days` days |
| `Self-signed` | Yellow | Subject CN equals issuer CN |
| `Untrusted CA` | Yellow | CA not found in the built-in trusted-root list |
| `Expired` | Red | Certificate is past its `notAfter` date |
| `Not yet valid` | Red | Certificate is before its `notBefore` date |
| `Error: …` | Red | Could not connect or could not parse the certificate |

Colour is automatically disabled when stdout is not a TTY (e.g. when piping
or redirecting). Use `--no-color` to force plain text at any time.

---

## CSV Export

When `--csv FILE` is supplied, results are written to a comma-separated file
with the following columns:

| Column | Description |
|---|---|
| `host` | Hostname as supplied in the hosts file |
| `port` | Port number used |
| `common_name` | Certificate subject Common Name |
| `issuer_ca` | Issuer Common Name (or Organisation Name if CN is absent) |
| `valid_from` | `notBefore` date/time in UTC |
| `valid_to` | `notAfter` date/time in UTC |
| `self_signed` | `Yes` if CN == issuer CN, otherwise `No` |
| `trusted_ca` | `Yes` if the issuer matched a known trusted root, otherwise `No` |
| `status` | Human-readable status label |
| `error` | Error message if the host could not be reached or parsed |

Console output is still shown when `--csv` is used; the two are independent.

---

## Trusted CA Detection

The tool checks the issuer name against a built-in list of well-known
commercial and public root CAs, including (among others):

DigiCert, Sectigo / Comodo, Let's Encrypt / ISRG, GlobalSign, Entrust,
IdenTrust, GeoTrust, RapidSSL, Thawte, Amazon, Google Trust Services,
Microsoft, Starfield, GoDaddy, SSL.com, Buypass, Trustwave, QuoVadis.

Any certificate whose issuer does not match a keyword in this list — including
private PKI roots, corporate CAs, and self-signed certificates — is flagged
with **Untrusted CA** (yellow) or **Self-signed** (yellow).

> **Note:** This is a heuristic keyword match against the issuer name, not a
> full path validation against an OS trust store. A certificate that passes
> this check is not guaranteed to be trusted by every browser or OS.

---

## Notes

- The tool connects with `ssl.CERT_NONE` so that it can **inspect** expired,
  self-signed, and otherwise invalid certificates rather than refusing to
  connect to them.
- IPv6 addresses with a port must be written as `[::1]:443`.
- A live, routable network connection is required for each host.

---

## License

MIT — free to use, modify, and redistribute.
