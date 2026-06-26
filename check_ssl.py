#!/usr/bin/env python3
"""
check_ssl.py — Bulk SSL Certificate Checker
============================================
Reads a list of hosts (with optional ports) and checks each SSL certificate,
reporting the common name, issuing CA, validity dates, and any problems found.

Hosts file format (one entry per line):
  example.com            # defaults to port 443
  example.com:443        # explicit port
  internal-host:8443     # non-standard port
  # lines starting with # are ignored

Highlights:
  - Expired or not-yet-valid certificates          (red)
  - Certificates expiring within --warn-days days  (yellow)
  - Self-signed certificates (CN == CA)            (yellow)
  - CAs not in the common trusted-root list        (yellow)
  - Connection / TLS errors                        (red)

Examples:
  python check_ssl.py hosts.txt
  python check_ssl.py hosts.txt --timeout 10 --warn-days 60
  python check_ssl.py hosts.txt --verbose
  python check_ssl.py hosts.txt --csv report.csv
  python check_ssl.py hosts.txt --csv report.csv --no-color
"""

import ssl
import socket
import sys
import csv
import argparse
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from alive_progress import alive_bar

# ── ANSI colours ──────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

DEFAULT_PORT      = 443
DEFAULT_TIMEOUT   = 5
DEFAULT_WARN_DAYS = 30

# Well-known / commonly trusted root CA name fragments (case-insensitive)
TRUSTED_CA_KEYWORDS = [
    "digicert", "comodo", "sectigo", "let's encrypt", "letsencrypt",
    "globalsign", "entrust", "identrust", "usertrust", "geotrust",
    "rapidssl", "thawte", "verisign", "amazon", "google trust services",
    "microsoft", "baltimore", "starfield", "godaddy", "go daddy",
    "ssl.com", "actalis", "buypass", "certigna", "d-trust",
    "swisssign", "teliasonera", "trustwave", "t-systems", "quovadis",
    "isrg", "internet security research group",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def c(text: str, *codes: str, use_color: bool = True) -> str:
    """Apply ANSI colour codes when use_color is True."""
    return ("".join(codes) + text + RESET) if use_color else text


def is_trusted_ca(issuer_cn: str) -> bool:
    lower = issuer_cn.lower()
    return any(kw in lower for kw in TRUSTED_CA_KEYWORDS)


def fmt_dt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d") if dt else "—"


def fmt_dt_long(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "—"


# ── Certificate fetching ──────────────────────────────────────────────────────

def get_cert_info(host: str, port: int, timeout: int) -> dict:
    """Connect to host:port, retrieve and parse its SSL certificate."""
    result = dict(
        host=host, port=port,
        common_name=None, issuer_cn=None,
        not_before=None, not_after=None,
        self_signed=False, trusted_ca=True,
        error=None,
    )

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # inspect even untrusted/expired certs

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except (socket.timeout, TimeoutError):
        result["error"] = "Timed out"
        return result
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result

    try:
        cert = x509.load_der_x509_certificate(der, default_backend())

        def get_attr(name_obj, oid, fallback_oid=None):
            attrs = name_obj.get_attributes_for_oid(oid)
            if attrs:
                return attrs[0].value
            if fallback_oid:
                attrs = name_obj.get_attributes_for_oid(fallback_oid)
                return attrs[0].value if attrs else "(unknown)"
            return "(unknown)"

        result["common_name"] = get_attr(cert.subject, x509.NameOID.COMMON_NAME,
                                         x509.NameOID.ORGANIZATION_NAME)
        result["issuer_cn"]   = get_attr(cert.issuer,  x509.NameOID.COMMON_NAME,
                                         x509.NameOID.ORGANIZATION_NAME)
        result["not_before"]  = cert.not_valid_before_utc
        result["not_after"]   = cert.not_valid_after_utc
        result["self_signed"] = (result["common_name"] == result["issuer_cn"])
        result["trusted_ca"]  = is_trusted_ca(result["issuer_cn"])

    except Exception as exc:
        result["error"] = f"Parse error: {exc}"

    return result


# ── Status derivation ─────────────────────────────────────────────────────────

def derive_status(r: dict, warn_days: int) -> tuple[str, str]:
    """
    Returns (status_code, status_label).

    Multiple conditions are composed so that, e.g., an expired self-signed
    certificate reports both facts.  The status_code reflects the *worst*
    single condition for colour-coding purposes:
      ERROR > EXPIRED > NOT_YET_VALID > EXPIRING > SELF_SIGNED > UNTRUSTED > OK
    """
    if r["error"]:
        return "ERROR", f"Error: {r['error']}"

    now   = datetime.now(timezone.utc)
    flags = []          # human-readable fragments, worst-first
    code  = "OK"        # colour/priority code — updated as we find issues

    # ── Validity window ───────────────────────────────────────────────────────
    if now > r["not_after"]:
        flags.append("Expired")
        code = "EXPIRED"
    elif now < r["not_before"]:
        flags.append("Not yet valid")
        code = "NOT_YET_VALID"
    else:
        days_left = (r["not_after"] - now).days
        if days_left <= warn_days:
            flags.append(f"Expiring in {days_left}d")
            code = "EXPIRING"

    # ── Certificate trust issues (checked independently of validity) ──────────
    if r["self_signed"]:
        flags.append("Self-signed")
        if code == "OK":
            code = "SELF_SIGNED"
    elif not r["trusted_ca"]:
        flags.append("Untrusted CA")
        if code == "OK":
            code = "UNTRUSTED"

    if not flags:
        days_left = (r["not_after"] - now).days
        return "OK", f"OK ({days_left}d left)"

    return code, ", ".join(flags)


STATUS_COLOR = {
    "ERROR":         (RED,    BOLD),
    "EXPIRED":       (RED,    BOLD),
    "NOT_YET_VALID": (RED,    BOLD),
    "SELF_SIGNED":   (YELLOW, BOLD),
    "UNTRUSTED":     (YELLOW, BOLD),
    "EXPIRING":      (YELLOW, BOLD),
    "OK":            (GREEN,),
}


# ── Output: condensed (default) ───────────────────────────────────────────────

def print_condensed(results: list, warn_days: int, use_color: bool) -> None:
    """One row per host in a fixed-width table."""
    W = dict(host=30, cn=26, ca=26, nb=11, na=11)

    def hdr(s, w): return s.ljust(w)

    header = (
        hdr("HOST:PORT",   W["host"]) + "  " +
        hdr("COMMON NAME", W["cn"])   + "  " +
        hdr("CA / ISSUER", W["ca"])   + "  " +
        hdr("VALID FROM",  W["nb"])   + "  " +
        hdr("VALID TO",    W["na"])   + "  " +
        "STATUS"
    )
    sep = c("─" * len(header), CYAN, use_color=use_color)

    print()
    print(c(header, BOLD, use_color=use_color))
    print(sep)

    for r in results:
        code, label = derive_status(r, warn_days)
        colors = STATUS_COLOR.get(code, ())

        def tr(s, w):
            s = s or "—"
            return (s[:w - 1] + "…") if len(s) > w else s.ljust(w)

        host_str = f"{r['host']}:{r['port']}"
        row = (
            tr(host_str,                W["host"]) + "  " +
            tr(r["common_name"] or "—", W["cn"])   + "  " +
            tr(r["issuer_cn"]   or "—", W["ca"])   + "  " +
            tr(fmt_dt(r["not_before"]), W["nb"])   + "  " +
            tr(fmt_dt(r["not_after"]),  W["na"])   + "  " +
            label
        )
        print(c(row, *colors, use_color=use_color))

    print(sep)
    _print_summary(results, warn_days, use_color)


# ── Output: verbose (--verbose) ───────────────────────────────────────────────

def print_verbose(results: list, warn_days: int, use_color: bool) -> None:
    """Detailed multi-line block per host."""
    sep = c("─" * 62, CYAN, use_color=use_color)

    for r in results:
        code, label = derive_status(r, warn_days)
        colors = STATUS_COLOR.get(code, ())

        print(sep)
        print(c(f"  Host   : {r['host']}:{r['port']}", BOLD, use_color=use_color))

        if r["error"]:
            print(c(f"  Status : {label}", *colors, use_color=use_color))
            continue

        ss_note = c("  ◀ self-signed", YELLOW, BOLD, use_color=use_color) \
                  if r["self_signed"] else ""
        ut_note = c("  ◀ not commonly trusted", YELLOW, BOLD, use_color=use_color) \
                  if not r["trusted_ca"] and not r["self_signed"] else ""

        print(f"  CN     : {r['common_name']}")
        print(f"  CA     : {r['issuer_cn']}{ss_note}{ut_note}")
        print(f"  From   : {fmt_dt_long(r['not_before'])}")
        print(f"  To     : {fmt_dt_long(r['not_after'])}")
        print(c(f"  Status : {label}", *colors, use_color=use_color))

    print(sep)
    _print_summary(results, warn_days, use_color)


# ── Shared summary footer ─────────────────────────────────────────────────────

def _print_summary(results: list, warn_days: int, use_color: bool) -> None:
    issues = [
        (r, code, label)
        for r in results
        for code, label in [derive_status(r, warn_days)]
        if code != "OK"
    ]
    print()
    if not issues:
        print(c("  ✓  All certificates are healthy.", GREEN, BOLD, use_color=use_color))
    else:
        print(c(f"  ⚠  {len(issues)} issue(s) found:", YELLOW, BOLD, use_color=use_color))
        for r, code, label in issues:
            colors = STATUS_COLOR.get(code, ())
            print(c(f"     • {r['host']}:{r['port']}  →  {label}", *colors, use_color=use_color))
    print()


# ── CSV export ────────────────────────────────────────────────────────────────

def write_csv(results: list, path: str, warn_days: int) -> None:
    fields = ["host", "port", "common_name", "issuer_ca",
              "valid_from", "valid_to", "self_signed", "trusted_ca", "status", "error"]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for r in results:
            _, label = derive_status(r, warn_days)
            writer.writerow({
                "host":        r["host"],
                "port":        r["port"],
                "common_name": r["common_name"] or "",
                "issuer_ca":   r["issuer_cn"]   or "",
                "valid_from":  fmt_dt_long(r["not_before"]),
                "valid_to":    fmt_dt_long(r["not_after"]),
                "self_signed": "Yes" if r["self_signed"] else "No",
                "trusted_ca":  "Yes" if r["trusted_ca"]  else "No",
                "status":      label,
                "error":       r["error"] or "",
            })


# ── Hosts file parser ─────────────────────────────────────────────────────────

def parse_hosts_file(path: str) -> list[tuple[str, int]]:
    hosts = []
    with open(path) as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                host, _, port_str = line.rpartition(":")
                try:
                    hosts.append((host.strip(), int(port_str.strip())))
                    continue
                except ValueError:
                    pass
            else:
                hosts.append((line, DEFAULT_PORT))
                continue
            print(f"  [line {lineno}] skipped (bad format): {line!r}", file=sys.stderr)
    return hosts


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check_ssl.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "hosts_file",
        metavar="HOSTS_FILE",
        help=(
            "Path to a plain-text file containing one host per line.  "
            "Entries may be 'hostname' (port defaults to 443) or "
            "'hostname:port'.  Lines beginning with '#' are ignored."
        ),
    )
    parser.add_argument(
        "--timeout", "-t",
        metavar="SECONDS",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"TCP connection timeout per host in seconds.  (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--warn-days", "-w",
        metavar="DAYS",
        type=int,
        default=DEFAULT_WARN_DAYS,
        dest="warn_days",
        help=(
            "Emit a warning when a certificate expires within this many days.  "
            f"(default: {DEFAULT_WARN_DAYS})"
        ),
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help=(
            "Show a detailed multi-line block for each host instead of the "
            "default condensed single-row table."
        ),
    )
    parser.add_argument(
        "--csv",
        metavar="FILE",
        dest="csv_path",
        help=(
            "Export results to a CSV file at the given path.  "
            "Can be combined with normal console output."
        ),
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        dest="no_color",
        help=(
            "Disable ANSI colour output.  Automatically implied when stdout "
            "is not a TTY (e.g. when piping or redirecting)."
        ),
    )
    return parser


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    # Check dependencies early with friendly messages
    missing = []
    try:
        import cryptography  # noqa: F401
    except ImportError:
        missing.append("cryptography")
    try:
        import alive_progress  # noqa: F401
    except ImportError:
        missing.append("alive-progress")
    if missing:
        pkgs = " ".join(missing)
        print(f"Missing package(s): {pkgs}\nInstall with:  pip install {pkgs}", file=sys.stderr)
        sys.exit(1)

    use_color = not args.no_color and sys.stdout.isatty()

    try:
        hosts = parse_hosts_file(args.hosts_file)
    except FileNotFoundError:
        print(f"File not found: {args.hosts_file}", file=sys.stderr)
        sys.exit(1)

    if not hosts:
        print("No valid host entries found in the file.", file=sys.stderr)
        sys.exit(1)

    # ── Scan with alive-progress bar ──────────────────────────────────────────
    results = []
    print()
    with alive_bar(
        len(hosts),
        title="Checking certificates",
        bar="smooth",
        spinner="classic",
        elapsed=True,
        stats=True,
        enrich_print=False,       # don't prepend bar position to print() calls
        receipt=True,             # show completion receipt when done
    ) as bar:
        for host, port in hosts:
            bar.text(f"→ {host}:{port}")
            results.append(get_cert_info(host, port, args.timeout))
            bar()

    # ── Render results ────────────────────────────────────────────────────────
    if args.verbose:
        print_verbose(results, args.warn_days, use_color)
    else:
        print_condensed(results, args.warn_days, use_color)

    if args.csv_path:
        write_csv(results, args.csv_path, args.warn_days)
        print(c(f"  CSV written → {args.csv_path}\n", CYAN, use_color=use_color))


if __name__ == "__main__":
    main()