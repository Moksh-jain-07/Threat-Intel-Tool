#!/usr/bin/env python3
"""
Threat Intelligence Automation Tool
Queries VirusTotal, AbuseIPDB, and Shodan for a given IP, domain, or file hash.
Outputs a clean HTML report.
"""

import argparse
import json
import sys
import os
import re
from datetime import datetime

try:
    import requests
except ImportError:
    print("[!] requests not installed. Run: pip install requests")
    sys.exit(1)

# ─── CONFIG ──────────────────────────────────────────────────────────────────

VT_API_KEY        = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
SHODAN_API_KEY    = os.getenv("SHODAN_API_KEY", "")

VT_BASE        = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
SHODAN_BASE    = "https://api.shodan.io"

# ─── HELPERS ─────────────────────────────────────────────────────────────────

def detect_ioc_type(ioc: str) -> str:
    ip_pattern   = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    hash_pattern = re.compile(r"^[a-fA-F0-9]{32,64}$")
    if ip_pattern.match(ioc):
        return "ip"
    elif hash_pattern.match(ioc):
        return "hash"
    else:
        return "domain"

def safe_get(url, headers=None, params=None, timeout=10):
    try:
        r = requests.get(url, headers=headers, params=params, timeout=timeout)
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 401:
            return {"error": "Invalid API key"}
        elif r.status_code == 403:
            return {"error": "API key does not have permission (upgrade required)"}
        elif r.status_code == 404:
            return {"error": "Not found"}
        elif r.status_code == 429:
            return {"error": "Rate limited — try again later"}
        else:
            return {"error": f"HTTP {r.status_code}"}
    except requests.exceptions.ConnectionError:
        return {"error": "Connection failed"}
    except requests.exceptions.Timeout:
        return {"error": "Request timed out"}
    except Exception as e:
        return {"error": str(e)}

# ─── API WRAPPERS ─────────────────────────────────────────────────────────────

def query_virustotal(ioc: str, ioc_type: str) -> dict:
    if not VT_API_KEY:
        return {"error": "No API key set (VT_API_KEY)"}

    headers      = {"x-apikey": VT_API_KEY}
    endpoint_map = {
        "ip":     f"{VT_BASE}/ip_addresses/{ioc}",
        "domain": f"{VT_BASE}/domains/{ioc}",
        "hash":   f"{VT_BASE}/files/{ioc}",
    }

    data = safe_get(endpoint_map[ioc_type], headers=headers)
    if "error" in data:
        return data

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    result = {
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation", "N/A"),
        "country":    attrs.get("country", "N/A"),
        "as_owner":   attrs.get("as_owner", "N/A"),
        "tags":       attrs.get("tags", []),
    }

    if ioc_type == "hash":
        result["file_type"] = attrs.get("type_description", "N/A")
        result["file_name"] = attrs.get("meaningful_name", "N/A")
        result["size"]      = attrs.get("size", "N/A")

    return result


def query_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {"error": "No API key set (ABUSEIPDB_API_KEY)"}

    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
    data    = safe_get(f"{ABUSEIPDB_BASE}/check", headers=headers, params=params)

    if "error" in data:
        return data

    d = data.get("data", {})
    return {
        "abuse_score":    d.get("abuseConfidenceScore", 0),
        "total_reports":  d.get("totalReports", 0),
        "last_reported":  d.get("lastReportedAt", "Never"),
        "isp":            d.get("isp", "N/A"),
        "usage_type":     d.get("usageType", "N/A"),
        "domain":         d.get("domain", "N/A"),
        "country_code":   d.get("countryCode", "N/A"),
        "is_tor":         d.get("isTor", False),
        "is_whitelisted": d.get("isWhitelisted", False),
    }


def query_shodan(ip: str) -> dict:
    if not SHODAN_API_KEY:
        return {"error": "Shodan API key not set"}

    data = safe_get(
        f"{SHODAN_BASE}/shodan/host/{ip}",
        params={"key": SHODAN_API_KEY}
    )

    if "error" in data:
        return data

    services = []
    for item in data.get("data", []):
        services.append({
            "port":      item.get("port"),
            "transport": item.get("transport", "tcp"),
            "product":   item.get("product", ""),
            "version":   item.get("version", ""),
            "banner":    item.get("data", "")[:120].strip(),
        })

    return {
        "ports":       data.get("ports", []),
        "services":    services,
        "os":          data.get("os", "N/A"),
        "org":         data.get("org", "N/A"),
        "isp":         data.get("isp", "N/A"),
        "country":     data.get("country_name", "N/A"),
        "city":        data.get("city", "N/A"),
        "hostnames":   data.get("hostnames", []),
        "vulns":       list(data.get("vulns", {}).keys()),
        "last_update": data.get("last_update", "N/A"),
    }

# ─── RISK SCORING ─────────────────────────────────────────────────────────────

def calculate_risk_score(vt: dict, abuse: dict, shodan: dict) -> tuple:
    score = 0
    score += min(vt.get("malicious", 0) * 5, 40)
    score += min(vt.get("suspicious", 0) * 2, 10)
    score += int(abuse.get("abuse_score", 0) * 0.3)
    if abuse.get("is_tor"):
        score += 10
    score += min(len(shodan.get("vulns", [])) * 5, 20)
    score = min(score, 100)

    if score >= 70:   label = "CRITICAL"
    elif score >= 40: label = "HIGH"
    elif score >= 20: label = "MEDIUM"
    elif score >= 5:  label = "LOW"
    else:             label = "CLEAN"

    return score, label

# ─── HTML REPORT ──────────────────────────────────────────────────────────────

RISK_COLORS = {
    "CRITICAL": ("#ff3b3b", "#2d0000"),
    "HIGH":     ("#ff8c00", "#2d1500"),
    "MEDIUM":   ("#ffd700", "#2d2500"),
    "LOW":      ("#4fc3f7", "#001f2d"),
    "CLEAN":    ("#69f0ae", "#002d15"),
}

def build_html_report(ioc, ioc_type, vt, abuse, shodan, score, label):
    color, bg = RISK_COLORS.get(label, ("#ffffff", "#000000"))
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    def kv(key, val):
        return f'<tr><td class="key">{key}</td><td class="val">{val}</td></tr>'

    def section(title, rows_html):
        return f'<div class="card"><h2>{title}</h2><table>{rows_html}</table></div>'

    # VirusTotal block
    if "error" not in vt:
        total    = vt['malicious'] + vt['suspicious'] + vt['harmless'] + vt['undetected']
        vt_rows  = kv("Malicious detections", f"<span style='color:#ff3b3b;font-weight:bold'>{vt['malicious']}</span> / {total}")
        vt_rows += kv("Suspicious",  vt['suspicious'])
        vt_rows += kv("Harmless",    vt['harmless'])
        vt_rows += kv("Reputation",  vt['reputation'])
        vt_rows += kv("Country",     vt['country'])
        vt_rows += kv("AS Owner",    vt['as_owner'])
        if vt.get("tags"):
            vt_rows += kv("Tags", ", ".join(vt['tags']))
        if vt.get("file_name") and vt["file_name"] != "N/A":
            vt_rows += kv("File name", vt['file_name'])
            vt_rows += kv("File type", vt['file_type'])
            vt_rows += kv("File size", f"{vt['size']} bytes")
    else:
        vt_rows = kv("Status", f"<span style='color:#aaa'>{vt['error']}</span>")

    # AbuseIPDB block
    if "error" not in abuse:
        abuse_rows  = kv("Abuse confidence", f"<span style='color:#ff8c00;font-weight:bold'>{abuse['abuse_score']}%</span>")
        abuse_rows += kv("Total reports",  abuse['total_reports'])
        abuse_rows += kv("Last reported",  abuse['last_reported'] or "Never")
        abuse_rows += kv("ISP",            abuse['isp'])
        abuse_rows += kv("Usage type",     abuse['usage_type'])
        abuse_rows += kv("Country",        abuse['country_code'])
        abuse_rows += kv("Tor exit node",  "YES (high risk)" if abuse['is_tor'] else "No")
        abuse_rows += kv("Whitelisted",    "Yes" if abuse['is_whitelisted'] else "No")
    else:
        abuse_rows = kv("Status", f"<span style='color:#aaa'>{abuse.get('error', 'N/A')}</span>")

    # Shodan block
    if "error" not in shodan:
        ports_str    = ", ".join(str(p) for p in shodan['ports']) if shodan['ports'] else "None found"
        vulns_str    = ", ".join(shodan['vulns']) if shodan['vulns'] else "None detected"
        hostnames_str = ", ".join(shodan['hostnames']) if shodan['hostnames'] else "None"

        shodan_rows  = kv("Open ports", ports_str)
        shodan_rows += kv("OS",         shodan['os'])
        shodan_rows += kv("Org",        shodan['org'])
        shodan_rows += kv("ISP",        shodan['isp'])
        shodan_rows += kv("Location",   f"{shodan['city']}, {shodan['country']}")
        shodan_rows += kv("Hostnames",  hostnames_str)
        shodan_rows += kv("Known CVEs", f"<span style='color:#ff3b3b'>{vulns_str}</span>")
        shodan_rows += kv("Last seen",  shodan['last_update'])

        if shodan['services']:
            services_rows = "".join(
                f"<tr><td class='val'>{s['port']}/{s['transport']}</td>"
                f"<td class='val'>{s['product']} {s['version']}</td>"
                f"<td class='val' style='font-size:0.78em;color:#aaa'>{s['banner'][:80]}</td></tr>"
                for s in shodan['services'][:10]
            )
            shodan_rows += f"</table><h3 style='margin-top:1rem;color:#90caf9'>Services</h3><table><tr><th>Port</th><th>Product</th><th>Banner</th></tr>{services_rows}"
    else:
        shodan_rows = kv("Status", f"<span style='color:#aaa'>{shodan.get('error', 'N/A')}</span>")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Threat Intel Report - {ioc}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0d1117; color: #e6edf3; font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }}
  .header {{ border-bottom: 1px solid #21262d; padding-bottom: 1.5rem; margin-bottom: 2rem; }}
  .header h1 {{ font-size: 1.4rem; color: #58a6ff; letter-spacing: 0.05em; text-transform: uppercase; margin-bottom: 0.4rem; }}
  .ioc-badge {{ display: inline-block; background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 0.4rem 0.9rem; font-family: monospace; font-size: 1.1rem; margin: 0.5rem 0; }}
  .meta {{ font-size: 0.8rem; color: #7d8590; margin-top: 0.4rem; }}
  .risk-banner {{ display: flex; align-items: center; gap: 1.5rem; background: {bg}; border: 1px solid {color}; border-radius: 10px; padding: 1.2rem 1.8rem; margin-bottom: 2rem; }}
  .risk-score {{ font-size: 3.5rem; font-weight: 900; color: {color}; line-height: 1; }}
  .risk-label {{ font-size: 1.6rem; font-weight: 700; color: {color}; }}
  .risk-desc {{ font-size: 0.85rem; color: #aaa; margin-top: 0.3rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 1.5rem; }}
  .card {{ background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 1.4rem; }}
  .card h2 {{ font-size: 0.95rem; text-transform: uppercase; letter-spacing: 0.08em; color: #58a6ff; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid #21262d; }}
  .card h3 {{ font-size: 0.85rem; color: #90caf9; }}
  table {{ width: 100%; border-collapse: collapse; }}
  tr:not(:last-child) td {{ border-bottom: 1px solid #21262d; }}
  td {{ padding: 0.45rem 0; vertical-align: top; }}
  td.key {{ color: #7d8590; font-size: 0.82rem; width: 42%; padding-right: 1rem; }}
  td.val {{ font-size: 0.88rem; }}
  th {{ color: #7d8590; font-size: 0.78rem; text-transform: uppercase; padding-bottom: 0.4rem; border-bottom: 1px solid #21262d; }}
  footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #21262d; font-size: 0.78rem; color: #7d8590; text-align: center; }}
</style>
</head>
<body>
<div class="header">
  <h1>Threat Intelligence Report</h1>
  <div class="ioc-badge">{ioc}</div>
  <div class="meta">IOC Type: {ioc_type.upper()} &nbsp;|&nbsp; Generated: {ts}</div>
</div>
<div class="risk-banner">
  <div class="risk-score">{score}</div>
  <div>
    <div class="risk-label">{label}</div>
    <div class="risk-desc">Composite threat score (0-100) based on VirusTotal detections,<br>AbuseIPDB confidence, and Shodan vulnerability data.</div>
  </div>
</div>
<div class="grid">
  {section("VirusTotal", vt_rows)}
  {section("AbuseIPDB", abuse_rows)}
  {section("Shodan", shodan_rows)}
</div>
<footer>Generated by Threat Intel Automation Tool &nbsp;|&nbsp; Data sources: VirusTotal · AbuseIPDB · Shodan &nbsp;|&nbsp; For analyst use only</footer>
</body>
</html>"""

# ─── MAIN ─────────────────────────────────────────────────────────────────────

def run(ioc: str, output_json: bool = False) -> None:
    ioc      = ioc.strip()
    ioc_type = detect_ioc_type(ioc)

    print(f"\n[*] IOC      : {ioc}")
    print(f"[*] Type     : {ioc_type}")
    print(f"[*] Querying threat intelligence sources...\n")

    print("  -> VirusTotal...", end=" ", flush=True)
    vt = query_virustotal(ioc, ioc_type)
    print("done" if "error" not in vt else f"error: {vt['error']}")

    if ioc_type == "ip":
        print("  -> AbuseIPDB...", end=" ", flush=True)
        abuse = query_abuseipdb(ioc)
        print("done" if "error" not in abuse else f"error: {abuse['error']}")

        print("  -> Shodan...   ", end=" ", flush=True)
        shodan = query_shodan(ioc)
        print("done" if "error" not in shodan else f"error: {shodan['error']}")
    else:
        abuse  = {"error": "Only available for IPs"}
        shodan = {"error": "Only available for IPs"}
        print("  -> AbuseIPDB : skipped (not an IP)")
        print("  -> Shodan    : skipped (not an IP)")

    score, label = calculate_risk_score(vt, abuse, shodan)

    print(f"\n[!] Risk score : {score}/100")
    print(f"[!] Risk label : {label}")

    safe_ioc = ioc.replace(".", "_").replace("/", "_")

    if output_json:
        result = {
            "ioc": ioc, "type": ioc_type,
            "risk_score": score, "risk_label": label,
            "virustotal": vt, "abuseipdb": abuse, "shodan": shodan,
        }
        out_file = f"threat_report_{safe_ioc}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
    else:
        html     = build_html_report(ioc, ioc_type, vt, abuse, shodan, score, label)
        out_file = f"threat_report_{safe_ioc}.html"
        with open(out_file, "w", encoding="utf-8") as f:   # <-- UTF-8 fix
            f.write(html)

    print(f"\n[+] Report saved -> {out_file}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Automation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python threat_intel.py 8.8.8.8
  python threat_intel.py malware.example.com
  python threat_intel.py d41d8cd98f00b204e9800998ecf8427e
  python threat_intel.py 1.2.3.4 --output json

Environment variables required:
  VT_API_KEY           VirusTotal API key
  ABUSEIPDB_API_KEY    AbuseIPDB API key
  SHODAN_API_KEY       Shodan API key (optional - free tier limited)
        """
    )
    parser.add_argument("ioc", help="IP address, domain, or file hash to investigate")
    parser.add_argument("--output", choices=["html", "json"], default="html")
    args = parser.parse_args()
    run(args.ioc, output_json=(args.output == "json"))


if __name__ == "__main__":
    main()