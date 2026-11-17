import socket
from urllib.parse import urlsplit
import requests


def get_network_intelligence(url: str) -> dict:
    raw_url = str(url).strip()
    parse_target = raw_url if "://" in raw_url else f"http://{raw_url}"

    try:
        hostname = (urlsplit(parse_target).hostname or "").strip().lower()
    except ValueError:
        hostname = ""

    if not hostname:
        return {
            "dns_resolution_status": "Invalid Hostname",
            "resolved_ip": "N/A",
            "server_country": "Unknown",
            "server_region_city": "Unknown",
            "isp_asn_organization": "Unknown"
        }

    try:
        resolved_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return {
            "dns_resolution_status": "Unresolved (NXDOMAIN)",
            "resolved_ip": "N/A",
            "server_country": "Unregistered / Offline Host",
            "server_region_city": "N/A",
            "isp_asn_organization": "N/A"
        }

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{resolved_ip}",
            params={"fields": "status,country,regionName,city,isp,org,as"},
            timeout=3
        )
        geo = resp.json()

        if geo.get("status") == "success":
            region = geo.get("regionName", "")
            city = geo.get("city", "")
            location_str = f"{city}, {region}".strip(", ") or "Unknown"
            isp_org = geo.get("org") or geo.get("isp") or "Unknown"
            asn = geo.get("as", "")
            isp_asn = f"{isp_org} ({asn})".strip() if asn else isp_org

            return {
                "dns_resolution_status": "Resolved",
                "resolved_ip": resolved_ip,
                "server_country": geo.get("country", "Unknown"),
                "server_region_city": location_str,
                "isp_asn_organization": isp_asn
            }
    except Exception:
        pass

    return {
        "dns_resolution_status": "Resolved",
        "resolved_ip": resolved_ip,
        "server_country": "Lookup Timeout",
        "server_region_city": "Lookup Timeout",
        "isp_asn_organization": "Lookup Timeout"
    }