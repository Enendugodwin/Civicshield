"""Web context for the assistant: fresh public data from allowlisted hosts.

SAFETY CONTRACT (do not weaken):
- Only two hosts are ever contacted: services.nvd.nist.gov (CVE details)
  and www.cisa.gov (Known Exploited Vulnerabilities catalog). Any other host
  — including redirects landing elsewhere — aborts the fetch.
- Never fetch a user-supplied URL. CVE ids are validated against
  ^CVE-\\d{4}-\\d{4,}$ before interpolation; everything else is rejected.
- Bounded: short timeouts, response size cap, in-memory TTL cache plus a
  file cache mirroring vuln_intel conventions.
- Every failure degrades to clearly labeled offline data. Web-derived facts
  always carry source + retrieval time; they never override local records.
- Kill switch: set WEB_CONTEXT_ENABLED=0 to disable all outbound fetch.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import time
import urllib.request
from pathlib import Path

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
NVD_HOST = "services.nvd.nist.gov"
CISA_HOST = "www.cisa.gov"
KEV_URL = ("https://www.cisa.gov/sites/default/files/csv/"
           "known_exploited_vulnerabilities.csv")
TIMEOUT_SECONDS = 8
MAX_BYTES = 2 * 1024 * 1024
KEV_TTL = 24 * 3600
NVD_TTL = 7 * 24 * 3600
_CACHE_PATH = Path(__file__).parents[1] / "data" / "web_context_cache.json"

_mem: dict[str, tuple[float, dict]] = {}


def enabled() -> bool:
    return os.environ.get("WEB_CONTEXT_ENABLED", "1") != "0"


def _check_host(url: str, allowed: str) -> None:
    from urllib.parse import urlparse
    if urlparse(url).hostname != allowed:
        raise ValueError(f"host not allowlisted: {url}")


def _fetch(url: str, allowed_host: str, _opener=None) -> bytes:
    """GET with host pinning, timeout, and size cap. _opener is test-only."""
    _check_host(url, allowed_host)
    opener = _opener or (lambda req: urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS))
    req = urllib.request.Request(url, headers={"User-Agent": "CivicShield/1.0 (defensive demo)"})
    with opener(req) as resp:
        final = getattr(resp, "url", url) or url
        _check_host(final, allowed_host)  # redirects must stay on-host
        return resp.read(MAX_BYTES + 1)[:MAX_BYTES + 1]


def _load_file_cache() -> dict:
    try:
        with _CACHE_PATH.open("r", encoding="utf-8") as fh:
            v = json.load(fh)
            return v if isinstance(v, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_file_cache(data: dict) -> None:
    try:
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _CACHE_PATH.open("w", encoding="utf-8") as fh:
            json.dump(data, fh)
    except OSError:
        pass


def kev_lookup(cve_id: str, _opener=None) -> dict:
    """CISA KEV status for a CVE. Returns {known_exploited, ...} or {error}."""
    cve_id = (cve_id or "").strip().upper()
    if not CVE_RE.match(cve_id):
        return {"error": f"invalid CVE id '{cve_id}'"}
    if not enabled():
        return {"error": "web context disabled"}
    now = time.time()
    hit = _mem.get("kev")
    rows = None
    if hit and now - hit[0] < KEV_TTL:
        rows = hit[1].get("rows")
    if rows is None:
        try:
            raw = _fetch(KEV_URL, CISA_HOST, _opener)
            rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8", "replace"))))
            _mem["kev"] = (now, {"rows": rows, "retrieved_at": now})
        except Exception as exc:  # noqa: BLE001 - degraded, never fatal
            return {"error": f"KEV catalog unreachable: {type(exc).__name__}"}
    for r in rows:
        if str(r.get("cveID", "")).strip().upper() == cve_id:
            return {"known_exploited": True, "cve_id": cve_id,
                    "vendor": r.get("vendorProject", ""), "product": r.get("product", ""),
                    "vuln_name": r.get("vulnerabilityName", ""),
                    "due_date": r.get("dueDate", ""),
                    "source": "CISA Known Exploited Vulnerabilities catalog",
                    "retrieved_at": _mem["kev"][1].get("retrieved_at", now)}
    return {"known_exploited": False, "cve_id": cve_id,
            "source": "CISA Known Exploited Vulnerabilities catalog",
            "retrieved_at": now}


def nvd_summary(cve_id: str, _opener=None) -> dict:
    """NVD description + CVSS for a CVE. Returns facts or {error}."""
    cve_id = (cve_id or "").strip().upper()
    if not CVE_RE.match(cve_id):
        return {"error": f"invalid CVE id '{cve_id}'"}
    if not enabled():
        return {"error": "web context disabled"}
    now = time.time()
    key = f"nvd:{cve_id}"
    hit = _mem.get(key)
    if hit and now - hit[0] < NVD_TTL:
        return hit[1]
    file_cache = _load_file_cache()
    if key in file_cache and now - file_cache[key].get("at", 0) < NVD_TTL:
        _mem[key] = (file_cache[key]["at"], file_cache[key]["data"])
        return file_cache[key]["data"]
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        raw = _fetch(url, NVD_HOST, _opener)
        body = json.loads(raw.decode("utf-8"))
        vulns = body.get("vulnerabilities") or []
        if not vulns:
            return {"error": f"{cve_id} not found in NVD"}
        cve = vulns[0].get("cve", {})
        desc = ""
        for d in cve.get("descriptions") or []:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        metrics = cve.get("metrics", {}) or {}
        cvss = ""
        for family in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(family) or []
            if arr:
                data = arr[0].get("cvssData", {})
                cvss = f"{data.get('baseScore', '?')} {data.get('baseSeverity', '')}".strip()
                break
        out = {"cve_id": cve_id, "description": desc[:1200],
               "cvss": cvss, "published": (cve.get("published", "") or "")[:10],
               "source": "NVD (services.nvd.nist.gov)", "retrieved_at": now}
        _mem[key] = (now, out)
        file_cache[key] = {"at": now, "data": out}
        _save_file_cache(file_cache)
        return out
    except Exception as exc:  # noqa: BLE001 - degraded, never fatal
        return {"error": f"NVD unreachable: {type(exc).__name__}"}


def cve_context(cve_id: str, _opener=None) -> dict:
    """Combined NVD + KEV context with per-source labeling."""
    return {"nvd": nvd_summary(cve_id, _opener), "kev": kev_lookup(cve_id, _opener)}
