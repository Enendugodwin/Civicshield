"""Web context: allowlisted, bounded, offline-tolerant. No real network here."""
import io
import json

from app import web_context as wc


class _Resp:
    def __init__(self, body: bytes, url: str):
        self._body = body
        self.url = url

    def read(self, n=-1):
        return self._body if n is None or n < 0 else self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


KEV_CSV = ("cveID,vendorProject,product,vulnerabilityName,dateAdded,dueDate,"
           "requiredAction,notes\n"
           "CVE-2024-1234,TestVendor,TestOS,Test flaw,2024-01-01,2024-02-01,"
           "Apply updates.,https://example.com\n").encode()

NVD_JSON = json.dumps({
    "vulnerabilities": [{
        "cve": {"id": "CVE-2024-1234", "published": "2024-01-01T00:00Z",
                "descriptions": [{"lang": "en",
                                  "value": "Test flaw allows remote code execution."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {
                    "baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}}]}).encode()


def _opener_factory():
    def opener(req):
        url = req.full_url
        if "cisa.gov" in url:
            return _Resp(KEV_CSV, url)
        if "nvd.nist.gov" in url:
            return _Resp(NVD_JSON, url)
        raise AssertionError(f"unexpected host: {url}")
    return opener


def test_invalid_cve_rejected_before_network():
    assert "error" in wc.nvd_summary("not-a-cve")
    assert "error" in wc.kev_lookup("CVE-123")


def test_kev_found_and_missing():
    op = _opener_factory()
    hit = wc.kev_lookup("CVE-2024-1234", _opener=op)
    assert hit["known_exploited"] is True and hit["product"] == "TestOS"
    assert "CISA" in hit["source"] and hit["retrieved_at"]
    miss = wc.kev_lookup("CVE-2024-9999", _opener=op)
    assert miss["known_exploited"] is False


def test_nvd_parses_description_and_cvss():
    out = wc.nvd_summary("CVE-2024-1234", _opener=_opener_factory())
    assert "remote code execution" in out["description"]
    assert out["cvss"] == "9.8 CRITICAL"
    assert "NVD" in out["source"]


def _isolated(monkeypatch, tmp_path):
    wc._mem.clear()
    monkeypatch.setattr(wc, "_CACHE_PATH", tmp_path / "webcache.json")


def test_offline_degrades_to_error_dicts(monkeypatch, tmp_path):
    _isolated(monkeypatch, tmp_path)

    def down(req):
        raise OSError("no route")
    assert "error" in wc.nvd_summary("CVE-2024-1234", _opener=down)
    assert "error" in wc.kev_lookup("CVE-2024-1234", _opener=down)


def test_off_host_redirect_rejected(monkeypatch, tmp_path):
    _isolated(monkeypatch, tmp_path)
    evil = _Resp(KEV_CSV, "https://evil.example.com/kev.csv")
    assert "error" in wc.kev_lookup("CVE-2024-1234",
                                    _opener=lambda req: evil)


def test_kill_switch(monkeypatch):
    monkeypatch.setenv("WEB_CONTEXT_ENABLED", "0")
    assert "error" in wc.nvd_summary("CVE-2024-1234")
