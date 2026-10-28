#!/usr/bin/env python3
"""CivicShield read-only evidence collector.

Run this on an *authorized* host. It gathers local configuration evidence with
allow-listed, read-only commands and can push the result to a CivicShield API:

    python civicshield_agent.py collect --asset-id 4 --push \
        --api http://127.0.0.1:8000 --token operator

It does not scan the network, open ports, brute force, or change the host.
Missing information is omitted so the assessment engine reports UNKNOWN rather
than inventing a pass or a failure.

Supported: Linux (Debian/Ubuntu and RPM families), Windows 10/11, macOS
(partial). Use --quick to skip software inventory on constrained hosts.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

VERSION = "1.1.0"
MAX_SOFTWARE = 80

# Package names that matter to the bundled advisories. Keeping the inventory
# narrow reduces sensitive data collection and keeps the payload small.
PACKAGE_ALLOWLIST = {
    "openssh-server", "openssh-client", "openssl", "libssl1.1", "libssl3",
    "libssl3t64", "libc6", "glibc", "curl", "libcurl4", "libcurl3-gnutls",
    "xz-utils", "liblzma5", "apache2", "nginx", "jenkins", "log4j-core",
    "openjdk-11-jre", "openjdk-17-jre", "postgresql-14", "postgresql-15",
    "mysql-server", "mariadb-server", "docker.io", "containerd.io", "sudo",
}

EDR_PROCESSES = {
    "falcon-sensor", "falconctl", "sentinelone", "sentinelagent",
    "cbagentd", "cbsensor", "osqueryd", "wazuh-agentd", "elastic-agent",
    "csfalconservice.exe", "sentinelagent.exe", "cb.exe", "osqueryd.exe",
}


def _run(cmd: List[str], timeout: float = 5.0) -> str:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            errors="replace", check=False,
        )
        return proc.stdout.strip() if proc.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _powershell(script: str, timeout: float = 6.0) -> str:
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        return ""
    return _run([exe, "-NoProfile", "-NonInteractive", "-Command", script], timeout)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _supported_os(name: str, version: str) -> Optional[bool]:
    """Small lifecycle table. None = we do not know, not 'unsupported'."""
    text = f"{name} {version}".lower()
    if "windows 10" in text:
        return False  # end of support 2025-10-14
    if "windows 11" in text:
        return True
    if "server 2012" in text or "server 2016" in text:
        return False
    if "server 2019" in text or "server 2022" in text or "server 2025" in text:
        return True
    if "ubuntu 18.04" in text or "ubuntu 20.04" in text:
        return False
    if "ubuntu 22.04" in text or "ubuntu 24.04" in text or "ubuntu 26.04" in text:
        return True
    if "debian 10" in text or "debian 11" in text:
        return False
    if "debian 12" in text or "debian 13" in text:
        return True
    if "rhel 7" in text or "centos 7" in text or "centos 8" in text:
        return False
    if "rhel 8" in text or "rhel 9" in text or "rocky 8" in text or "rocky 9" in text \
            or "almalinux 8" in text or "almalinux 9" in text:
        return True
    if "macos" in text or "mac os" in text:
        return True
    return None


def _os_info() -> Dict[str, Any]:
    system = platform.system()
    if system == "Linux":
        name, version = "Linux", platform.release()
        try:
            text = Path("/etc/os-release").read_text(encoding="utf-8", errors="replace")
            vals = dict(re.findall(r'^([A-Z_]+)="?([^"\n]*)"?', text, re.M))
            if vals.get("NAME"):
                name = vals["NAME"]
            version = vals.get("VERSION_ID") or version
        except OSError:
            pass
        return {"name": f"{name} {version}".strip(), "version": version,
                "kernel": platform.release(), "supported": _supported_os(name, version)}
    if system == "Windows":
        release = platform.release()
        build = platform.version()
        name = f"Windows {release}" if release else "Windows"
        if release == "10" and build:
            try:
                if int(build.split(".")[-1]) >= 22000:
                    name = "Windows 11"
            except ValueError:
                pass
        return {"name": name, "version": build, "build": build,
                "supported": _supported_os(name, build)}
    if system == "Darwin":
        version = platform.mac_ver()[0]
        return {"name": "macOS", "version": version,
                "supported": _supported_os("macOS", version)}
    return {"name": system, "version": platform.release(), "supported": None}


def _patch_info() -> Optional[Dict[str, Any]]:
    system = platform.system()
    if system == "Windows":
        raw = _powershell(
            "Get-HotFix | Sort-Object InstalledOn -Descending | "
            "Select-Object -First 1 -ExpandProperty InstalledOn"
        )
        raw = raw.strip()
        if raw:
            try:
                # Locale-dependent short date; let PowerShell format it instead.
                iso = _powershell(
                    "$h = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1;"
                    " if ($h) { $h.InstalledOn.ToUniversalTime().ToString('o') }"
                ).strip()
                if iso:
                    return {"last_applied": iso, "max_age_days": 30,
                            "source": "Get-HotFix (latest installed update)"}
            except Exception:
                pass
    if system == "Linux":
        candidates = ["/var/lib/dpkg/status", "/var/lib/rpm/.rpm.lock", "/var/lib/apt/lists"]
        for path in candidates:
            try:
                ts = os.path.getmtime(path)
            except OSError:
                continue
            return {"last_applied": _iso(ts), "max_age_days": 30,
                    "source": f"package database mtime ({path})"}
    return None


def _firewall() -> Optional[Dict[str, Any]]:
    system = platform.system()
    if system == "Linux":
        if shutil.which("ufw"):
            out = _run(["ufw", "status"], timeout=4)
            if "Status: active" in out:
                return {"ingress": "restricted", "source": "ufw"}
            if "Status: inactive" in out:
                return {"ingress": "allow-all", "source": "ufw"}
        if shutil.which("firewall-cmd"):
            out = _run(["firewall-cmd", "--state"], timeout=4)
            if out == "running":
                return {"ingress": "restricted", "source": "firewalld"}
        if shutil.which("nft"):
            out = _run(["nft", "list", "ruleset"], timeout=4)
            if out and "hook input" in out:
                return {"ingress": "restricted", "source": "nftables"}
    if system == "Windows":
        out = _powershell(
            "$p = Get-NetFirewallProfile; "
            "'{0}/{1}' -f (@($p | Where-Object Enabled -eq $true).Count), $p.Count"
        ).strip()
        if "/" in out:
            enabled, total = out.split("/", 1)
            if enabled.isdigit() and total.isdigit() and int(total) > 0:
                if int(enabled) == 0:
                    return {"ingress": "allow-all", "source": "Windows Firewall profiles"}
                if int(enabled) == int(total):
                    return {"ingress": "restricted", "source": "Windows Firewall profiles"}
                return {"ingress": "partial", "source": "Windows Firewall profiles"}
    return None


def _listeners() -> List[Dict[str, Any]]:
    system = platform.system()
    rows: List[Dict[str, Any]] = []
    if system == "Linux" and shutil.which("ss"):
        out = _run(["ss", "-H", "-tuln"], timeout=4)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0]
            local = parts[4]
            m = re.match(r"^(.*):(\d+)$", local)
            if m:
                rows.append({"proto": proto, "address": m.group(1), "port": int(m.group(2))})
    elif system == "Windows":
        out = _powershell(
            "Get-NetTCPConnection -State Listen | "
            "ForEach-Object { '{0}:{1}' -f $_.LocalAddress, $_.LocalPort }"
        )
        for line in out.splitlines():
            m = re.match(r"^(.*):(\d+)$", line.strip())
            if m:
                rows.append({"proto": "tcp", "address": m.group(1), "port": int(m.group(2))})
    return sorted(rows, key=lambda x: (x["port"], x["address"]))[:100]


def _identity() -> Optional[Dict[str, Any]]:
    system = platform.system()
    accounts: List[str] = []
    if system == "Linux":
        for group in ("sudo", "wheel"):
            out = _run(["getent", "group", group], timeout=3)
            if out and ":" in out:
                accounts.extend(x.strip() for x in out.split(":")[-1].split(",") if x.strip())
    elif system == "Windows":
        out = _powershell(
            "$g = Get-LocalGroup -SID S-1-5-32-544; "
            "Get-LocalGroupMember -Group $g | Select-Object -ExpandProperty Name"
        )
        accounts = [line.strip().split("\\")[-1] for line in out.splitlines() if line.strip()]
    if not accounts:
        return None
    uniq = sorted(set(accounts))
    return {
        "privileged_accounts": [{"name": a, "mfa": None} for a in uniq],
        "admin_count": len(uniq),
        "note": "MFA and last-login data are not readable locally; they are reported as unknown.",
    }


def _endpoint() -> Dict[str, Any]:
    system = platform.system()
    out: Dict[str, Any] = {}
    if system == "Linux":
        proc = _run(["ps", "-eo", "comm="], timeout=4).lower()
        out["edr_installed"] = any(name in proc for name in EDR_PROCESSES)
        out["logging_enabled"] = _run(
            ["systemctl", "is-active", "systemd-journald"], timeout=3
        ).strip() == "active"
    elif system == "Windows":
        tasks = _powershell("Get-Process | Select-Object -ExpandProperty ProcessName").lower()
        out["edr_installed"] = any(
            name.removesuffix(".exe") in tasks for name in EDR_PROCESSES
        ) or "msmpeng" in tasks  # Defender counts as endpoint protection
        out["logging_enabled"] = _powershell(
            "(Get-Service -Name EventLog).Status"
        ).strip().lower() == "running"
    else:
        return {}
    out["source"] = "local process/service inventory"
    return out


def _software() -> List[Dict[str, str]]:
    system = platform.system()
    items: List[Dict[str, str]] = []
    if system == "Linux":
        if shutil.which("dpkg-query"):
            out = _run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], timeout=8)
            for line in out.splitlines():
                if "\t" not in line:
                    continue
                name, version = line.split("\t", 1)
                if name.lower() in PACKAGE_ALLOWLIST:
                    items.append({"name": name, "version": version, "ecosystem": "deb"})
        elif shutil.which("rpm"):
            out = _run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], timeout=8)
            for line in out.splitlines():
                if "\t" not in line:
                    continue
                name, version = line.split("\t", 1)
                if name.lower() in PACKAGE_ALLOWLIST:
                    items.append({"name": name, "version": version, "ecosystem": "rpm"})
    elif system == "Windows":
        out = _powershell(
            "$paths = @('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
            "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
            "Get-ItemProperty $paths -ErrorAction SilentlyContinue | "
            "Where-Object { $_.DisplayName } | "
            "ForEach-Object { '{0}`t{1}' -f $_.DisplayName, $_.DisplayVersion }"
        )
        for line in out.splitlines():
            if "\t" not in line:
                continue
            name, version = line.split("\t", 1)
            if name.strip() and version.strip():
                items.append({"name": name.strip(), "version": version.strip(),
                              "ecosystem": "windows"})
    if system in ("Windows", "Darwin"):
        os_info = _os_info()
        items.insert(0, {"name": os_info.get("name", platform.system()),
                         "version": os_info.get("version", platform.release()),
                         "ecosystem": "windows" if system == "Windows" else "macos"})
    seen = set()
    out_items: List[Dict[str, str]] = []
    for item in items:
        key = (item["name"].lower(), item["version"])
        if key in seen:
            continue
        seen.add(key)
        out_items.append(item)
    return out_items[:MAX_SOFTWARE]


def _unnecessary_services(listeners: List[Dict[str, Any]]) -> List[str]:
    """Only evidence-backed legacy services, never a guess."""
    risky = {23: "telnet", 21: "ftp", 69: "tftp", 513: "rlogin", 514: "rsh"}
    found = sorted({name for item in listeners if item["port"] in risky
                    for name in [risky[item["port"]]]})
    return found


def collect_evidence(quick: bool = False, exposure: Optional[str] = None,
                     hostname: Optional[str] = None) -> Dict[str, Any]:
    """Collect read-only evidence. `exposure` is an operator declaration."""
    started = time.time()
    os_info = _os_info()
    listeners = [] if quick else _listeners()
    evidence: Dict[str, Any] = {
        "collector": {
            "source": "civicshield-agent",
            "version": VERSION,
            "collected_at": started,
            "hostname": hostname or socket.gethostname(),
            "platform": platform.platform(),
        },
        "hostname": hostname or socket.gethostname(),
        "os": os_info,
    }
    patch = _patch_info()
    if patch:
        evidence["patch"] = patch
    firewall = _firewall()
    if firewall:
        evidence["firewall"] = firewall
    if listeners:
        evidence["network"] = {"listening": listeners}
    if exposure:
        evidence.setdefault("network", {})["remote_admin_exposed"] = exposure in ("wan", "internet")
        evidence["network"]["zone"] = exposure
    unwanted = _unnecessary_services(listeners)
    if unwanted:
        evidence["services"] = {"unnecessary": unwanted}
    identity = _identity()
    if identity:
        evidence["identity"] = identity
    endpoint = _endpoint()
    if endpoint:
        evidence["endpoint"] = endpoint
    if not quick:
        software = _software()
        if software:
            evidence["software"] = software
    return evidence


def push(api: str, asset_id: int, evidence: Dict[str, Any], token: str,
         run_detection: bool = False) -> Dict[str, Any]:
    url = f"{api.rstrip('/')}/api/assets/{asset_id}/evidence"
    payload = json.dumps({
        "evidence": evidence,
        "collected_at": evidence.get("collector", {}).get("collected_at"),
        "collector_version": VERSION,
        "source": "civicshield-agent",
        "run_detection": run_detection,
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={"Content-Type": "application/json",
                 "X-Role": "operator",
                 "Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="CivicShield read-only evidence collector")
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("collect", help="collect local evidence")
    c.add_argument("--api", default="http://127.0.0.1:8000")
    c.add_argument("--asset-id", type=int)
    c.add_argument("--push", action="store_true", help="POST evidence to the CivicShield API")
    c.add_argument("--run-detection", action="store_true", help="run detection after pushing")
    c.add_argument("--token", default="operator")
    c.add_argument("--out", help="write evidence JSON to this file")
    c.add_argument("--quick", action="store_true", help="skip software inventory")
    c.add_argument("--exposure", choices=["internal", "wan", "internet", "none"],
                   help="operator declaration of remote-admin exposure")
    c.add_argument("--hostname", help="override the hostname label")
    args = parser.parse_args(argv)

    evidence = collect_evidence(quick=args.quick, exposure=args.exposure,
                                hostname=args.hostname)
    text = json.dumps(evidence, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(text)
    if args.push:
        if not args.asset_id:
            print("--push requires --asset-id", file=sys.stderr)
            return 2
        try:
            result = push(args.api, args.asset_id, evidence, args.token,
                          run_detection=args.run_detection)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            print(f"push failed: {exc}", file=sys.stderr)
            return 1
        summary = {k: result.get(k) for k in ("asset_id", "collected_at", "software_count")}
        if "detection" in result:
            d = result["detection"]
            summary["detection"] = {k: d.get(k) for k in (
                "run_id", "outcomes", "vulnerabilities", "critical_vulnerabilities")}
        print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
