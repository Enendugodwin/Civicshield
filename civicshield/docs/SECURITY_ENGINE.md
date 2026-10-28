# Security Engine (BaselineGuard)

Deterministic rules over asset evidence; missing evidence → UNKNOWN, never invented FAIL/PASS.

Detection also includes version-based known-vulnerability matching (`app/vuln_intel.py`)
and a read-only collector (`backend/agent/civicshield_agent.py`). Only FAIL controls
and vulnerability matches become findings; see `docs/DETECTION.md`. Each rule: id, name, category, version, inputs, logic. Examples: OWN-001 missing owner; OS-002 unsupported OS; PATCH-003 overdue patches; RADMIN-004 exposed RDP/SSH; FW-005 overly broad firewall; SVC-006 unnecessary services; MFA-007 no MFA on privileged; PERM-008 excessive admin; SHARED-009 shared privileged account; STALE-010 stale privileged; LP-011 no least-privilege evidence; EDR-012 missing endpoint protection; LOG-013 logging disabled; MON-014 monitoring gaps; BASE-015 unverified baseline; BKUP-016 stale backup; BKUP-017 no immutable backup; REC-018 recovery test overdue; BKDEP-019 missing backup dep; RECPROC-020 no recovery procedure. Outcomes PASS/FAIL/UNKNOWN/NOT_APPLICABLE with evidence refs.
