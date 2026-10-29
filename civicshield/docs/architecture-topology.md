# Architecture topology schema

How to describe infrastructure so CivicShield can import it. All uploads are
**parsed and validated but never executed**. Unknown values become warnings
with safe defaults; nothing commits without explicit approval.

## Supported formats

- **CSV inventory** (`.csv`): header row with `name` (required), `kind`
  (or `type` alias), `hostname`, `zone`, `owner`, `os_name`, `criticality`,
  plus optional `depends_on`, `authenticates_via`, and `connects_to` columns
  holding semicolon-separated target names.
- **JSON inventory** (`.json`): `{"nodes": [...same fields plus optional id...],
  "edges": [{"source": "<name-or-id>", "target": "<name-or-id>", "rel": "..."}]}`.
- **Mermaid** (`.mmd`): flowchart/graph subset —
  `web[Web Frontend] -->|depends_on| gw[Gateway Firewall]`. Node labels become
  names; edge labels become relations (default `depends_on`).

Uploads are capped at 1MB and 100 stored warnings per batch.

## Canonical vocabulary

- **Node kinds**: router, switch, firewall, server, database, workstation,
  identity, monitoring, backup, gateway, service, external, other.
  Aliases resolve common names (`fw` → firewall, `idp` → identity,
  `db` → database, `siem` → monitoring, `vendor` → external, …).
- **Zones**: core, office, plant, dmz, central, edge, external.
- **Relations**: depends_on, authenticates_via, monitors, backs_up, serves,
  connects_to, manages. Aliases resolve (`requires` → depends_on,
  `auth` → authenticates_via, …).
- **Edge provenance**: observed (collector evidence), configured (declared
  config), inferred (derived), simulated (scenario), imported (this pipeline,
  with `evidence_ref: import-batch:<id>`), manual (hand-entered).

## Staged workflow

1. `POST /api/architecture/import` → parses to a **preview** batch with node/edge
   counts and warnings. No records change.
2. `GET /api/architecture/imports/{id}` → inspect staged nodes/edges.
3. `POST .../commit` → matches nodes to existing assets by name/hostname
   (reuses them), creates the rest, skips identical edges (idempotent).
   `POST .../discard` abandons the batch. Committing twice is rejected (409).
4. `GET /api/architecture/graph` → normalized graph with edge provenance for
   topology views.

## Architecture checks (AR-*)

`GET /api/architecture/checks` evaluates six deterministic structural rules
over the normalized graph (no writes); `POST /api/architecture/checks/raise`
upserts `architecture`-source findings with risk scores, reopens still-failing
resolved findings, and resolves findings whose structure was fixed. The
Findings page offers one-click **Run architecture checks** plus an
`Architecture graph` source filter, and each AR finding links to the map.

| Rule | What fires | Evidence |
|------|------------|----------|
| AR-SPF-01 Single point of failure | high/critical asset with 3+ recorded dependents and no failover peer | dependent asset ids + relationship ids (confirmed) |
| `failover` relationship | active/standby redundancy: the peer takes over when the device is down; clears AR-SPF-01, never an attack-traversal path | the relationship (a device cannot fail over to itself) |
| AR-EXP-01 External exposure path | direct edge from an external asset/zone to a high-value asset | the relationship (confirmed) |
| AR-SEG-01 Workstation in core/dmz | workstation asset in core or dmz zone | the asset record (confirmed) |
| AR-MON-01 Unmonitored sensitive store | critical database/identity/backup with no `monitors` link | asset; inventory may be incomplete (inferred) |
| AR-BKP-01 Database without backup path | high-value database with no backup relationship | asset; inventory may be incomplete (inferred) |
| AR-CYC-01 Dependency cycle | circular depends_on/authenticates_via chain | cycle member assets (confirmed) |

Absence-based rules (MON, BKP) report `inferred` status and say so in the
finding detail: either the control is missing or the link is missing from
the inventory. Findings page remediation drafts can be generated per AR
finding like any other finding.

## Attack-path analysis

`POST /api/analysis/attack-paths` computes defensive reachability from
entry points (external/edge-zone assets, or an explicit start) to high-value
assets (critical/high criticality, or an explicit target). Traversal is
limited to declared relationships with fixed semantics: `connects_to` is
bidirectional lateral movement (assumed); `depends_on` yields downstream
impact (control NOT implied) and upstream dependency targeting;
`authenticates_via` yields credential paths; `manages` yields a declared
control path. Serving, monitoring, backup, and unknown relations are never
traversed for movement.

Only `observed`-provenance edges count as confirmed connectivity; every other
hop carries its assumption in plain language, and `simulated` edges are
flagged hypothetical — never presented as confirmed exploits. Paths rank by
a documented score (fewer hops, open critical findings, target value, zone
crossings, minus assumed hops) with deterministic tiebreaks. Each path also
reports its blast radius (downstream assets + services). The Attack Paths
page offers entry/target/depth selection plus per-hop **Exclude & re-run**
for what-if comparison of a defensive cut.

## Change proposals and simulation

`POST /api/architecture/proposals` stages graph edits (`remove_edge`,
`add_edge`, `update_asset` with eager validation) without touching live
records. `POST .../simulate` copies the inventory snapshot, applies the
edits, and diffs AR-* hits and attack paths before/after; `must_block`
asserts an (entry, target) pair has no simulated path, `must_keep` asserts
a relationship survives. Results are labeled simulation and stored on the
proposal. Lifecycle `draft → simulated → approved → applied` is enforced
(`approved` before `apply`); applying writes live records with `configured`
provenance and an audit trail, then the change can be verified by re-running
checks. The Attack Paths page can stage its exclusions as a proposal in one
click; the Proposals page builds, simulates, verifies, approves, and applies.
