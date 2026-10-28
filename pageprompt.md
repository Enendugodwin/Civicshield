# Implementation Prompt: AI-Powered Recovery Recommendations and Threat Intelligence Center

## Project Context

You are working on an existing cybersecurity application running locally at:

- **Recovery:** `http://localhost:5173/recovery`
- **Threat Intelligence:** `http://localhost:5173/threats`

Your task is to enhance these existing pages with functional, AI-powered cybersecurity capabilities. Do not create a separate application or rebuild the entire project.

First, inspect the existing codebase, architecture, components, API integrations, database schema, routing, authentication, and design system. Reuse the existing functionality and preserve the application's current visual identity.

The objective is to turn these pages into intelligent security operations interfaces that identify weaknesses, correlate global cyber threats with the organization's assets, and recommend actionable remediation steps.

---

# 1. Recovery Page — AI Remediation Recommendations

Route: `/recovery`

## Objective

When a device fails a security simulation, the application must automatically generate contextual AI recommendations explaining why it failed, how to resolve the issue, and how to verify that the fix works.

### 1.1 Simulation Results

Display the results of each device simulation, including:

- Device name and unique asset ID.
- Hostname, IP address, operating system, and device type, where available.
- Simulation name and execution timestamp.
- Overall result: Passed, Failed, Warning, or Not Evaluated.
- Security controls that passed or failed.
- Risk severity: Critical, High, Medium, or Low.
- Failed policies, misconfigurations, and missing controls.
- Relevant evidence, logs, and detected configuration issues.
- Business criticality and exposure level, if available.

Include summary cards for:

- Total devices simulated.
- Devices that passed.
- Devices that failed.
- Devices requiring remediation.
- Critical failures.
- Remediation completion rate.

Provide filtering by severity, device, simulation type, operating system, and remediation status.

### 1.2 AI Recommendations for Failed Devices

For every failed device, generate an AI remediation report grounded in the actual simulation results and available device telemetry.

Each report must contain:

**A. Failure explanation**
- What failed and why.
- The relevant security policy or control.
- Evidence supporting the finding.
- Potential impact if the issue remains unresolved.
- Relevant MITRE ATT&CK technique or security framework control, when applicable and verified.

**B. Recommended remediation**
- A concise summary of the recommended fix.
- Step-by-step instructions tailored to the affected operating system, platform, or security product.
- The expected secure configuration or desired state.
- Relevant official vendor documentation.
- Required permissions and dependencies.
- Potential operational impact, downtime, or compatibility concerns.
- A rollback procedure for changes that could disrupt production.

**C. Remediation actions**

Support appropriate actions such as:

- View full recommendation.
- Copy remediation commands.
- Export the remediation plan.
- Create a remediation task.
- Assign the task to a team or administrator.
- Mark the recommendation as accepted, rejected, or deferred.
- Mark remediation as completed.
- Rerun the relevant simulation.
- Compare the new results with the original failure.

Only show actions that the backend actually supports. Do not claim a fix was applied merely because a recommendation was generated.

### 1.3 AI Recommendation Engine

Build an AI service that accepts structured simulation results and relevant asset metadata.

Example input:

{
  "asset_id": "ASSET-1042",
  "hostname": "WORKSTATION-1042",
  "os": "Windows 11",
  "simulation": "Endpoint Security Baseline",
  "status": "failed",
  "findings": [
    {
      "control": "Endpoint protection",
      "severity": "high",
      "evidence": "Required protection service is disabled"
    }
  ]
}

The AI must produce a structured response containing:

- Finding summary.
- Root-cause hypothesis.
- Evidence and confidence level.
- Risk assessment.
- Prioritized remediation steps.
- Relevant commands or configuration changes.
- Required permissions.
- Potential side effects.
- Rollback instructions.
- Validation steps.
- Official references.
- Residual risk after remediation.

Use structured JSON output validated against a backend schema.

Do not allow the model to invent logs, asset properties, simulation results, CVEs, vendor advisories, or successful remediation outcomes.

Clearly distinguish confirmed findings from inferred root causes.

### 1.4 Recovery Workflow

Implement the following workflow:

1. A device simulation completes.
2. The backend stores the simulation result and evidence.
3. Failed controls are identified.
4. Findings are prioritized according to severity, asset criticality, and exposure.
5. The AI recommendation service analyzes the findings.
6. Recommendations are stored against the asset and simulation.
7. The frontend displays the results.
8. An administrator reviews and approves the proposed remediation.
9. The remediation is performed through an authorized integration or by an administrator.
10. The device is tested again.
11. The application records whether the issue was resolved.

Track recommendation status using appropriate states such as Pending Review, Approved, In Progress, Resolved, Failed Verification, and Deferred.

Avoid generating duplicate recommendations for the same unresolved finding unless new evidence or material changes justify an update.

---

# 2. Threats Page — Global Threat Intelligence and Internal Asset Exposure

Route: `/threats`

## Objective

Transform this page into an AI-powered threat intelligence and exposure management center.

The page must answer three questions:

1. What significant cyber threats and security advisories are emerging globally?
2. Which assets in my environment are affected or potentially exposed?
3. What should I do to mitigate or resolve each threat?

## 2.1 Recent Global Threat Advisories

Build a threat intelligence ingestion service that retrieves recent, verifiable cybersecurity advisories and threat reports from reputable sources.

Prioritize sources such as:

- CISA Known Exploited Vulnerabilities (KEV) Catalog.
- CISA Cybersecurity Advisories.
- NIST National Vulnerability Database (NVD).
- CERT/CC advisories.
- Microsoft Security Response Center.
- Cisco Security Advisories.
- Palo Alto Networks security advisories.
- Fortinet PSIRT advisories.
- Cloudflare security advisories and relevant threat reports.
- Relevant national CERTs and other trusted vendor security bulletins.

Use official APIs, RSS feeds, or supported public data sources where available.

Do not scrape websites in violation of their terms or depend on brittle HTML parsing when an official feed or API exists.

### Threat intelligence fields

Each threat record should include:

- Threat or advisory title.
- CVE ID, when applicable.
- Advisory identifier.
- Source organization.
- Original publication date.
- Last updated date.
- Date first ingested by the application.
- Threat category.
- Severity and CVSS score, when available.
- Exploitation status.
- Affected products and versions.
- Vulnerability description.
- Known indicators of compromise, when applicable.
- Threat actor attribution, only when supported by reliable sources.
- Official source URL.
- Data freshness and verification status.

Support filtering and searching by:

- Critical, High, Medium, and Low severity.
- Exploited versus not known to be exploited.
- Publication date.
- Vendor and product.
- CVE.
- Threat category.
- Affected assets.
- Source organization.

Sort important threats by a combination of verified exploitation status, severity, exposure, asset criticality, and relevance to the organization's environment.

Do not rank threats by CVSS alone.

## 2.2 Internal Asset Correlation

This is a core requirement.

The application must correlate incoming threat intelligence against the organization's actual asset inventory.

Retrieve available inventory data from the existing backend and connected sources, such as endpoint agents, vulnerability scanners, cloud inventory, CMDB, operating-system inventory, and authorized security integrations.

For each asset, use available attributes such as:

- Asset ID and hostname.
- Operating system and version.
- Installed software and versions.
- Exposed services and ports.
- Installed packages and libraries.
- Cloud platform and resource type.
- Firmware and network appliance versions.
- Vulnerability scan findings.
- Patch status.
- External exposure.
- Business criticality.
- Existing compensating controls.

Compare these attributes with advisory affected-product ranges, vulnerability conditions, and known prerequisites.

### Asset matching logic

Classify matches as:

- **Confirmed affected:** Available evidence establishes that the asset runs an affected product/version and meets the relevant vulnerability conditions.
- **Potentially affected:** The product or version is incomplete, ambiguous, or requires additional verification.
- **Not affected:** Reliable inventory evidence establishes that the asset is outside the affected conditions.
- **Unknown:** There is insufficient inventory or advisory information to determine exposure.

Do not label an asset vulnerable merely because its vendor appears in an advisory.

Account for version ranges, edition differences, patched releases, configuration prerequisites, and mitigating controls where the source provides that information.

If asset inventory is stale, missing, or incomplete, display the data-quality limitation.

### Threat-to-asset mapping

For every relevant advisory, display:

- Number of confirmed affected assets.
- Number of potentially affected assets.
- Number of assets requiring verification.
- Affected asset names and identifiers.
- Relevant product and version.
- Exposure evidence.
- Asset criticality.
- External accessibility, where known.
- Patch or remediation status.
- Last inventory update.
- Recommended next action.

Allow users to open an affected asset to see the detailed match evidence.

Include a relationship view or expandable panel showing:

Global Advisory → Vulnerability or Threat → Affected Product → Internal Asset → Recommended Remediation.

## 2.3 AI Threat Analysis

Generate an AI analysis for each significant advisory using the original source data and verified internal asset matches.

Each analysis should contain:

**Threat summary**
- What the vulnerability or threat is.
- How it may be exploited.
- Which products, versions, and configurations are affected.
- Whether exploitation is confirmed, reported, or unknown.
- Whether the advisory appears relevant to the current environment.

**Organizational impact**
- Which internal assets are affected.
- Which assets are potentially affected and require investigation.
- Likely business impact based on available asset metadata.
- Potential attack paths, but only where the necessary evidence exists.
- Whether the threat is relevant to externally exposed or business-critical assets.

**Recommended actions**
- Immediate containment measures, if justified.
- Patching or upgrading instructions.
- Temporary mitigations when patching is unavailable.
- Detection opportunities and relevant telemetry sources.
- Threat hunting queries or detection logic, where appropriate.
- Verification steps.
- Recovery and rollback guidance.
- Official vendor documentation.

**Priority**
Assign an actionable priority such as:

- P0 — Immediate response required.
- P1 — Urgent remediation.
- P2 — Planned remediation.
- P3 — Monitor or investigate.

Explain why the priority was assigned.

Priority must reflect more than the CVSS score. Consider known exploitation, asset exposure, business criticality, exploit prerequisites, compensating controls, and confidence in the asset match.

AI analysis must cite the advisory or vendor documentation used. Clearly label AI-generated assessments and uncertain conclusions.

## 2.4 Threat Dashboard

Create a dashboard containing:

- New advisories ingested within the last 24 hours.
- Critical and high-severity threats.
- Known exploited vulnerabilities relevant to the environment.
- Confirmed affected assets.
- Potentially affected assets.
- Critical assets with unresolved exposure.
- Threats with remediation overdue.
- Threat intelligence feed health and last successful synchronization.

Use real data from the backend. If there is no data, show a useful empty state and explain how to connect a source or import inventory.

Never display fabricated threats or invented asset counts as real results.

## 2.5 Threat Detail Page or Drawer

When a user selects a threat, show a detailed view with:

- Original advisory and source link.
- Publication and update dates.
- CVE details and severity.
- Exploitation status and evidence.
- Affected product/version ranges.
- AI-generated explanation.
- Internal asset matches and match confidence.
- Recommended remediation steps.
- Relevant detection and hunting guidance.
- Assigned owner and remediation status.
- Activity history and verification results.

Provide a clear separation between source-verified facts, internal inventory evidence, and AI-generated analysis.

## 2.6 Remediation Workflow

For a confirmed or potential match:

1. Open the threat.
2. Review the affected assets and supporting evidence.
3. Generate or inspect AI recommendations.
4. Assign an owner and due date.
5. Approve the proposed response.
6. Apply the fix using an authorized integration or documented manual procedure.
7. Rerun a vulnerability scan or another suitable verification check.
8. Update the asset's exposure status.
9. Record the outcome and audit history.

Where supported, integrate with existing ticketing, patch management, endpoint protection, SIEM, or vulnerability management systems.

Do not imply that an integration exists unless it has been implemented and configured.

---

# 3. Backend Architecture and Data Model

Inspect and reuse the current backend before adding new services.

Create or extend suitable models for:

- Assets.
- Asset software and versions.
- Simulation runs.
- Simulation findings.
- AI recommendations.
- Threat advisories.
- Affected-product ranges.
- Threat-to-asset matches.
- Remediation tasks.
- Remediation verification results.
- Threat feed synchronization status.
- Audit events.

Recommended conceptual relationships:

Asset → Simulation Run → Finding → AI Recommendation → Remediation Task → Verification Result.

Threat Advisory → Affected Product → Asset Match → AI Recommendation → Remediation Task.

Maintain a traceable connection between every AI recommendation and the source finding or threat advisory that produced it.

Implement database migrations, indexes, pagination, validation, and access controls appropriate to the existing stack.

Use background jobs or scheduled tasks for feed ingestion and expensive AI analysis. Avoid making the frontend wait for every advisory to be downloaded and analyzed.

Use incremental synchronization, deduplication, retry handling, rate limits, and source-specific error handling.

Do not run external threat feed requests directly from the browser when server-side processing is required.

---

# 4. AI Integration Requirements

Inspect the project's current AI provider and configuration.

Reuse an existing provider when available. Otherwise, implement a provider abstraction so the application can support a configured model without tightly coupling its business logic to one vendor.

Requirements:

- Configurable AI model and provider.
- Structured, schema-validated responses.
- Explicit timeouts and retry limits.
- Safe handling of provider failures.
- Input size limits.
- Appropriate caching of repeated analyses.
- Logging of analysis status and model/provider metadata.
- No exposure of API keys in frontend code.
- No secrets or unnecessary sensitive asset data sent to an external AI provider.
- A deterministic fallback when AI is unavailable.

The fallback should still provide rule-based severity, known advisory information, asset matching, and vendor remediation links. It must not pretend to be an AI-generated analysis.

Treat advisory descriptions, web content, logs, and other imported data as untrusted input. Do not let embedded instructions in those sources control the AI system or authorize actions.

AI must recommend security actions, not independently execute high-impact changes.

Require explicit authorization for patch deployment, service changes, device isolation, firewall changes, account disabling, or other potentially disruptive actions. Log approvals and execution outcomes.

---

# 5. User Interface and Experience

Preserve the existing design system, navigation, typography, colors, responsive behavior, and reusable components.

The pages should feel like parts of the same cybersecurity application.

### Recovery page layout

- Summary metrics at the top.
- Search, filters, and sorting.
- Device simulation results table or card list.
- Severity indicators.
- Expandable failed-device details.
- AI recommendation panel.
- Remediation task status and verification history.

### Threats page layout

- Threat exposure summary at the top.
- Recently published advisories.
- Critical threat and known-exploited vulnerability sections.
- Search, filters, and sorting.
- Threat cards or a data table with severity and exploitation indicators.
- Internal affected-asset counts.
- AI analysis panel.
- Threat detail drawer or dedicated detail route.
- Remediation tracking.

Use clear loading, empty, partial-data, stale-data, and error states. Avoid blank screens when one data source is unavailable.

Use accessible controls, keyboard navigation, readable contrast, responsive layouts, and pagination for large datasets.

Avoid unnecessary animations or visual clutter.

---

# 6. Security and Reliability

Implement:

- Authentication and role-based authorization consistent with the existing application.
- Server-side authorization for asset and remediation operations.
- Audit logging for approvals and changes.
- Input validation and output sanitization.
- Secure secret management.
- Rate limiting for expensive analysis endpoints.
- Protection against prompt injection in imported threat content.
- Safe rendering of untrusted advisory text.
- Read-only behavior by default for asset discovery.
- Explicit authorization for active scans or endpoint actions.
- Graceful handling of unavailable integrations.

Do not create fake live data to make the interface look functional.

If a source or integration is not configured, identify the missing dependency and show setup instructions.

---

# 7. API and Frontend Integration

Implement API endpoints that match the project's conventions.

Suggested capabilities include:

- Retrieve simulation runs and failed findings.
- Retrieve recommendations for a simulation or asset.
- Generate or refresh a recommendation.
- Create and update remediation tasks.
- Retrieve recent threat advisories.
- Retrieve threat details.
- Retrieve affected assets for an advisory.
- Retrieve advisories affecting an asset.
- Trigger a controlled feed synchronization.
- Request threat analysis.
- Update remediation status.
- Record verification results.
- Retrieve synchronization health and audit history.

These are conceptual endpoints, not mandatory literal paths. Follow the existing routing and naming conventions.

Connect both pages to real backend data, implement loading and error handling, and ensure that state changes persist after refreshing the browser.

Do not leave buttons as decorative elements.

---

# 8. Testing and Acceptance Criteria

Add unit tests, integration tests, and frontend tests appropriate to the existing project.

### Recovery acceptance criteria

- A failed simulation produces a recommendation linked to its actual finding.
- The recommendation contains actionable, OS-appropriate steps.
- Evidence and inferred root causes are distinguishable.
- A reviewer can approve, assign, and track remediation where implemented.
- Verification updates the finding's status only when supported by new evidence.
- An AI outage does not break the recovery page.
- Successful simulations do not receive unnecessary failure remediation.

### Threats acceptance criteria

- The system ingests real advisories from at least one functioning, verifiable source.
- Publication dates and source links are preserved.
- Duplicate advisories are handled correctly.
- Asset matching accounts for product and version evidence.
- Confirmed, potential, unaffected, and unknown statuses are distinguishable.
- Each relevant threat displays matching internal assets.
- AI recommendations reference verified advisory information.
- Missing inventory or feed data is communicated honestly.
- Feed synchronization failures are visible and recoverable.
- Remediation status and verification history persist.

### End-to-end acceptance criteria

- Both pages work with the current application's authentication and routing.
- The frontend and backend use consistent data models.
- No mock results are presented as live production intelligence.
- Sensitive data and credentials are not exposed.
- Existing features and pages continue working.
- Database migrations and setup instructions are documented.
- Tests pass, and all new dependencies are documented.

---

# 9. Implementation Instructions

Work in this order:

1. Inspect the full repository and identify the frontend, backend, database, AI provider, authentication, and existing simulation engine.
2. Summarize the current architecture and identify reusable components.
3. Trace the existing data flow for simulation results and assets.
4. Implement the Recovery page enhancements.
5. Implement the threat intelligence ingestion and normalization service.
6. Implement internal asset correlation.
7. Implement the AI analysis and recommendation service.
8. Implement the Threats page enhancements.
9. Connect remediation tracking and verification workflows.
10. Add tests, database migrations, configuration examples, and documentation.
11. Run the application and test both routes.
12. Fix integration issues and regressions before finishing.

Do not stop after producing a plan, mockup, or static frontend. Implement the functionality in the existing repository.

If an API key, asset connector, vulnerability scanner, or other external dependency is missing, implement the integration interface and clearly document the required configuration. Never fabricate successful integration results.

At completion, provide:

- A summary of files changed.
- The functionality implemented on each page.
- The threat intelligence sources configured.
- The AI provider and configuration required.
- Database migration and startup commands.
- Environment variables and external dependencies.
- Tests executed and their actual results.
- Remaining limitations or integrations requiring credentials.

**Final goal:** `/recovery` should tell the security team how to fix devices that fail simulations, while `/threats` should tell them which global cyber threats matter to their environment, which assets are exposed, and what actions to take next.