# MASTER DEVELOPMENT PROMPT — CIVICSHIELD SERVICE HEALTH & AFFECTED ASSETS INTELLIGENCE DASHBOARD

## 1. Role and Objective

Act as a senior full-stack engineer, cybersecurity architect, UI/UX designer, geospatial visualization engineer and DevSecOps specialist.

Build a complete, functional, production-minded dashboard for **CivicShield**, an AI-assisted cybersecurity and resilience platform designed to protect essential community services, including water utilities, electricity infrastructure, local government, healthcare infrastructure and other critical services.

Use the user-provided Aegis Nexus screenshot as the primary visual reference. Recreate its dark executive dashboard, compact metrics, left navigation, workspace tabs, interactive geospatial map, affected-assets table and floating executive-perspective menu. Use original CivicShield branding and implementation.

This is an implementation task, not a request for a proposal or static mockup. Inspect the existing repository, build the application in the actual project workspace, run it, test the interactions and resolve implementation errors.

Do not replace an existing application unnecessarily. If CivicShield already has a backend, database, authentication system or shared components, reuse compatible functionality and integrate the dashboard into the existing architecture.

## 2. Product Vision

CivicShield helps organizations with limited cybersecurity resources understand their infrastructure, identify weaknesses, prioritize threats according to their impact on essential services, plan remediation and verify recovery readiness.

This dashboard is the **Service Health and Affected Assets Intelligence Map** module.

It must help users answer:

- Which essential services are down, degraded or at risk?
- Which assets and dependencies are affected?
- What is the potential operational impact?
- Which security findings contribute to the risk?
- What should the security team prioritize?
- How prepared is the organization to restore its services?

The application must combine real deterministic application logic with AI-assisted explanations where available. It must not be a static dashboard with fabricated metrics or a generic AI chatbot.

## 3. Required Technology Stack

Use the following stack unless the existing project has a compatible, established alternative:

### Frontend
- React.
- TypeScript.
- Vite.
- Tailwind CSS.
- Lucide React icons.
- React Flow for infrastructure dependency visualization.
- Leaflet and OpenStreetMap for geographic mapping.
- Recharts for trend charts and service-level objectives.

### Backend
- Python 3.12 or another compatible supported version.
- FastAPI.
- Pydantic.
- SQLAlchemy.
- SQLite for the local MVP.
- PostgreSQL compatibility for future deployment.
- Pytest for backend testing.

### AI
- Meta Muse Spark through the currently documented official Meta API, where access is available.
- A provider abstraction layer.
- Structured prompts and validated JSON output.
- A deterministic fallback when AI is unavailable.

Verify the current official API documentation before implementing the integration. Do not invent endpoints, model identifiers or authentication methods. Never expose API credentials in frontend code.

If the backend has not yet been implemented, create a typed mock-data adapter that allows the frontend to function immediately and be connected to the backend later.

### Deployment
- Docker Compose where appropriate.
- Environment variables for secrets and configuration.
- `.env.example`.
- A documented local development workflow.
- Windows PowerShell setup instructions and equivalent Linux/macOS commands.
- Automated tests.

Keep the implementation lightweight, modular and maintainable.

## 4. Design Language

Create a professional, information-dense cybersecurity interface inspired by the supplied screenshot.

### Visual characteristics
- Deep navy and charcoal backgrounds.
- Slightly lighter slate panels.
- Thin, subtle borders.
- Compact typography.
- Dense information layouts.
- Restrained cyan and blue accents.
- Green for operational or healthy states.
- Amber for warnings and degradation.
- Red for critical incidents and outages.
- Violet for identity security and AI governance.
- Small, precise status badges.
- Compact metric cards with subtle sparklines.
- Modest corner radii.
- Clear visual hierarchy and readable contrast.

Avoid generic SaaS landing-page aesthetics, oversized cards, excessive whitespace, bright gradients, unnecessary animations and decorative elements that reduce the information density.

Prioritize visual fidelity at 1440 × 900 and 1920 × 1080 resolutions. The application must also remain usable on tablets and mobile devices.

Include a visible environment indicator:

**DEMO ENVIRONMENT — SIMULATED DATA**

All synthetic assets, incidents, service impacts and geographic markers must be clearly identified as illustrative.

## 5. Main Application Layout

Create a desktop-first, three-part dashboard consisting of:

1. A collapsible left navigation sidebar.
2. A compact top header containing global metrics and workspace controls.
3. A main content workspace containing navigation tabs, KPI cards, a geospatial map and an affected-assets table.

The dashboard should fit as much of the important information as possible into a 1440 × 900 viewport without unnecessary scrolling. The map and table should support independent scrolling where appropriate.

### 5.1 Left Navigation Sidebar

Use a fixed or sticky sidebar approximately 174 px wide at a 1440 px viewport.

At the top, display the CivicShield logo, product name and collapse/expand control.

Organize navigation into compact groups.

**Executive Focus**
- Enterprise Posture
- Affected Assets
- Governance
- Incident Impact
- Service Health

**Operations**
- Infrastructure Map
- Asset Inventory
- Security Assessments
- Incident Response
- Recovery Lab

**Risk & Posture**
- Vulnerabilities
- Configuration Drift
- Exposure Analysis
- Risk Prioritization

**Identity & Threat**
- Identity Security
- Threat Intelligence
- Access Analysis
- AI Agent Security

**Workbenches**
- Infrastructure Graph
- Assessment Workbench
- Recovery Simulator

**Reports**
- Executive Reports
- Security Reports
- Recovery Reports

**Administration**
- Users and Roles
- Audit Log
- Integrations
- Settings

Use compact icons, uppercase section labels, subtle chevrons and a narrow cyan indicator for the active item.

Navigation groups must expand and collapse. Clicking an item must open the appropriate page or view. Do not leave visible navigation links inert. Where a complete secondary page is outside the initial implementation scope, provide a meaningful functional view using the same underlying data rather than an empty placeholder.

### 5.2 Top Metrics Header

Create a compact horizontal header across the workspace.

Display global indicators for:

- Security posture score.
- Critical incidents.
- Service degradation count.
- Affected assets.
- Exposed assets.
- Critical findings.
- Recovery readiness.
- Audit coverage.

On the right, include:
- Time-range selector.
- Organization selector.
- Environment selector.
- Active workspace selector.
- User profile menu.

Each metric should have a compact label, clearly readable value and appropriate status treatment.

All metric values must be calculated from the active dataset or returned by the backend. Do not hard-code dashboard figures independently of the records they represent.

### 5.3 Workspace Header

Show a compact breadcrumb:

`CivicShield / Service Health / Affected Assets Intelligence Map`

Display the workspace title:

**Service Health — Affected Assets Intelligence Map**

Include a Back button, workspace actions and an executive-lens selector.

Provide the following tabs:

- What's Down
- Critical Service Status
- Affected Assets
- Affected Assets Intelligence Map
- Customer Impact Map
- SLO / SLA Burn Chart
- Availability Timeline

Set Affected Assets Intelligence Map as the default active tab.

Use a compact highlighted background and cyan accent for the active tab. Each tab must display a distinct, functional view or meaningful filtered representation of the same underlying data.

## 6. KPI Cards

Immediately below the tabs, display four compact cards in a single desktop row.

### Card A — Services Down
- Current number of unavailable services.
- Red status indicator.
- Small trend sparkline.
- Comparison with the previous period.

### Card B — Affected Assets
- Number of assets associated with active incidents or service impact.
- Amber/orange emphasis.
- Trend indicator.
- Click action that filters the map and table.

### Card C — SLAs at Risk
- Number of service-level objectives at risk.
- Green, amber or red status based on the actual calculated state.
- Small effectiveness or trend indicator.

### Card D — Average Recovery Time
- Recovery duration in hours.
- Historical trend.
- Clear indication of whether the figure is measured, estimated or simulated.

Cards should be approximately 80–100 px tall, with compact labels and sparklines.

All counts, status colors and trends must reflect the dataset, selected time range and relevant filters. Do not imply historical measurements exist if the application only has synthetic sample data.

## 7. Main Feature — Affected Assets Intelligence Map

The map is the primary visual centerpiece.

Use a two-column content area:

- Left: approximately 60–65% of the available width for the interactive map.
- Right: approximately 35–40% for the affected-assets table.

### 7.1 Geospatial Map

Implement a real interactive Leaflet map using OpenStreetMap tiles.

Provide a restrained, dark-compatible map style where practical. Keep the map visually similar to the supplied reference: a large map canvas, compact controls, colored markers, floating statistics and a selected-location information card.

Display geolocated assets and essential services using synthetic coordinates.

Use consistent marker colors:

- Red: Down.
- Amber: Degraded.
- Yellow: At Risk.
- Blue: Recovering.
- Green: Operational.

Support marker clustering or grouping when necessary.

Include:
- Zoom controls.
- Full Map button.
- Map legend.
- Current map status summary.
- Asset/service markers.
- Marker selection.
- Search and filtering controls.
- Reset Filters button.
- Selected-marker details panel.

### 7.2 Map Summary Overlay

Display compact statistics over the map:

- Total mapped assets.
- Assets down.
- Critical assets.
- Affected beneficiaries or users, where data exists.

The figures must update based on the active dataset and filters.

### 7.3 Map Filters

Implement the following controls:

- Service status.
- Severity.
- Asset owner.
- Exposure.
- Service type.
- Region.

When a filter changes, update the markers, summary statistics and table consistently.

### 7.4 Selected Marker Panel

When a marker is selected, display a compact information panel with:

- Asset or service name.
- Geographic region.
- Current status.
- Severity.
- Affected users or service impact, if known.
- Associated incident ID.
- Relevant security findings.
- A View Details action.

Clearly distinguish confirmed outages from potential or simulated impacts.

### 7.5 Full Map Mode

The Full Map action must expand the map across most of the content area. The table should become accessible through a collapsible side panel.

Provide a clear way to exit Full Map mode and return to the original split layout.

### 7.6 Map Failure Handling

If external map tiles cannot load, display a clear fallback state and preserve the remaining functionality.

Where feasible, provide a locally rendered schematic map or infrastructure dependency graph. Do not leave a blank or broken map container.

Do not fabricate real geographic observations or imply that illustrative locations represent actual infrastructure.

## 8. Affected Assets Table

Place a compact, scrollable table beside the map.

Use the following columns:

- Asset.
- Region.
- Status.
- Severity.
- Service.
- Incident ID.

Seed the demo with representative synthetic records such as:

| Asset | Region | Status | Severity |
|---|---|---|---|
| water-gateway-01 | osun-east | Degraded | High |
| ops-server-03 | south-west | Recovering | Critical |
| billing-db-01 | central | Degraded | Medium |
| backup-node-02 | south-west | At Risk | High |
| monitoring-01 | osun-east | Operational | Low |

Use compact colored badges and readable, restrained typography.

Implement:
- Search.
- Sorting.
- Status filtering.
- Severity filtering.
- Region filtering.
- Row selection.
- Pagination or virtual scrolling when needed.
- Asset detail drawer.
- Incident detail action.

Clicking a table row must select and highlight the corresponding map marker. Clicking a map marker must highlight the matching table row.

Clicking an incident ID must open the associated incident detail view. Clicking an asset name must open its details.

The map and table must use a shared data model and centralized filtering logic. Do not maintain inconsistent duplicate datasets for the two components.

## 9. Executive Lens Selector

Implement a floating dropdown titled **CivicShield Lens**, positioned near the upper-right workspace controls.

Include these perspectives:

- SOC Analyst (L1/L2).
- SOC Manager.
- Incident Commander.
- Exposure & Vulnerability.
- Identity Security.
- AI Governance.
- Executive.
- Service Resilience.

Display a compact floating menu with a distinct active-selection indicator, inspired by the reference image.

Selecting a lens must change the displayed priorities, contextual metrics or panel emphasis without silently modifying the underlying records.

### Lens behavior

**SOC Analyst:** Technical findings, event evidence, affected hosts and assessment results.

**SOC Manager:** Incident workload, remediation progress, assessment coverage and operational risk.

**Incident Commander:** Incident status, service impact, response timeline and restoration progress.

**Exposure & Vulnerability:** Exposed assets, weaknesses, critical findings and remediation priorities.

**Identity Security:** Privileged identities, MFA evidence, excessive access and identity-related findings.

**AI Governance:** AI integrations, model status, AI-related risks and governance findings.

**Executive:** Essential-service health, overall risk, critical incidents and recovery readiness.

**Service Resilience:** Dependencies, backup readiness, restoration objectives and recovery scenarios.

Provide a clear active-lens label so the user always knows which perspective is selected.

## 10. Functional Dashboard Views

Implement all workspace tabs as meaningful, interactive views sharing the same data source.

### 10.1 What's Down
Display unavailable services, associated assets, incidents and operational consequences. Allow users to filter by severity and region.

### 10.2 Critical Service Status
Display essential services with health status, availability, configured objectives and critical dependencies.

### 10.3 Affected Assets
Display the full filtered asset inventory with findings, owners, incidents and operational status.

### 10.4 Affected Assets Intelligence Map
Display the map and synchronized affected-assets table as the default view.

### 10.5 Customer Impact Map
Display illustrative impact regions and estimated affected beneficiaries, where the sample data supports these calculations. Label all synthetic estimates clearly.

### 10.6 SLO / SLA Burn Chart
Display service availability against configured service-level objectives, using synthetic time-series data where necessary. Explain the time window and calculation used for burn-rate indicators.

### 10.7 Availability Timeline
Display chronological service status transitions, incident events, assessment events and recovery actions. Distinguish recorded events from simulated events.

## 11. Asset and Incident Details

### Asset Details Drawer

Selecting an asset should open a right-side drawer without unnecessarily leaving the current workspace.

Display:
- Asset name and type.
- Current operational health.
- Criticality.
- Region or network zone.
- Owner.
- Associated essential service.
- Security assessment results.
- Related findings.
- Dependency relationships.
- Recent incident events.
- Backup and recovery readiness.
- Last assessment timestamp.

Provide working actions to:
- View findings.
- View dependency graph.
- View associated incidents.
- Open a remediation plan.
- View recovery status.

### Incident Details Drawer

Display:
- Incident identifier.
- Incident status and severity.
- Affected assets.
- Affected essential services.
- Incident timeline.
- Supporting evidence.
- Related findings.
- Response progress.
- Recovery status.
- Recorded operator actions.

Never invent timestamps, evidence or confirmed incident facts. Clearly label synthetic demo records.

Sensitive or disruptive actions must require authorization and explicit confirmation.

## 12. CivicShield Backend Integration

The dashboard must be an application layer over CivicShield's underlying data and security engines, not an isolated mockup.

Define shared TypeScript interfaces for:

- `Asset`
- `Service`
- `AssetRelationship`
- `SecurityFinding`
- `Incident`
- `RecoveryStatus`
- `AssessmentResult`
- `ServiceLevelObjective`
- `AuditEvent`

Use a centralized API client with typed requests, consistent error handling and loading states.

Support backend endpoints equivalent to:

- `GET /api/health`
- `GET /api/assets`
- `GET /api/services`
- `GET /api/relationships`
- `GET /api/findings`
- `GET /api/incidents`
- `GET /api/assessments`
- `GET /api/recovery/status`
- `GET /api/audit`

Adapt endpoint names to the existing backend if appropriate.

If no backend exists, implement a mock-data service using deterministic seeded data and a clear API adapter boundary. All major interactions must still work in demo mode.

When the backend is available, retrieve actual records rather than continuing to use independent hard-coded frontend values.

Provide an obvious data-source indicator for Demo, Connected or Offline mode.

## 13. Integration with CivicShield Security Engines

Use the dashboard to expose existing CivicShield capabilities where implemented.

### Security assessment engine
Show the results of deterministic checks, including the status, severity, affected asset and evidence.

### Risk prioritization engine
Display the backend-calculated risk score and its contributing factors. Do not generate arbitrary risk scores in the frontend.

### AI-assisted remediation
Allow the user to open a finding and view an AI-assisted explanation or remediation plan, if supported by the backend.

### RecoveryLab
Display recovery readiness and scenario status. Provide a working navigation action to the recovery simulator.

### Incident response
Show linked incident records and timelines.

### Infrastructure graph
Use asset relationships to visualize service dependencies where needed.

If a module has not yet been implemented, indicate that the functionality is not yet connected rather than presenting fabricated results as live capabilities.

## 14. Data Model and Seed Dataset

Create consistent synthetic records for:

- Assets.
- Essential services.
- Asset relationships.
- Security findings.
- Incidents.
- Service-level objectives.
- Recovery status.
- Assessment results.
- Audit events.

Each record should have stable identifiers, timestamps, status and relevant ownership or relationship fields.

Seed approximately 8–12 assets for the initial water-utility demo, including:

- Administrative workstation.
- Operations workstation.
- Identity server.
- Application server.
- Billing application.
- Database server.
- Network gateway.
- Backup server.
- Monitoring server.
- Water operations monitoring workstation.

Include both healthy and affected records.

Demonstrate at least three meaningful service-impact scenarios:
1. An unavailable application server.
2. A privileged account security issue.
3. A backup or monitoring dependency at risk.

Ensure that all dashboard metrics, map markers, status counts, table records and charts derive from a consistent dataset.

Use deterministic seed data so the demonstration is reproducible.

## 15. Security and Privacy Requirements

CivicShield is a defensive cybersecurity application and must itself follow secure development practices.

Implement or preserve:
- Server-side authorization.
- Input validation.
- Secure session or token handling appropriate to the existing authentication architecture.
- Parameterized database access.
- Safe rendering of imported content.
- Restricted CORS configuration.
- Rate limiting for relevant sensitive endpoints.
- Audit logging for security-relevant changes.
- Safe error handling.
- Secure handling of API credentials.
- Upload size and row-count limits.
- Validation of imported CSV and JSON.
- Organization-level data isolation where multi-tenancy is implemented.

Treat imported logs, asset descriptions and AI-generated content as untrusted data.

Never automatically execute AI-generated commands or allow model output to directly modify production infrastructure.

Do not implement unauthorized scanning, exploitation or destructive testing. Use synthetic data by default.

## 16. AI Integration

Implement a backend AI adapter for Muse Spark using verified official Meta API documentation.

Use AI for suitable tasks such as:
- Explaining security findings in plain language.
- Summarizing evidence-backed incident records.
- Generating remediation guidance.
- Explaining potential service impacts using supplied dependency data.

The model must not determine factual status counts or fabricate live operational telemetry.

Use structured prompts and validated responses. Include relevant finding IDs and evidence references where possible.

Treat imported content as untrusted input and defend against prompt injection.

Do not send unnecessary infrastructure records or sensitive data to the AI provider.

When the API is unavailable:
- Preserve all deterministic dashboard functionality.
- Show the AI provider as unavailable.
- Provide an explicit fallback when appropriate.
- Never represent a fallback response as a live Meta model response.

If model access is not available during initial development, use a deterministic mock provider with a clear interface and document how to configure the actual integration.

## 17. Responsive Design

### Desktop
- Fixed or collapsible sidebar.
- Compact top metrics.
- Four KPI cards in a row.
- Map and table side by side.
- Floating lens selector.
- Detail drawers.

### Tablet
- Collapsible navigation.
- Responsive KPI grid.
- Resizable or stacked map/table layout.

### Mobile
- Navigation drawer.
- Stacked KPI cards.
- Map above the asset list.
- Compact filter controls.
- Scrollable or card-based asset records.
- Full-width detail panels.
- Touch-friendly controls.

Do not simply scale down the desktop interface. Reorganize components according to the available screen width.

## 18. Component Architecture

Use reusable components with typed props.

Suggested structure:

- `AppShell`
- `Sidebar`
- `NavigationGroup`
- `TopMetricsBar`
- `WorkspaceHeader`
- `WorkspaceTabs`
- `ExecutiveLensMenu`
- `MetricCard`
- `AffectedAssetsMap`
- `MapMarker`
- `MapLegend`
- `MapFilters`
- `AffectedAssetsTable`
- `AssetDetailsDrawer`
- `IncidentDetailsDrawer`
- `ServiceHealthView`
- `AffectedAssetsView`
- `CustomerImpactView`
- `SlaBurnChart`
- `AvailabilityTimeline`
- `StatusBadge`
- `DemoDataBanner`
- `DataSourceIndicator`
- `LoadingState`
- `ErrorState`
- `EmptyState`

Separate data access, business logic and presentation components.

Centralize:
- Status-to-color mappings.
- Filtering and sorting.
- Risk and impact display rules.
- Data-source status.
- Shared selected-asset state.
- Navigation state.
- Lens selection.

Avoid duplicated logic, oversized components and unnecessary global state.

## 19. Interaction and Functional Acceptance Criteria

All major visible controls must perform their advertised actions.

Implement and test:
- Sidebar collapse and expansion.
- Navigation between functional views.
- Navigation group expansion.
- Workspace tab switching.
- Executive lens switching.
- Time-range selection.
- Organization and environment selection.
- Asset search.
- Table sorting.
- Map filters.
- Marker selection.
- Map/table synchronization.
- Full Map mode.
- Filter reset.
- Asset details drawer.
- Incident details drawer.
- RecoveryLab navigation.
- Security finding navigation.
- Export of filtered asset records to CSV.
- Refresh and data-source status.
- Responsive mobile navigation.

Filters must update every dependent component consistently.

Handle:
- Loading.
- Empty results.
- Backend errors.
- Offline operation.
- Missing map tiles.
- Unavailable AI provider.
- Invalid imported data.

No visible primary action should be a decorative, nonfunctional control.

## 20. Automated Testing

Write and run appropriate frontend and backend tests.

### Frontend
Test:
- Dashboard rendering.
- KPI calculations.
- Tab navigation.
- Lens selection.
- Filtering and sorting.
- Marker selection.
- Table/map synchronization.
- Asset and incident drawers.
- Full Map mode.
- CSV export.
- Loading and error states.
- Mobile layout behavior.

### Backend or data layer
Test:
- Asset and service retrieval.
- Relationship consistency.
- Finding association.
- Incident association.
- Metric calculations.
- Invalid or missing data.
- Access controls where implemented.
- API error handling.
- Deterministic demo-data initialization.

### End-to-end workflow

A user must be able to:
1. Launch CivicShield.
2. Open the Service Health dashboard.
3. Inspect the seeded infrastructure map.
4. Filter assets by severity or status.
5. Select a map marker.
6. Open the corresponding asset.
7. Inspect related findings and incidents.
8. Change the executive lens.
9. Open a recovery or remediation view.
10. Export the filtered asset records.

Run the tests and resolve errors before claiming the application is complete. Report any remaining limitations honestly.

## 21. Repository and Documentation

Preserve the existing repository structure where practical.

If starting from scratch, use a structure similar to:

`civicshield/`
- `frontend/`
- `backend/`
- `backend/app/`
- `backend/tests/`
- `sample-data/`
- `docs/`
- `scripts/`
- `.env.example`
- `.gitignore`
- `docker-compose.yml`
- `README.md`
- `LICENSE`

Provide:
- Installation and startup instructions.
- Required software and versions.
- Environment configuration.
- Demo-data explanation.
- API integration documentation.
- Architecture overview.
- Testing instructions.
- Troubleshooting.
- Known limitations.
- Instructions for connecting the real CivicShield backend.

Do not commit secrets, API keys, credentials or sensitive infrastructure data.

## 22. Meta Global AI Developer Hackathon Requirements

The target hackathon runs from October 26 to November 4, 2026.

Ensure that:
- All project-specific work presented as new hackathon work is created during the event.
- Existing projects or functionality are not misrepresented as new contributions.
- Third-party libraries and assets are used according to their licenses.
- The submitted repository is public.
- The project is entered into exactly one track.
- A three-minute demo video is prepared.
- The Meta model's contribution is clearly demonstrated when model access is available.
- Simulated results are labelled as simulated.
- No unsupported security, customer or performance claims are made.

Choose the Indie Developer track for a solo-builder submission unless the entrant explicitly selects the Startup track.

Use the reference screenshot as inspiration rather than claiming the original design or code as your own.

## 23. Three-Minute Demo Script

Prepare `docs/DEMO_SCRIPT.md` with the following demonstration sequence.

**0:00–0:25 — The problem**

Introduce CivicShield and explain why smaller essential-service providers need accessible cybersecurity and resilience tools.

**0:25–0:55 — Infrastructure visibility**

Show the service health dashboard, map, affected assets and relationships.

**0:55–1:25 — Investigate impact**

Select a critical asset, inspect its findings and demonstrate how the application identifies potentially affected services.

**1:25–1:55 — AI assistance**

Generate an evidence-grounded remediation explanation using Muse Spark, or explicitly demonstrate the documented fallback if the model API is unavailable.

**1:55–2:25 — Investigate and remediate**

Open the finding, review the proposed action and demonstrate the supported simulated remediation workflow.

**2:25–2:45 — Recovery readiness**

Open RecoveryLab and run a synthetic service-failure scenario.

**2:45–3:00 — The mission**

Explain how CivicShield helps protect the essential services communities depend on.

The demonstration must show actual working functionality. Do not present prerecorded model responses or simulated outcomes as live, verified results.

## 24. Implementation Workflow

Work through the following phases without stopping after planning.

### Phase 1 — Inspect and initialize
- Inspect the existing workspace.
- Identify the framework and existing features.
- Preserve compatible code.
- Establish the dashboard route and application shell.
- Configure the seed dataset.
- Confirm the development environment runs.

### Phase 2 — Build the interface
- Implement the sidebar.
- Implement the header and metrics.
- Build workspace tabs.
- Implement KPI cards.
- Build the interactive map.
- Implement the affected-assets table.
- Connect marker selection and table selection.

### Phase 3 — Implement functional views
- Build service status.
- Build affected assets.
- Build customer impact.
- Build SLO/SLA charts.
- Build availability timeline.
- Implement executive lens behavior.
- Add asset and incident detail drawers.

### Phase 4 — Integrate CivicShield
- Connect existing APIs and security engines where available.
- Implement typed API clients.
- Add loading, error and offline handling.
- Connect remediation and recovery workflows.
- Keep a deterministic mock-data mode.

### Phase 5 — Harden and test
- Validate the data model.
- Review security controls.
- Execute automated tests.
- Fix runtime and type errors.
- Verify desktop and mobile layouts.
- Test map failures and backend outages.

### Phase 6 — Deliver
- Write documentation.
- Prepare the demo script.
- Verify clean installation and startup.
- Check for exposed secrets.
- Document completed work and remaining limitations.

Maintain a concise implementation checklist and update it as each feature is completed.

## 25. Definition of Done

The dashboard is complete when:

- It launches using documented commands.
- The UI matches the visual direction of the supplied reference.
- CivicShield branding is applied consistently.
- Metrics derive from the active data.
- The map displays the seeded infrastructure records.
- Map and table filters remain synchronized.
- Selecting assets opens meaningful details.
- The executive lens changes the displayed perspective.
- All major tabs work.
- CSV export functions correctly.
- Backend integration or the documented mock-data adapter works.
- AI availability is clearly represented.
- No synthetic data is presented as real telemetry.
- Error and offline states are usable.
- Automated tests have been executed.
- The application is responsive.
- Documentation and the demo script are included.
- No secrets are committed.

## Final Instruction

Begin by inspecting the existing project files and understanding the available implementation. Then build the CivicShield Service Health dashboard directly in the workspace.

Prioritize **visual fidelity, a large interactive geospatial map, compact executive metrics, a synchronized affected-assets table, functional navigation, evidence-backed security information and working interactions**.

Build the complete page, connect it to the existing CivicShield architecture where possible, run it locally, test the major workflows and fix implementation errors.

Do not stop at a design proposal, screenshot, static mockup or code snippet. Deliver the working application and provide the exact commands required to run it.

If a feature cannot be fully implemented, document the limitation and provide the most functional safe alternative. Never claim that unimplemented functionality is complete.