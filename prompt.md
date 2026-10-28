# MASTER BUILD PROMPT: CIVICSHIELD
## AI-Powered Cybersecurity and Resilience Platform for Essential Community Services

### 1. Your Role

Act as a senior full-stack software engineer, cybersecurity architect, AI engineer, UI/UX designer, DevSecOps engineer and software tester.

Your assignment is to design, implement, test and document a complete working application called **CivicShield**.

Do not stop at a project plan, wireframes, mockups or sample snippets. Build the actual application, including its frontend, backend, database, security assessment engine, AI integration, infrastructure visualization, recovery simulator, automated tests and deployment instructions.

Make reasonable engineering decisions independently. Do not ask unnecessary questions. Prioritize a reliable, demonstrable application over an unnecessarily complicated architecture.

## 2. Product Vision

CivicShield is an open-source, AI-assisted cybersecurity and cyber-resilience platform designed to help organizations with limited cybersecurity resources protect the technology supporting essential community services.

The initial target environment is a small community water utility. The architecture should be extensible to electricity providers, schools, local government, nonprofits, small businesses and other essential service providers.

The problem CivicShield addresses is that smaller organizations often lack the resources to continuously assess their infrastructure, understand which weaknesses matter most, implement fixes safely and verify that their services can recover after an attack.

CivicShield must bring these activities into one application.

### Core mission

Help organizations answer five questions:

1. What technology and digital assets do we depend on?
2. What security weaknesses exist, and what evidence supports each finding?
3. Which weaknesses could cause the greatest harm to our essential services?
4. How do we fix those weaknesses safely and verify the result?
5. Can we recover our essential services if a critical system is compromised or unavailable?

CivicShield is not a generic AI chatbot, a basic RAG application or a dashboard that merely displays generated security advice. It must contain functioning security assessment logic, asset relationships, risk prioritization, remediation verification and recovery simulation.

## 3. Primary Use Case

Build a complete simulated environment for a community water utility.

The environment should contain approximately 8–12 assets, such as:

- Administrative workstation.
- Operations workstation.
- Identity or directory server.
- Application server.
- Billing application.
- Database server.
- Network gateway or firewall.
- Remote administration endpoint.
- Backup server.
- Water operations monitoring workstation.
- Logging or endpoint monitoring server.
- External service or cloud dependency.

Represent assets, identities, applications, connections and essential services as related entities.

The application must use synthetic data for its initial demonstrations. It must not require access to real water infrastructure, production systems or sensitive organizational records.

Demonstrate how a weakness in one component may affect a critical service through the dependency graph. Clearly distinguish confirmed findings from inferred or simulated risks.

## 4. Required Technology Stack

Use a maintainable, reasonably lightweight architecture.

### Frontend
- React.
- TypeScript.
- Vite.
- Tailwind CSS or an equivalent maintainable styling system.
- React Flow or an equivalent graph visualization library.
- A suitable charting library for risk and recovery metrics.
- Accessible reusable components.
- Responsive layouts for desktop, tablet and mobile.

### Backend
- Python 3.12 or a compatible supported Python release.
- FastAPI.
- Pydantic for request and response validation.
- SQLAlchemy for database access.
- SQLite for the initial local deployment.
- PostgreSQL compatibility for a future multi-organization deployment.
- Pytest for automated backend testing.

### AI integration
- Meta Model API with Muse Spark, using the currently documented supported model identifier.
- A dedicated backend AI service and provider adapter.
- Structured prompts and validated JSON responses.
- A deterministic fallback when model access is unavailable.

Verify the current Meta developer documentation before implementing the API client. Do not invent endpoint URLs, authentication headers, model identifiers or request formats. Keep the model integration isolated so that it can be updated without rewriting the application.

### Development and deployment
- Docker Compose where practical.
- A documented local development workflow.
- Environment variables for configuration.
- A Python virtual environment for backend development.
- Separate frontend and backend configuration.
- Database initialization and deterministic demo-data seeding.
- Windows PowerShell setup and startup scripts, plus equivalent instructions for Linux and macOS.

Keep dependencies limited to what the application genuinely needs.

## 5. Core Module A: CivicMap — Asset Inventory and Dependency Graph

Build an interactive infrastructure management interface.

### Features
1. Create, view, edit and retire assets.
2. Assign asset type, owner, hostname, operating system, environment, criticality and security status.
3. Record asset location or network zone when relevant, without exposing sensitive information unnecessarily.
4. Record relationships between computers, identities, applications, services, databases and backups.
5. Allow users to search, filter and inspect assets.
6. Display assets and relationships in an interactive graph.
7. Highlight critical assets, single points of failure and unverified dependencies.
8. Show which services may be affected when an asset becomes unavailable.
9. Import assets from a documented CSV format.
10. Validate imported data and preview changes before accepting them.

### Asset criticality

Support configurable criticality levels:

- Low.
- Moderate.
- High.
- Critical.

Include the reason for an asset's criticality and its relationship to an essential service.

### Dependency graph

Users must be able to select an asset and view:

- Direct dependencies.
- Downstream dependent services.
- Related security findings.
- Relevant identities and administrative relationships.
- Backup and recovery dependencies.
- Simulated impact if that asset becomes unavailable.

Do not represent a hypothetical connection as a verified network connection. Track the source and confidence of imported or inferred relationships.

## 6. Core Module B: BaselineGuard — Security Assessment Engine

Implement a real, deterministic rules engine rather than an AI-generated checklist.

The assessment engine should evaluate structured asset information, explicitly supplied configuration evidence and synthetic test fixtures.

Build at least 12–20 meaningful checks covering:

### Asset and exposure checks
- Missing asset ownership.
- Unsupported or obsolete operating systems when lifecycle evidence is available.
- Missing or overdue security patch evidence.
- Unexpectedly exposed remote administration services.
- Overly broad firewall or access policies.
- Unnecessary services declared in the simulated configuration.

### Identity and access checks
- Missing MFA evidence for privileged accounts.
- Excessive administrative permissions.
- Shared privileged account indicators.
- Stale privileged accounts.
- Missing evidence of least-privilege enforcement.

### Endpoint and monitoring checks
- Missing endpoint protection evidence.
- Disabled or insufficient logging.
- Inadequate security monitoring coverage.
- Unverified security configuration baselines.

### Backup and recovery checks
- Backups older than the configured policy permits.
- Missing evidence of protected or immutable backups.
- Recovery tests overdue or absent.
- Missing backup dependencies.
- A critical service with no documented recovery procedure.

Each check must include:

- Unique rule ID.
- Rule name and description.
- Category.
- Evaluation logic.
- Required input evidence.
- Outcome.
- Severity.
- Confidence.
- Affected asset.
- Evidence reference.
- Recommended next action.
- Timestamp of the assessment.
- Rule version.

Use appropriate outcomes such as `PASS`, `FAIL`, `UNKNOWN` and `NOT_APPLICABLE`.

Missing information must result in `UNKNOWN`, not an invented failure or a fabricated pass.

Every reported failure must be reproducible from the inputs and rule version.

Do not claim that a service is vulnerable merely because a field is empty. Distinguish an absent observation from a confirmed misconfiguration.

### Assessment execution

Users must be able to:

1. Run an assessment against the seeded environment.
2. Inspect every individual check.
3. Filter results by severity, category, asset and status.
4. Compare assessment results over time.
5. Re-run the checks after a configuration change.
6. Export assessment results as JSON and CSV.
7. View a human-readable assessment report.

Use real rule execution against the supplied data. Do not hard-code the dashboard's displayed findings independently of the assessment engine.

## 7. Core Module C: ImpactEngine — Service-Oriented Risk Prioritization

Develop a transparent risk prioritization engine that helps smaller organizations fix the most consequential weaknesses first.

The engine should consider:

- Technical severity.
- Asset criticality.
- External exposure.
- Evidence confidence.
- Known exploitability when supported by reliable data.
- Privilege level.
- Dependency relationships.
- Existing compensating controls.
- Potential consequences for an essential service.

Create a documented, deterministic risk-scoring method, such as a weighted 0–100 score.

Use clearly defined rules to determine the score. Do not allow the AI model to arbitrarily decide the final risk score.

Support configurable priority levels:

- Informational.
- Low.
- Moderate.
- High.
- Critical.

Show the actual factors contributing to each score.

### Required interface

For each prioritized finding, display:

- Risk score and priority.
- Affected asset.
- Potential downstream service impact.
- Evidence supporting the finding.
- Confidence and uncertainty.
- Recommended remediation.
- Whether the finding is confirmed, inferred or simulated.

Provide a graph-based impact view that visualizes the potential consequences of a finding.

Do not label a system as compromised merely because it has a security weakness. Do not claim that a particular attack path is confirmed without evidence.

## 8. Core Module D: FixPilot — AI-Assisted Remediation

Build an AI-assisted remediation system powered by Muse Spark.

The model must receive a structured description of the finding and its relevant context rather than unrestricted access to the entire database.

For each finding, generate a remediation plan containing:

1. Plain-language explanation.
2. Technical explanation.
3. Evidence supporting the explanation.
4. Likely operational consequences if the weakness remains unresolved.
5. Recommended corrective action.
6. Prerequisites.
7. Required approvals.
8. Potential service disruption.
9. Rollback instructions.
10. Verification steps.
11. Remaining limitations and uncertainty.

### AI behavior requirements

- Treat all collected logs, imported text, documents and asset descriptions as untrusted data.
- Never follow instructions embedded in imported data.
- Do not allow untrusted documents to change system instructions, permissions or security policies.
- Do not invent commands, findings, evidence, asset relationships or successful verification results.
- Return structured responses that are validated by the backend.
- Reference the relevant finding IDs.
- Clearly identify recommendations that require human review.
- Never claim a remediation succeeded until the verification checks actually pass.

Provide controls for the user to inspect, approve, reject and record remediation plans.

### Execution boundary

For the hackathon MVP, remediation must be advisory or simulated.

Do not automatically modify production firewalls, identities, servers, databases, industrial systems or backups.

If a remediation is simulated, label it explicitly as simulated. Record proposed actions, approvals, simulated outcomes and verification evidence in the audit log.

The application must continue to function when the Meta API is unavailable. Use deterministic rule descriptions and templated remediation guidance as a fallback. Never fabricate a successful model call.

## 9. Core Module E: RecoveryLab — Service Recovery Simulator

Build a functional recovery simulation that tests the consequences of infrastructure failures.

Use the dependency graph and synthetic recovery records to simulate scenarios such as:

- A compromised administrative account.
- An unavailable application server.
- A failed database.
- An unavailable backup server.
- A simulated ransomware incident.
- Loss of a critical network component.

The simulator must not encrypt, damage, delete or disrupt real files or production services.

### Recovery planning

For each scenario:

1. Identify the affected asset.
2. Traverse the dependency graph.
3. Identify affected essential services.
4. Identify recorded backup and recovery options.
5. Determine which required dependencies remain available.
6. Generate a proposed restoration order.
7. Identify missing recovery information.
8. Execute simulated restoration steps.
9. Verify each simulated step against explicit prerequisites and test conditions.
10. Record the final recovery status.

Clearly distinguish predicted impact from results observed during the simulation.

### Recovery metrics

Track:

- Number of affected assets.
- Number of affected services.
- Dependencies required for restoration.
- Backups available in the scenario.
- Successful and failed recovery steps.
- Simulated recovery time.
- Unresolved blockers.
- Whether the essential service met its defined recovery objective.

Simulated recovery time is an estimate, not evidence of real-world restoration performance.

Support configurable recovery objectives for essential services.

### Recovery interface

Provide a dependency graph, scenario selection, event timeline, restoration steps, verification results and an exportable recovery report.

Users must be able to reset and rerun a scenario.

## 10. Core Module F: IncidentGuide — Guided Incident Response

Implement a basic incident workspace that helps operators organize security evidence during a suspected incident.

Features:

- Create and manage an incident.
- Select affected assets and services.
- Record a timeline of events.
- Attach or reference available evidence.
- Link related assessment findings.
- Produce a structured list of recommended containment and investigation steps.
- Generate an incident report.
- Record operator decisions and approvals.

All incident advice must be grounded in the information supplied to the application.

The AI may assist with summarization and prioritization, but it must not invent events or timestamps.

Preserve the distinction between observed events, analyst interpretations and model-generated suggestions.

Disruptive actions such as isolating a production server must never execute automatically based solely on an AI-generated recommendation.

## 11. Core Module G: CommonShield — Threat Intelligence Sharing Foundation

Implement the minimal data model and interface needed to support future community threat intelligence sharing.

For the MVP, allow the administrator to import synthetic indicators such as:

- Malicious domains.
- Phishing URLs.
- Known campaign identifiers.
- File hashes.
- Source references.
- Confidence ratings.
- First-seen and last-seen timestamps.
- Expiration dates.
- Defensive recommendations.

Include provenance, duplicate detection, expiration and correction mechanisms.

Do not automatically block systems based on unverified community submissions.

Do not collect users' private messages or confidential infrastructure data for sharing.

Full multi-organization intelligence exchange, reputation systems and public reporting should remain future enhancements unless the core application is already stable.

## 12. Core Module H: CivicOffline — Local and Low-Connectivity Operation

CivicShield must preserve the availability of core defensive features when internet connectivity or the AI provider is unavailable.

Requirements:

- Local database.
- Offline asset viewing.
- Local rule execution.
- Local risk calculations.
- Local dependency graph.
- Offline report generation.
- Saved remediation procedures.
- Recovery scenario execution.
- AI integration status indicator.
- Clear handling of failed AI requests.
- Manual export of assessment and recovery data.

Do not require a cloud model call for basic assessments, asset views, risk scoring or recovery simulation.

Never place API keys or service credentials in browser code, frontend environment variables exposed to users, logs or public repositories.

## 13. Dashboard and User Experience

Build a polished, professional cybersecurity application. It should look like a real infrastructure-resilience product, not a generic admin template.

### Visual direction

Use a modern, trustworthy public-infrastructure design:

- Deep navy or charcoal backgrounds where appropriate.
- Teal and restrained cyan accents.
- Clear light and dark theme support if it can be implemented reliably.
- Readable typography.
- Restrained severity colors.
- Clear status labels and accessible contrast.
- Consistent spacing and reusable components.
- Interactive infrastructure graphs.
- Useful tables, filters and detail panels.
- Responsive layouts.
- Loading, error, empty and offline states.

Do not prioritize decoration over usability. Avoid excessive gradients, unnecessary animations and oversized cards.

### Main navigation

Implement the following sections:

1. Overview.
2. Infrastructure Map.
3. Assets.
4. Security Assessments.
5. Findings and Risk.
6. Remediation.
7. RecoveryLab.
8. Incidents.
9. Threat Intelligence.
10. Reports.
11. Settings and Audit Log.

### Overview dashboard

Display live metrics derived from actual stored data:

- Number of registered assets.
- Critical and high-priority findings.
- Assessment completion and status.
- Assets missing important security evidence.
- Essential-service dependency risks.
- Backup and recovery readiness.
- Latest incidents.
- Recent remediation activity.
- Latest assessment timestamp.
- AI-provider availability.

Do not populate metrics with fabricated static values once the user begins interacting with the system.

Provide an initial demo dataset so the first launch is visually complete and immediately usable.

### Asset detail panel

Show asset metadata, relationships, assessment history, findings, assigned owner, relevant service dependencies and recovery information.

### Finding detail panel

Show evidence, check logic, risk factors, affected assets, potential service impact, remediation plan, approval status and verification history.

### RecoveryLab interface

Provide a clear scenario selector, dependency graph, event timeline, recovery checklist and scenario results.

Every interactive button must have a real action. Do not leave placeholder controls or links that appear functional but do nothing.

## 14. Application Data Model

Implement appropriately normalized database models for at least:

- User.
- Organization.
- Asset.
- Service.
- AssetRelationship.
- SecurityRule.
- AssessmentRun.
- AssessmentResult.
- Finding.
- RiskAssessment.
- RemediationPlan.
- RemediationApproval.
- VerificationResult.
- RecoveryScenario.
- RecoveryRun.
- RecoveryStep.
- BackupRecord.
- Incident.
- IncidentEvent.
- ThreatIndicator.
- AuditEvent.

Include identifiers, relevant timestamps, ownership and status fields.

Use migrations or an equally reliable database initialization mechanism.

Maintain relationships through foreign keys where appropriate. Prevent invalid asset references, duplicate relationships and inconsistent assessment records.

An assessment run must retain sufficient information to explain the results that were produced, including the rule version and relevant input evidence.

## 15. Backend API

Provide documented REST endpoints for the core workflows.

Include equivalents of:

- `GET /api/health`
- `GET /api/assets`
- `POST /api/assets`
- `GET /api/assets/{id}`
- `PATCH /api/assets/{id}`
- `DELETE /api/assets/{id}`
- `GET /api/services`
- `GET /api/relationships`
- `POST /api/assessments/run`
- `GET /api/assessments`
- `GET /api/assessments/{id}`
- `GET /api/findings`
- `GET /api/findings/{id}`
- `POST /api/findings/{id}/explain`
- `POST /api/findings/{id}/remediation-plan`
- `POST /api/remediation-plans/{id}/approve`
- `POST /api/remediation-plans/{id}/simulate`
- `POST /api/recovery/scenarios`
- `POST /api/recovery/runs`
- `GET /api/recovery/runs/{id}`
- `POST /api/incidents`
- `GET /api/incidents`
- `GET /api/audit`
- `GET /api/reports/{type}`

Adapt the API as needed, but document every implemented endpoint.

Use request validation, appropriate HTTP status codes, pagination where appropriate and consistent error responses.

Implement API authentication and role-based authorization. Include suitable roles such as Administrator, Operator and Viewer. A read-only viewer must not be able to approve actions or modify infrastructure records.

For local demonstrations, provide an explicitly enabled demo mode with synthetic accounts and data. Demo credentials must not be presented as production credentials.

## 16. Security Requirements

CivicShield is a cybersecurity product and must itself follow secure development practices.

Implement:

- Password hashing using a secure, maintained algorithm if local password authentication is used.
- Server-side authorization checks.
- Input validation and output encoding.
- Parameterized database operations.
- Secure handling of secrets.
- Restricted CORS configuration.
- Rate limiting on suitable sensitive endpoints.
- Audit logging for security-relevant changes.
- Error messages that do not expose stack traces or secrets to users.
- Strict validation of uploaded CSV and JSON files.
- File size and row-count limits for imports.
- Safe handling of AI model output.
- Protection against prompt injection from imported data.
- Human approval for sensitive actions.
- Tenant isolation if organization-scoped records are implemented.
- No automatic execution of AI-generated commands.

Do not implement unrestricted scanning, exploitation or destructive testing.

The collector must operate only on systems for which the operator has authorization. The hackathon's default environment must be synthetic.

## 17. AI Service Design

Create a provider interface separating the application from the specific model API.

Implement:

- A Meta Muse Spark client using verified official documentation.
- Environment-based configuration.
- Request and response validation.
- Timeouts and bounded retries.
- Clear provider failure messages.
- Minimal context transmission.
- Structured output schemas.
- A fallback when the provider is unavailable.
- Tests using a deterministic mock provider.

The model should receive only the data needed for the particular task.

For example, to generate a remediation plan, provide the finding, its relevant evidence, the asset's criticality, known dependencies and the allowed response schema. Do not send every stored asset and incident to the model.

Make it possible to disable AI in settings while preserving the core application.

Do not claim a security benefit simply because the model has produced an explanation. Measure security results using the deterministic checks and test scenarios.

## 18. Sample Data and Demonstration Scenarios

Create a deterministic seed dataset for the simulated water utility.

Include examples of:

- A privileged account missing MFA evidence.
- An overly broad remote administration rule.
- An asset with overdue patch evidence.
- A critical asset without a verified owner.
- A backup with outdated recovery evidence.
- A missing recovery procedure.
- An asset without endpoint monitoring evidence.
- An essential service with a single point of failure.

Also include healthy assets and passing checks. The demo must contain both passing and failing cases.

Create at least three repeatable recovery scenarios:

1. Loss of an application server.
2. Suspected compromise of a privileged account.
3. A simulated ransomware event affecting a non-production application and selected dependencies.

Use clearly labelled synthetic data and record which results are simulated.

Ensure that the user can reset the demonstration environment and reproduce the same baseline.

## 19. Testing and Quality Assurance

Write and execute automated tests.

### Backend tests

Test:

- Asset creation, editing and retrieval.
- Relationship validation.
- CSV import validation.
- Every assessment rule.
- Unknown and not-applicable assessment outcomes.
- Risk score calculations.
- Service-impact traversal.
- Remediation-plan validation.
- Approval and role authorization.
- Recovery prerequisites and dependency ordering.
- Recovery success and failure.
- AI provider failures.
- Invalid model output.
- Audit record creation.
- Report exports.
- Data isolation and access restrictions where applicable.

### Frontend tests

Test key user workflows:

- Viewing the dashboard.
- Inspecting an asset.
- Starting an assessment.
- Filtering findings.
- Inspecting evidence.
- Generating a remediation plan.
- Simulating recovery.
- Exporting a report.
- Handling unavailable AI services.
- Handling empty and error states.

### End-to-end acceptance test

A user must be able to:

1. Start CivicShield.
2. Open the seeded water-utility environment.
3. Inspect the infrastructure dependency map.
4. Run a real assessment.
5. View evidence-backed findings and risk scores.
6. Generate an AI-assisted remediation plan or use the fallback.
7. Apply a simulated remediation.
8. Rerun the assessment to verify that a finding has been resolved in the test fixture.
9. Run a recovery scenario.
10. View and export the final report.

Do not claim tests have passed unless they have actually been executed. Fix implementation failures before declaring the application complete.

## 20. Repository Structure and Documentation

Organize the repository so that a new contributor can understand it quickly.

Use a structure similar to:

civicshield/
- frontend/
- backend/
- backend/app/api/
- backend/app/models/
- backend/app/schemas/
- backend/app/services/
- backend/app/engine/
- backend/app/recovery/
- backend/app/ai/
- backend/app/security/
- backend/tests/
- docs/
- scripts/
- sample-data/
- .env.example
- .gitignore
- docker-compose.yml
- README.md
- LICENSE
- CONTRIBUTING.md

Adapt this structure when necessary, but maintain clear separation of responsibilities.

### Required documentation

Create:

1. `README.md` — overview, supported features, screenshots, requirements, setup, startup, configuration, tests, limitations and troubleshooting.
2. `docs/ARCHITECTURE.md` — component diagram, data flow and major design decisions.
3. `docs/THREAT_MODEL.md` — assets, trust boundaries, threats, mitigations and residual risks.
4. `docs/SECURITY_ENGINE.md` — each assessment rule and its evidence requirements.
5. `docs/RISK_MODEL.md` — scoring formula, assumptions and limitations.
6. `docs/RECOVERY_LAB.md` — supported scenarios and simulator behavior.
7. `docs/AI_INTEGRATION.md` — Meta API configuration, output validation, failure handling and privacy considerations.
8. `docs/API.md` — API endpoints and examples.
9. `docs/DEMO_SCRIPT.md` — a three-minute hackathon demonstration.
10. `docs/ROADMAP.md` — future capabilities deliberately excluded from the MVP.

Use a license compatible with the project and its dependencies. Do not include assets, code or datasets without the necessary rights.

## 21. Hackathon Compliance

This project is for the Meta Global AI Developer Hackathon, October 26–November 4, 2026.

The implementation must respect the following conditions:

- All project-specific features, code and functionality presented as hackathon work must be created during the hackathon.
- Do not import or repackage pre-existing personal projects as new work.
- Existing tools and open-source dependencies may be used only in accordance with their licenses and must not be misrepresented as original work.
- Track the original contributions clearly in the repository and demo.
- Keep the submitted repository public.
- Choose exactly one track: Indie Developer or Startup. Use Indie Developer for the solo-builder default unless the entrant explicitly establishes a startup team.
- Identify third-party components and their licenses.
- Provide a working three-minute demo video.
- Make meaningful use of a supported Meta model and document its role.
- Keep the project within defensive, authorized and ethical use.
- Do not claim the application prevents all cyberattacks or has been validated in real critical infrastructure.

Do not fabricate deployment statistics, security improvements, customers, partnerships or real-world test results.

## 22. Hackathon Demo Requirements

Prepare a reproducible, three-minute demonstration based on the seeded water-utility environment.

Suggested timing:

**0:00–0:25 — The problem**
Explain why smaller essential-service providers need affordable cybersecurity and recovery tools.

**0:25–0:55 — Understand the infrastructure**
Show CivicMap and demonstrate how assets relate to an essential service.

**0:55–1:25 — Detect and prioritize**
Run the real security assessment. Show a finding with actual input evidence and explain why it matters to the service.

**1:25–1:55 — Use Meta AI**
Generate a remediation explanation with Muse Spark. Show how the model uses structured evidence and how the deterministic policy engine retains control of the process.

**1:55–2:30 — Verify the fix**
Simulate an approved repair, rerun the relevant check and display the changed evidence and result.

**2:30–2:50 — Test recovery**
Simulate loss of a critical component and show the dependency-aware recovery sequence.

**2:50–3:00 — The mission**
Explain how CivicShield can help small organizations protect the essential services communities depend on.

The demonstration must show working functionality, not merely static screens or prerecorded model responses presented as live execution.

Create a demo script and a checklist for recording the final video.

## 23. Development Workflow

Work in implementation phases, but continue until the application is built and tested.

### Phase 1: Foundation
- Inspect the development environment.
- Establish the repository and project structure.
- Configure the frontend, backend and database.
- Create the initial seed dataset.
- Establish working local startup commands.

### Phase 2: Core cybersecurity engine
- Implement asset and relationship models.
- Build the deterministic assessment engine.
- Implement finding evidence and risk scoring.
- Build the asset graph and assessment interface.

### Phase 3: AI and remediation
- Verify current Meta API documentation.
- Implement the provider adapter.
- Integrate evidence-grounded explanations.
- Implement structured remediation plans and safe simulated approval.

### Phase 4: Recovery
- Implement the dependency-aware recovery simulator.
- Add scenario execution, step verification and reports.

### Phase 5: Hardening and polish
- Implement authentication and authorization.
- Add audit logging and data validation.
- Complete the dashboard and responsive interface.
- Test error handling and AI outages.
- Execute automated tests and fix failures.

### Phase 6: Release
- Write setup and architecture documentation.
- Confirm that a fresh environment can launch the application.
- Check that no secrets are committed.
- Publish the repository publicly.
- Prepare the hackathon demo video.

At each stage, implement real functionality instead of replacing unfinished work with placeholders. Maintain a concise record of completed modules, known defects and remaining acceptance criteria.

## 24. Definition of Done

CivicShield is ready for submission only when:

- The application launches from documented instructions.
- The frontend communicates with the real backend.
- The database stores and retrieves actual records.
- The infrastructure graph represents actual seeded relationships.
- Security checks execute through a deterministic rules engine.
- Findings include supporting evidence.
- Risk scores are calculated by documented logic.
- Meta model integration works when configured, with a tested fallback when unavailable.
- AI-generated explanations cannot directly execute system changes.
- Remediation can be simulated and independently verified.
- Recovery scenarios produce reproducible results.
- Reports can be exported.
- Role permissions and input validation are tested.
- Core functions remain available without the model API.
- Automated tests have been executed and their results documented.
- The public repository contains setup instructions, documentation, a suitable license and no secrets.
- The three-minute demo demonstrates actual working functionality.

## Final Instruction

Begin by inspecting the available development environment, then build CivicShield Core as an end-to-end application.

Prioritize the complete workflow of **infrastructure mapping → evidence-backed assessment → service-impact prioritization → AI-assisted remediation → verification → recovery simulation**.

Do not silently omit a required component. If a capability cannot be completed, state the limitation explicitly, implement a working alternative where feasible and document what remains.

Your final delivery must include the runnable application, source code, database initialization and demo data, tests, deployment instructions, technical documentation, a feature checklist and the three-minute demo script.

Build CivicShield as a practical tool for protecting essential community services, not merely as a cybersecurity dashboard.