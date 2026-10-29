# CIVICSHIELD — MASTER IMPLEMENTATION PROMPT
## AI Cybersecurity Team, Architecture Intelligence and Continuous Defensive Protection


**Product vision:** Build an AI-assisted cybersecurity team that understands, analyzes, protects and improves an organization's entire digital environment.

**Primary principle:** Understand the environment. Identify what is at risk. Explain why. Recommend what to change. Validate the change. Verify the result.

You are acting as a principal cybersecurity architect, senior full-stack engineer, defensive security researcher, AI agent engineer, cloud security specialist, identity security specialist, infrastructure security engineer and product designer.

Your assignment is to transform the existing CivicShield application into a functional AI-driven defensive cybersecurity platform while preserving working code and documentation.

Do not build a disconnected prototype, generate only documentation, or replace the existing project with an unnecessary new scaffold. Inspect the existing repository and implement the features directly within it.

---

# 1. THE CORE PRODUCT CONCEPT

Build CivicShield around a new architecture called the **Architecture-to-Resilience Intelligence Graph**.

This is the central model connecting an organization's infrastructure, applications, identities, network boundaries, security controls, vulnerabilities, incidents, essential services, remediation plans and recovery procedures.

Every major security decision should be connected to this model.

For example, the platform should be able to reason through the following scenario:

An organization imports its cloud architecture, network topology and infrastructure configuration into CivicShield.

The platform identifies that:
- A public-facing service communicates with an internal application.
- The internal application has excessive privileges.
- The application can access a sensitive data store.
- The data store does not have a verified recovery path.
- The organization's current monitoring cannot reliably detect the modeled access path.

CivicShield combines these observations into an evidence-backed risk assessment.

Its cybersecurity team then:
1. Analyzes the architecture.
2. Identifies the security weaknesses.
3. Maps plausible attack paths using verified relationships and explicitly labeled assumptions.
4. Prioritizes the weaknesses by potential business and service impact.
5. Proposes architectural improvements.
6. Generates a defensive detection strategy.
7. Creates a controlled remediation plan.
8. Tests the proposed changes in a safe simulation.
9. Verifies the resulting modeled security state.
10. Produces an auditable report.

The platform must distinguish confirmed facts, inferred risks, missing information, simulated results and AI-generated recommendations.

It must never claim to have protected or remediated a live environment unless the relevant action was authorized, actually executed and independently verified.

# 2. PHASE ZERO: AUDIT THE EXISTING REPOSITORY

Before coding, inspect the complete CivicShield repository.

Review:
- README and functional documentation.
- Backend services and API endpoints.
- Frontend pages and components.
- Database models and migrations.
- Existing AI integrations.
- Security assessment rules.
- Asset inventory and dependency mapping.
- Findings and risk scoring.
- Remediation approvals and audit history.
- Recovery simulation.
- Existing tests and deployment configuration.

The documented stack includes FastAPI, React, TypeScript, SQLAlchemy, SQLite and Vite. Reuse this stack wherever practical.

Create a feature inventory with the following statuses:

- Implemented and tested.
- Implemented but unverified.
- Partially implemented.
- Missing.
- Blocked by an external dependency.

Run the existing tests and build before changes. Record existing failures, then implement the missing functionality in dependency order.

Preserve working functionality. Avoid large refactors unless they are necessary for correctness, security or maintainability.

Produce a concise implementation plan, but do not stop at the plan. Continue implementing features and validating them in stages.

# 3. THE CIVICSHIELD CYBERSECURITY TEAM

Implement a coordinated team of specialist defensive agents.

These agents should share a common organization model, evidence repository, architecture graph, security policies and workflow engine.

They must not be independent chatbots that provide contradictory advice.

## Agent 1: Security Team Orchestrator

Purpose: Coordinate the other security specialists.

Responsibilities:
- Receive user requests and security events.
- Determine which specialized analyses are necessary.
- Delegate structured tasks to appropriate agents.
- Maintain a shared investigation record.
- Merge duplicate findings.
- Resolve conflicting recommendations through explicit comparison.
- Identify missing evidence.
- Prioritize tasks based on security and operational impact.
- Produce one coherent security assessment.
- Track progress and summarize outstanding decisions.

Every agent invocation must have a defined task, input evidence, permitted tools, output schema and resource budget.

The orchestrator may recommend actions but cannot bypass authorization, approval, deterministic policies or execution safeguards.

## Agent 2: Architecture Intelligence Analyst

Purpose: Understand the organization's current and proposed technology architecture.

Responsibilities:
- Ingest architecture diagrams and configuration files.
- Identify infrastructure components and their relationships.
- Detect missing documentation.
- Map network trust boundaries.
- Identify public-facing and internal services.
- Map data flows between components.
- Identify single points of failure.
- Identify unnecessary communication paths.
- Detect security-sensitive dependencies.
- Compare current and proposed architectures.
- Recommend secure-by-design improvements.

This agent is a primary product differentiator and must receive high implementation priority.

It must ground its conclusions in parsed configuration, supplied diagrams, inventory records and explicitly labeled assumptions.

## Agent 3: Vulnerability and Exposure Analyst

Purpose: Identify and prioritize technical weaknesses.

Responsibilities:
- Ingest vulnerability scan results and authorized inventory exports.
- Evaluate exposed services and vulnerable components.
- Correlate findings with applicable CVE information.
- Incorporate verified exploitability and exposure evidence.
- Identify internet-facing critical assets.
- Detect outdated or unsupported components when version evidence is available.
- Group findings that share a root cause.
- Recommend mitigation strategies.
- Validate whether remediation evidence supports closure.

Do not report a vulnerable version, confirmed exploit or exposed service without adequate evidence.

Unknown information must remain unknown rather than being interpreted as a clean security result.

## Agent 4: Identity and Access Security Analyst

Purpose: Evaluate human, service and machine identity risk.

Responsibilities:
- Analyze imported user and role inventories.
- Identify excessive privileges and unnecessary administrative access.
- Detect risky trust relationships.
- Review MFA and authentication policy coverage where data is available.
- Analyze service accounts and long-lived credentials represented in authorized inventory data.
- Identify privilege escalation opportunities within the modeled trust graph.
- Recommend least-privilege access.
- Identify identity security control gaps.
- Generate prioritized access-review recommendations.

Never ingest plaintext passwords, private keys, access tokens or other secrets unnecessarily.

The MVP must analyze imported identity configurations or fixtures before introducing live identity integrations.

## Agent 5: Cloud and SaaS Security Analyst

Purpose: Analyze cloud infrastructure, hosted services and SaaS integrations.

Responsibilities:
- Review supported infrastructure-as-code files.
- Analyze cloud resource relationships and access boundaries.
- Detect publicly accessible storage or services where configuration proves exposure.
- Identify excessive IAM permissions.
- Review network security boundaries and routing.
- Identify risky secrets-management configurations.
- Analyze cross-account and cross-project trust relationships.
- Identify missing logging, encryption and recovery controls.
- Recommend configuration improvements.

Start with static analysis of supplied configurations. Later, support authorized read-only cloud inventory APIs.

Do not assume a resource exists in production merely because it appears in an IaC file.

## Agent 6: Network and OT Security Analyst

Purpose: Evaluate network architecture and operational technology boundaries.

Responsibilities:
- Parse supported network configuration exports.
- Analyze segmentation between public, corporate, management and OT environments.
- Identify broad trust boundaries and unnecessary modeled connectivity.
- Highlight paths between user networks and critical systems.
- Identify monitoring gaps.
- Review remote-access architecture.
- Recommend defensive segmentation and access-control improvements.
- Identify scenarios that could disrupt essential services.

For industrial and critical infrastructure, default to passive analysis and read-only data.

Do not execute intrusive scans or modify live controllers, PLCs, pumps, gateways or other operational systems. Use simulated OT models for testing.

## Agent 7: Threat Intelligence Analyst

Purpose: Contextualize organizational risks with external intelligence.

Responsibilities:
- Ingest vulnerability advisories and approved threat-intelligence sources.
- Track relevant adversary techniques and defensive recommendations.
- Correlate known attack patterns with the organization's architecture.
- Identify potentially applicable weaknesses.
- Track source dates and confidence.
- Distinguish confirmed exploitation from theoretical applicability.
- Recommend relevant detection and prevention measures.

Prioritize trustworthy sources such as CISA, NIST, NVD, ENISA and relevant vendor advisories.

Use an adapter-based design so sources can be added or replaced without rewriting the application.

Cache results and handle offline operation.

Every external claim must retain its source URL, publication date when available, retrieval timestamp and relevance rationale.

## Agent 8: Detection Engineering Analyst

Purpose: Help the organization detect activity associated with identified risks.

Responsibilities:
- Convert architecture risks into defensive detection objectives.
- Recommend relevant log sources.
- Identify missing audit events.
- Map detections to MITRE ATT&CK techniques when applicable.
- Generate defensive detection-rule drafts for supported platforms.
- Identify unmonitored identities, assets and trust boundaries.
- Map each detection rule to the risks it addresses.
- Validate rule syntax when a supported parser or validator is available.
- Record coverage gaps and validation status.

Generated rules must be reviewed before deployment.

Do not claim that a rule is operational merely because it was generated.

## Agent 9: Incident Response Analyst

Purpose: Assist with investigation and containment planning.

Responsibilities:
- Correlate available security events.
- Build incident timelines.
- Identify potentially affected assets and identities.
- Connect incident evidence to the architecture graph.
- Separate confirmed compromise from suspicion.
- Recommend containment options.
- Explain possible operational consequences.
- Generate investigation checklists.
- Prepare incident reports.

Containment recommendations must consider operational dependencies and safety.

Real isolation, credential revocation, firewall changes or account disabling require explicit authorization and a supported integration.

## Agent 10: Secure Architecture Advisor

Purpose: Recommend improvements to existing and proposed architectures.

Responsibilities:
- Compare the current architecture with an intended secure design.
- Identify security anti-patterns.
- Propose alternative trust boundaries.
- Recommend least privilege and network segmentation.
- Identify missing security controls.
- Evaluate logging, recovery and resilience requirements.
- Compare alternative architectures.
- Explain implementation cost, risks, dependencies and trade-offs.
- Prioritize recommendations by risk reduction and feasibility.

For every recommendation, include:
- Affected assets or components.
- Evidence and source.
- Current design.
- Identified weakness.
- Proposed design.
- Expected security benefit.
- Operational impact.
- Implementation effort.
- Dependencies and prerequisites.
- Validation method.
- Potential failure modes.
- Rollback plan when applicable.

## Agent 11: Remediation Planner

Purpose: Convert approved security recommendations into controlled work plans.

Responsibilities:
- Group related remediation tasks.
- Identify prerequisites and dependencies.
- Estimate implementation effort.
- Plan change sequencing.
- Recommend maintenance windows where relevant.
- Create verification criteria.
- Prepare rollback procedures.
- Identify actions that require additional authorization.
- Track assigned owners and status.

This agent must generate plans, not execute arbitrary commands.

## Agent 12: Recovery and Resilience Analyst

Purpose: Evaluate whether essential services can withstand and recover from cyber incidents.

Responsibilities:
- Identify critical dependencies.
- Review imported backup and recovery metadata.
- Identify missing recovery dependencies.
- Analyze single points of failure.
- Compare modeled recovery strategies.
- Evaluate stated RTO and RPO targets.
- Create safe disaster-recovery scenarios.
- Verify simulated state transitions.
- Identify evidence needed for real recovery assurance.

Distinguish a configured backup, an observed backup, a tested restoration and a successful real recovery.

## Agent 13: Security Governance and Evidence Analyst

Purpose: Convert security posture into accountable, auditable evidence.

Responsibilities:
- Map findings to relevant security controls.
- Track control coverage.
- Identify missing evidence.
- Maintain remediation ownership.
- Prepare assessment reports.
- Map controls to configurable frameworks such as NIST CSF and CIS Controls.
- Record approvals and exceptions.
- Track accepted risks and expiration dates.

Compliance mappings must explain why a requirement is relevant and must not claim certification or compliance merely because a control is documented.

# 4. MULTI-AGENT ORCHESTRATION ENGINE

Implement a real orchestration service.

Do not create a separate LLM request for every agent on every user interaction.

Use deterministic routing to decide which agents are necessary.

Examples:
- Architecture upload: Architecture Analyst + Secure Architecture Advisor.
- Critical vulnerability: Exposure Analyst + Architecture Analyst + Risk Engine.
- Suspicious identity activity: Identity Analyst + Incident Response Analyst.
- Recovery readiness assessment: Architecture Analyst + Recovery Analyst.
- Complete security assessment: relevant specialists in bounded parallel batches.

Provide:
- Agent registry.
- Agent capability declarations.
- Typed input and output schemas.
- Shared evidence references.
- Task queue.
- Execution status.
- Dependency-aware scheduling.
- Timeouts and cancellation.
- Retry limits.
- Failure handling.
- Token and resource budgets.
- Duplicate-task suppression.
- Conflict reporting.
- Audit records.

Every agent must declare which tools it may invoke.

Use LLMs where interpretation and reasoning add value. Use deterministic code for parsing, graph traversal, scoring, validation and policy enforcement.

The application must not require every specialist to be an independently hosted AI model. Start with modular specialist services that can share an existing provider, local model or rules-based implementation.

Provide an offline mode in which architecture parsing, graph analysis, core risk scoring and basic policy checks continue to work without an external model.

If a specialist fails, report the failure and continue with other valid results where safe.

# 5. ARCHITECTURE ANALYZER — PRIMARY FEATURE

Build Architecture Intelligence as a major application module.

Its purpose is to answer:

- What infrastructure does this organization have?
- How are its systems connected?
- Where are the security boundaries?
- Which assets are public-facing?
- Which identities and services are trusted?
- Where does sensitive data flow?
- Which components are critical?
- What happens if a component or identity is compromised?
- Which security controls are missing?
- What should the organization change first?

## 5.1 Supported input formats

Implement a clearly documented MVP supporting a practical subset of:

- JSON asset inventories.
- CSV inventory exports.
- Mermaid architecture diagrams.
- Docker Compose YAML.
- Kubernetes manifests.
- Terraform configuration.
- Network topology exports in an explicitly documented schema.
- Manually created architecture diagrams through the application UI.

For each format:
1. Validate the file.
2. Identify supported constructs.
3. Parse resources and relationships.
4. Preserve the original source reference.
5. Normalize resources into a common data model.
6. Identify unsupported constructs.
7. Report parsing warnings.
8. Display a preview before importing records.
9. Allow the user to approve and commit the import.

Never execute uploaded code, Terraform, Kubernetes manifests, scripts or container commands as part of static analysis.

Do not silently interpret unknown configuration syntax as valid.

Clearly communicate partial parsing and unsupported resource types.

Add further formats through separate parser modules.

## 5.2 Architecture normalization model

Create a unified model representing:

**Assets**
- Servers.
- Applications.
- Databases.
- Containers.
- Kubernetes workloads.
- Cloud resources.
- Identity providers.
- User and service identities.
- Network devices.
- Security controls.
- Data stores.
- Backups.
- External dependencies.
- SaaS services.
- OT assets.
- Essential business services.

**Relationships**
- Communicates with.
- Runs on.
- Authenticates through.
- Can administer.
- Can read.
- Can write.
- Depends on.
- Exposes.
- Trusts.
- Stores data in.
- Backs up.
- Monitors.
- Routes traffic to.
- Shares credentials or trust relationships where evidence establishes this.

Each relationship must record:
- Source and destination.
- Relationship type.
- Source provenance.
- Confidence.
- Evidence references.
- Last-seen timestamp when applicable.
- Whether it is observed, configured, inferred or simulated.

Do not treat a visual line on a diagram as proof of a working network connection.

Distinguish desired configuration from observed production state.

## 5.3 Architecture visualization

Build an interactive visual graph.

Features:
- Pan and zoom.
- Search.
- Filter by asset type.
- Filter by environment.
- Show public-facing assets.
- Highlight sensitive data stores.
- Highlight privileged identities.
- Show trust boundaries.
- Highlight security findings.
- Trace dependencies.
- Compare architecture versions.
- Display evidence when a node or edge is selected.
- Display missing information and confidence.

The graph must be generated from real persisted application data.

Use a maintained graph-visualization library compatible with the existing frontend.

For large graphs, provide grouping, filtering and lazy expansion rather than attempting to display every resource at once.

# 6. ARCHITECTURE SECURITY ANALYSIS ENGINE

Implement deterministic checks that identify common architectural weaknesses.

Start with the following checks:

### Network and exposure
- Public-facing resources that contain sensitive data.
- Management interfaces modeled as directly reachable from untrusted networks.
- Unexpected communication paths across trust boundaries.
- Overly broad network access rules when the rule data supports the conclusion.
- Missing segmentation between high-risk and critical environments.
- Single points of network failure.
- Unnecessary public exposure.

### Identity and trust
- Excessive permissions.
- Broad administrative privileges.
- Unnecessary cross-environment trust.
- Workloads with excessive access to sensitive data.
- Weakly separated administrative and ordinary user identities.
- Missing MFA policy evidence where identity configuration is available.
- Long-lived credentials represented in configuration metadata.

### Application and infrastructure
- Insecure communication configurations.
- Public storage settings.
- Missing encryption settings when applicable.
- Unsupported or outdated component versions when verified.
- Risky container privileges.
- Kubernetes workloads with excessive permissions.
- Unsafe secret-handling patterns.
- Missing audit or monitoring configuration.

### Resilience
- Single points of failure.
- Missing backup relationships.
- Critical services with no modeled recovery path.
- Backups that share the same failure domain as the protected asset.
- Missing redundancy.
- Unverified restoration procedures.
- Dependency paths that make recovery impossible under a modeled scenario.

For each check:
- Assign a stable rule identifier.
- Define its applicability conditions.
- Produce structured evidence.
- Explain its limitations.
- Specify severity and confidence independently.
- Provide remediation guidance.
- Include automated tests.

Do not label a control absent simply because the relevant configuration was not supplied. Use states such as PRESENT, ABSENT, UNKNOWN and NOT_APPLICABLE.

# 7. ATTACK-PATH AND BLAST-RADIUS ANALYSIS

Build a defensive graph-analysis service.

The service should help users understand how an existing weakness could contribute to risk in another part of the organization.

Support:
- Reachability analysis.
- Trust-boundary crossings.
- Privileged access paths.
- Paths from exposed entry points to sensitive assets.
- Relationships between vulnerable components and dependent services.
- Blast-radius estimation.
- Single points of failure.
- Alternative defensive paths.
- Changes in risk after a proposed architecture improvement.

Each path must display its supporting relationships and evidence.

Separate:
- Confirmed connectivity.
- Configured connectivity.
- Inferred relationships.
- Hypothetical scenario edges.

Never treat a hypothetical path as a confirmed exploit.

Rank paths using documented, deterministic logic that accounts for exposure, trust relationships, required privileges, evidence confidence and potential impact.

Do not require a complex machine-learning model for the MVP. Start with graph algorithms and explicit risk rules.

Use the results only for authorized defensive assessment. Do not implement autonomous exploitation, credential theft, persistence or destructive attack execution.

# 8. THE CONTINUOUS DEFENSIVE PROTECTOR

Build a continuous security assessment engine.

In the first version, implement event-driven recalculation and scheduled assessment of imported or configured data sources.

Example triggers:
- New asset imported.
- Architecture relationship changed.
- New vulnerability finding received.
- Asset criticality updated.
- Identity permissions changed in an imported snapshot.
- New threat advisory becomes relevant.
- Security policy modified.
- Recovery simulation completed.

When a change occurs:
1. Record the triggering event.
2. Identify affected assets and relationships.
3. Recalculate relevant security checks.
4. Recalculate affected risk assessments.
5. Re-evaluate relevant attack paths.
6. Identify changes in risk.
7. Create or update findings.
8. Notify authorized users of significant changes.
9. preserve a record of the source and assessment version.

Support comparison of the previous and current security posture.

Avoid repeatedly creating the same finding. Use stable finding fingerprints, explicit lifecycle rules and deduplication.

Create a visible monitoring status:
- Healthy.
- Degraded.
- Data stale.
- Integration unavailable.
- Assessment failed.
- Awaiting data.

A lack of new alerts must never be presented as evidence that the environment is secure.

Start with local event processing and scheduled jobs. Add durable queues and distributed workers only when needed.

# 9. CONTEXTUAL RISK ENGINE

Implement a transparent deterministic risk engine.

Inputs should include:
- Technical severity.
- Exposure.
- Confirmed exploitability evidence.
- Asset criticality.
- Dependency impact.
- Privilege level.
- Sensitive data access.
- Essential-service impact.
- Control coverage.
- Evidence confidence.

Keep technical severity separate from business priority.

Store:
- Input factors.
- Individual factor scores.
- Missing inputs.
- Scoring model version.
- Final score.
- Explanation.
- Calculation timestamp.

Avoid double-counting correlated factors.

Do not hide uncertainty by assigning arbitrary precise probabilities.

Provide an understandable explanation of why a finding is prioritized over another.

The graph, finding details and reports must all use the same authoritative risk assessment rather than independently calculating different numbers.

# 10. SECURE ARCHITECTURE RECOMMENDATION ENGINE

Build a recommendation service that evaluates possible improvements to the environment.

Examples:
- Separate administrative access from standard user traffic.
- Place sensitive applications behind an appropriate access boundary.
- Reduce unnecessary service privileges.
- Replace unrestricted network rules with explicit permitted communications.
- Introduce better identity controls.
- Improve logging and monitoring coverage.
- Isolate high-risk workloads.
- Introduce recovery dependencies outside the primary failure domain.
- Remove unnecessary public access.
- Introduce staged deployment and rollback procedures.

Do not generate generic recommendations without relating them to the actual environment.

Each recommendation must identify:
- The finding or architecture condition.
- The affected assets.
- The relevant architecture relationships.
- Evidence supporting the proposed change.
- Proposed architecture before and after.
- Expected security benefit.
- Operational risks.
- Performance and availability implications.
- Dependencies and implementation effort.
- Validation criteria.
- Rollback procedure.
- Confidence and unknowns.

Allow users to compare multiple options.

For example, compare a network segmentation change with a narrowly scoped access-policy change and explain the trade-offs.

Support an architecture proposal mode in which users can edit a proposed design without altering the authoritative current architecture.

# 11. ARCHITECTURE CHANGE SIMULATOR

Implement a simulator for evaluating proposed architecture changes.

The simulation should operate on a separate model of the environment.

Example:
- Existing state: an application has excessive permissions to a data store.
- Proposed change: restrict the application's access to the minimum required operations.
- Simulated result: remove unnecessary graph relationships and re-evaluate modeled attack paths.
- Verification: ensure legitimate modeled dependencies remain and prohibited paths are absent.
- Report: show the difference between the original and proposed security posture.

Support scenarios including:
- Restricting an overly broad trust relationship.
- Introducing network segmentation.
- Removing unnecessary privileges.
- Changing a public-storage configuration.
- Adding a required logging control.
- Introducing a redundant dependency.
- Designing a recovery path.

Display before-and-after graphs, findings, risk assessments, affected services and validation outcomes.

Simulation results must remain labeled as simulations.

A successful graph simulation does not prove that a real configuration change works in production.

# 12. SECURITY FINDINGS, EVIDENCE AND AUDIT

Use consistent persistent models for:
- Assets.
- Architecture versions.
- Relationships.
- Findings.
- Evidence records.
- Risk assessments.
- Recommendations.
- Agent tasks.
- Agent results.
- Approval records.
- Simulation runs.
- Verification records.
- Integration status.
- Audit events.

Each finding must have:
- Unique ID.
- Affected assets.
- Detection source.
- Evidence references.
- Status.
- Severity.
- Business risk.
- Confidence.
- Rule or analysis version.
- Remediation recommendation.
- Assigned owner.
- Verification result.

Preserve history when an architecture changes.

Implement finding states such as:

NEW → TRIAGED → INVESTIGATING → REMEDIATION_PENDING → VERIFYING → RESOLVED

Support rejection, exceptions and reopening when appropriate.

Every agent result must link to its input evidence, analysis version, execution status and conclusions.

Use append-oriented audit events with strict access controls and integrity verification.

# 13. APPROVAL AND REMEDIATION SAFEGUARDS

Separate recommendation, approval, simulation and execution.

Required safeguards:
- Authenticated user.
- Server-enforced permissions.
- Clearly defined scope.
- Human approval for consequential changes.
- Precondition validation.
- Action-specific authorization.
- Simulation when available.
- Verification after changes.
- Rollback planning.
- Audit logging.

For the MVP, real remediation execution is disabled by default.

Do not allow an LLM to execute arbitrary shell commands, send unrestricted API requests, modify infrastructure directly or bypass approval workflows.

If real integrations are later introduced, implement narrowly scoped action adapters with least-privilege credentials, explicit allowlisted operations and independent policy enforcement.

The LLM must not be the source of truth for authorization.

# 14. SECURE AI IMPLEMENTATION

Treat user input, uploaded configuration, external threat intelligence and retrieved documents as untrusted data.

Protect the platform against:
- Prompt injection.
- Malicious files.
- Incorrect or fabricated tool calls.
- Unauthorized cross-organization data access.
- Secret leakage.
- Unsafe generated configuration.
- Unrestricted resource use.
- Conflicting agent conclusions.
- Repeated or recursive agent execution.
- Poisoned or misleading evidence.

Controls:
- Use strict structured output schemas.
- Validate all tool arguments.
- Use a capability-based agent tool registry.
- Limit tool calls and execution time.
- Separate analysis from execution.
- Sanitize sensitive content before external AI requests.
- Keep credentials outside model context.
- Validate generated configuration using supported parsers.
- Require approval before consequential changes.
- Record provenance and errors.
- Provide an offline fallback.

Do not describe a provider as integrated unless the integration actually works.

Provide adapter interfaces for existing AI providers and local models. Reuse the project's existing provider if it is functional.

# 15. DEFENSIVE DETECTION ENGINEERING

For risks discovered by the architecture analyzer, provide a workflow to create defensive detection proposals.

Example:
- Finding: unnecessary administrative access exists.
- Risk: unauthorized privilege use might go undetected.
- Required evidence: supported authentication and audit events.
- Proposed detection: identify unexpected administrative use or policy deviations.
- Rule output: a validated draft for a supported SIEM or analytics platform.
- Verification: test the rule against synthetic positive and negative events.
- Status: draft, validated, approved or deployed.

Implement only supported rule formats and label unsupported outputs as examples.

Never claim detection coverage merely because a rule was generated.

# 16. DASHBOARD AND USER EXPERIENCE

Develop a professional, responsive interface consistent with a modern infrastructure security platform.

Preserve working UI elements and reuse existing components when practical.

Implement these modules.

### A. Security Command Center
Show:
- Overall modeled security posture.
- Critical and high-priority findings.
- Newly discovered assets.
- Architecture risks.
- Important trust-boundary violations.
- High-impact dependency paths.
- Assessment freshness.
- Integration health.
- Outstanding approval requests.
- Active and historical simulation runs.

Do not invent metrics to make the dashboard appear populated.

### B. Architecture Intelligence
Show:
- Interactive architecture graph.
- Asset inventory.
- Data flows.
- Trust boundaries.
- Public-facing services.
- Identity relationships.
- Sensitive data stores.
- Architecture findings.
- Missing evidence.
- Current-versus-proposed comparison.

### C. AI Security Team
Show:
- Specialist agents.
- Capabilities.
- Available, busy, degraded and offline states.
- Current tasks.
- Findings and recommendations.
- Evidence used.
- Conflicting conclusions.
- Failed tasks.
- Audit history.

Include a natural-language request panel for prompts such as:

"Analyze this architecture and identify the highest-risk trust relationships."

"Which weaknesses could affect our critical business services?"

"Recommend improvements to our network segmentation."

"Compare the current architecture with this proposed configuration."

"Which critical assets have no verified recovery path?"

"Generate a detection plan for the findings in this assessment."

The response must reference real analysis results and persisted evidence.

### D. Attack Paths
Show relevant graph paths, evidence, prerequisites, confidence and potential impact.

Allow users to compare the original state with a proposed defensive change.

### E. Findings and Risk
Show prioritized findings, risk explanations, owners, evidence and remediation status.

### F. Remediation Workbench
Show proposed changes, prerequisites, approvals, simulations, validation and rollback.

### G. RecoveryLab
Show safe scenarios, recovery objectives, simulated state changes and verification.

### H. Reports
Allow authorized users to export security assessment, architecture, risk, remediation and recovery reports.

### I. Integrations and Settings
Show configured sources, health status, last synchronization, errors, permission scope and data provenance.

Every functional page must be connected to backend services. Do not leave decorative controls that do nothing.

# 17. BACKEND API DESIGN

Use the existing API conventions where practical and extend them with typed, validated endpoints.

The following is a logical endpoint specification, not permission to duplicate existing routes blindly.

Architecture:
- POST /api/architecture/import
- GET /api/architecture/assets
- GET /api/architecture/graph
- GET /api/architecture/versions
- GET /api/architecture/assets/{asset_id}
- GET /api/architecture/assets/{asset_id}/dependencies
- POST /api/architecture/proposals
- POST /api/architecture/proposals/{proposal_id}/simulate

Assessment:
- POST /api/assessments
- GET /api/assessments/{assessment_id}
- GET /api/findings
- GET /api/findings/{finding_id}
- GET /api/findings/{finding_id}/evidence
- GET /api/risk/summary

Attack-path analysis:
- POST /api/analysis/attack-paths
- GET /api/analysis/attack-paths/{analysis_id}

AI security team:
- POST /api/agents/tasks
- GET /api/agents
- GET /api/agents/tasks/{task_id}
- GET /api/agents/tasks/{task_id}/results

Remediation:
- POST /api/remediation/plans
- POST /api/remediation/plans/{plan_id}/submit
- POST /api/remediation/plans/{plan_id}/approve
- POST /api/remediation/plans/{plan_id}/reject
- POST /api/remediation/plans/{plan_id}/simulate
- POST /api/remediation/plans/{plan_id}/verify

Audit and reporting:
- GET /api/audit
- POST /api/reports
- GET /api/reports/{report_id}

Follow consistent naming, authorization, validation, error handling and pagination conventions.

Use asynchronous task processing for analyses that may take a long time. Report task status honestly.

# 18. REQUIRED MVP IMPLEMENTATION PHASES

Implement features in this order.

## Phase 1 — Architecture Intelligence Foundation

Priority: Critical.

Implement:
- Repository audit.
- Common architecture data model.
- CSV and JSON imports.
- Mermaid diagram parsing.
- A documented network-topology schema.
- Asset and relationship persistence.
- Interactive graph visualization.
- Evidence provenance.
- Initial deterministic architecture checks.
- Architecture findings.
- Risk score explanations.

Acceptance criterion:

A user imports a supported architecture, sees the actual parsed components and relationships, receives evidence-backed findings and can inspect why each finding was generated.

## Phase 2 — Security Analysis and Risk

Implement:
- Vulnerability and exposure analysis on supplied data.
- Identity and trust relationship checks.
- Basic cloud and application configuration rules.
- Dependency and reachability analysis.
- Contextual risk scoring.
- Finding deduplication.
- Missing-data handling.
- Architecture version comparison.

Acceptance criterion:

A synthetic environment with known weaknesses produces predictable findings, identifies relevant relationships and explains the risk factors.

## Phase 3 — AI Cybersecurity Team

Implement:
- Agent registry.
- Orchestrator.
- Architecture Analyst.
- Exposure Analyst.
- Identity Analyst.
- Secure Architecture Advisor.
- Remediation Planner.
- Evidence-linked structured outputs.
- Shared investigation records.
- Agent status and error reporting.
- Offline analysis fallback.

Start with these six agents rather than implementing all thirteen at once. Add other specialists through the same interfaces as the foundation stabilizes.

Acceptance criterion:

A user asks CivicShield to analyze an imported architecture. The orchestrator invokes the relevant specialists, combines their results without duplication and produces one coherent assessment with supporting evidence.

## Phase 4 — Architecture Improvement and Simulation

Implement:
- Proposed architecture versions.
- Before-and-after graph comparison.
- Secure-design recommendations.
- Simulated access restrictions.
- Attack-path re-evaluation.
- Verification criteria.
- Approval workflow.
- Persistent simulation results.

Acceptance criterion:

A user can select an architectural weakness, review a proposed change, simulate the change, compare both states and inspect the resulting risk differences.

## Phase 5 — Defensive Monitoring and Response

Implement:
- Scheduled reassessment.
- Event-driven assessment triggers.
- Import adapters.
- Threat-intelligence integration.
- Detection engineering workflow.
- Incident investigation.
- Remediation lifecycle.
- RecoveryLab improvements.
- Security posture change notifications.

Acceptance criterion:

A change to imported architecture or security data triggers the appropriate reassessment, updates the findings and records the new result.

## Phase 6 — Production Hardening and Extensibility

Implement:
- Authentication and server-side authorization.
- Tenant isolation if multi-tenancy is enabled.
- Audit integrity controls.
- API security tests.
- Configuration validation.
- Dependency scanning.
- Observability.
- Database migrations.
- Robust integration handling.
- Deployment documentation.

Acceptance criterion:

The application passes its security and functional tests, has documented operational limitations and does not expose privileged actions by default.

# 19. DEMONSTRATION DATA AND USE CASES

Provide reproducible, entirely fictional seed data for at least three environments.

### Environment A: Community Water Utility

Include:
- Operator workstations.
- Remote-access gateway.
- Monitoring server.
- Simulated OT zone.
- Water-service dependencies.
- Backup system.

Seed a documented excessive-trust or access-control weakness.

Demonstrate:
- Architecture import.
- Finding generation.
- Critical dependency analysis.
- Potential service impact.
- Architectural recommendation.
- Simulated remediation.
- Verification report.

### Environment B: Cloud SaaS Application

Include:
- Public application.
- API service.
- Identity provider.
- Cloud storage.
- Database.
- Administrative identity.
- Logging service.

Seed a fictional excessive-permission or public-access configuration.

Demonstrate:
- Configuration analysis.
- Trust and data-flow graph.
- Risk explanation.
- Least-privilege recommendation.
- Before-and-after comparison.
- Detection proposal.

### Environment C: Hybrid Enterprise

Include:
- On-premises identity.
- Cloud workload.
- VPN or remote-access gateway.
- SIEM.
- Backup service.
- Critical business application.

Seed a fictional weak trust relationship and incomplete recovery dependency.

Demonstrate:
- Cross-environment architecture analysis.
- Privileged identity review.
- Potential attack-path analysis.
- Monitoring coverage gaps.
- Recovery readiness assessment.

Clearly mark all seed data and scenario outcomes as synthetic.

# 20. SECURITY TESTING AND ACCEPTANCE REQUIREMENTS

Create automated unit, integration, API and frontend tests.

Test that:
- Invalid configuration files are rejected safely.
- Unknown constructs are reported.
- Uploaded files are never executed.
- Asset and relationship imports are reproducible.
- Invalid graph relationships are rejected or flagged.
- Risk calculations are deterministic.
- Unknown evidence does not become a clean security result.
- Agent outputs comply with their schemas.
- Agent failures do not fabricate successful results.
- Prompt injection cannot grant unauthorized tool access.
- Cross-organization data is not exposed, where applicable.
- Unauthorized users cannot approve or execute actions.
- Simulated remediation does not change the authoritative live-configuration record.
- Failed verification prevents closure of a finding.
- Architecture comparisons show the actual model differences.
- Threat-intelligence results preserve source provenance.
- CSV and JSON exports are properly validated and authorized.
- The application remains useful when the AI provider is offline.

Do not report tests as passing unless they were actually executed.

# 21. IMPLEMENTATION QUALITY RULES

- Reuse existing project conventions.
- Keep the code modular.
- Avoid monolithic agent classes.
- Use typed schemas.
- Separate parsing, analysis, orchestration, persistence and UI concerns.
- Use deterministic logic where possible.
- Keep AI provider implementations behind adapters.
- Make configuration rules testable.
- Store analysis and architecture versions.
- Avoid unnecessary infrastructure dependencies.
- Provide meaningful errors.
- Track technical debt.
- Document unsupported input formats.
- Use migrations rather than silently changing database schemas.
- Preserve a working local development path.
- Never fabricate operational telemetry.

Do not implement the complete vision as one uncontrolled code-generation pass. Deliver functional vertical slices with tests and documentation after each phase.

# 22. DEFINITION OF DONE

The first complete version of CivicShield must demonstrate the following workflow:

1. An organization imports a supported architecture.
2. CivicShield parses and displays its actual assets and relationships.
3. The architecture analyzer identifies deterministic security weaknesses.
4. The risk engine explains the priority of each finding.
5. The graph engine traces relevant dependencies and potential impact.
6. The AI security team performs a coordinated analysis.
7. The architecture advisor proposes concrete design improvements.
8. The user compares the current and proposed architecture.
9. The user runs a safe simulation.
10. The system evaluates whether the proposed controls meet their modeled objectives.
11. The report displays the actual simulation results and limitations.
12. The entire workflow is recorded in an auditable history.

The platform must continue to support core architecture and risk analysis without external AI.

A demonstration is not considered successful if the core results are hardcoded, the agent outputs are disconnected from evidence, or the visual graph does not reflect persisted data.

# 23. FINAL DELIVERY

At completion, provide:
- Repository audit.
- List of implemented features.
- List of incomplete features.
- Updated architecture documentation.
- Database migrations.
- Automated tests and actual results.
- Installation instructions.
- Sample configuration files.
- Reproducible demo data.
- A scripted demonstration.
- Security assumptions and limitations.
- A prioritized roadmap for subsequent releases.

For every feature, identify whether it is implemented and tested, implemented but unverified, partial, missing or blocked.

Begin with the repository audit, proceed with Phase 1, and continue through the highest-priority feasible implementation stages. Modify the existing repository directly, preserve working functionality, and verify changes as you progress.

The ultimate goal is a cybersecurity platform that understands the environment it is protecting, coordinates specialized defensive intelligence, recommends measurable architectural improvements, and verifies those improvements without compromising the systems it exists to protect.