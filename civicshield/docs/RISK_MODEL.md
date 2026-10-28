# Risk Model (ImpactEngine)

score = severity 30 + criticality 20 + exposure 15 + confidence 10 + exploitability 10 + privilege 5 + blast-radius 5*(min(1, radius/5)) + controls 5 (0 when compensating controls are recorded). Priority bands: >=85 Critical, >=65 High, >=40 Moderate, >=15 Low, else Informational. Every finding shows contributing factors, confidence, confirmed/inferred/simulated flag. Limitations: no CVSS feed by default; SPOF derived from graph degree; human review required.
