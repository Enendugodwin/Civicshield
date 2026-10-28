# RecoveryLab

Scenarios: (1) app-server loss, (2) privileged-account compromise, (3) simulated ransomware on non-prod app. Simulator: traverse dependency graph from affected asset, list services/backups, order restoration topologically, verify prerequisites per step, record metrics (affected assets/services, backups, step pass/fail, simulated time, blockers, RTO met?). Nothing touches production; reset/rerun supported; report exportable.
