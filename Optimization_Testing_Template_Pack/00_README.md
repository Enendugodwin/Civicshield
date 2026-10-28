# Optimization & Testing Template Pack

A reusable framework for optimizing Hosts, VMs, Servers, Projects, and Code while proving improvements with tests and measurements.

## Operating model

**Baseline → Profile → Optimize → Test → Benchmark → Compare → Gate → Release → Monitor**

## Rules

1. Never optimize before taking a baseline.
2. Optimize measured bottlenecks, not assumptions.
3. Make one major optimization change at a time where practical.
4. Run functional + security + performance + reliability tests after changes.
5. Preserve correctness and security while improving speed.
6. Store benchmark results with the build/commit/version.
7. Define pass/fail thresholds before testing.
