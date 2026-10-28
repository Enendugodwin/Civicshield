# Test Plan Template

## 1. Test Metadata

| Field | Value |
|---|---|
| Project | |
| Version | |
| Environment | |
| Build/Commit | |
| Tester | |
| Date | |

## 2. Unit Tests

Cover:
- [ ] Core business logic
- [ ] Parsers/validators
- [ ] Utility functions
- [ ] Error paths
- [ ] Boundary conditions
- [ ] Concurrency-sensitive logic

Targets:
- Overall coverage: ____ %
- Critical-path coverage: ____ %

## 3. Integration Tests

- [ ] Database
- [ ] Cache
- [ ] Queue
- [ ] Filesystem
- [ ] Authentication
- [ ] Authorization
- [ ] External APIs
- [ ] Service-to-service communication

## 4. Functional Tests

- [ ] Main workflows
- [ ] Positive cases
- [ ] Negative cases
- [ ] Invalid input
- [ ] Permission boundaries
- [ ] Configuration variations
- [ ] Failure handling

## 5. Security Tests

- [ ] Authentication
- [ ] Authorization
- [ ] Input validation
- [ ] Injection resistance
- [ ] Secrets handling
- [ ] Dependency scanning
- [ ] TLS/certificate validation
- [ ] Rate limiting
- [ ] Audit logging
- [ ] Secure error handling

## 6. Regression Tests

- [ ] Existing defects
- [ ] Critical workflows
- [ ] Previous performance defects
- [ ] Integration paths
- [ ] Configuration compatibility

## 7. Reliability Tests

- [ ] Service restart
- [ ] Dependency outage
- [ ] Network interruption
- [ ] Database unavailable
- [ ] Disk pressure
- [ ] CPU pressure
- [ ] Memory pressure
- [ ] Recovery

## 8. Test Cases

| ID | Test | Preconditions | Steps | Expected | Actual | Status |
|---|---|---|---|---|---|---|
| T-001 | | | | | | |
| T-002 | | | | | | |
| T-003 | | | | | | |

## 9. Exit Criteria

- Critical tests: 100% pass
- Critical/high defects: 0 open
- Critical security findings: 0
- High security findings: 0
- Performance budget: PASS
- Reliability budget: PASS
