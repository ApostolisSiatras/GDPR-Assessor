# GDPR Assessment (dpia(1.1))
- Generated: 2025-11-11T09:50:32.980004Z

## Overall Score
- 74.7% (14.2/19.0) — Adequate

## Key Facts
- **Data Subjects**: EMPLOYEES
- **Purposes**: PAYROLL, FRAUD_PREVENTION
- **Data Categories**: IDENTITY, EDUCATION
- **Special Categories**: HEALTH, BIOMETRIC
- **Legal Basis**: CONSENT, CONTRACT
- **Processors**: JOINT_CONTROLLER
- **Transfers**: flag=YES, mechanisms=['ADEQUACY', 'SCC']
- **Rights Processes**: ACCESS, RECTIFICATION

## Section Scores
- **A.Context**: 10.0% (0.2/2.0)
- **B.Stakeholders**: 100.0% (2.0/2.0)
- **B.Transfers**: 100.0% (1.0/1.0)
- **C.Risk**: 50.0% (2.0/4.0)
- **D.Security**: 100.0% (7.0/7.0)
- **E.Rights**: 100.0% (2.0/2.0)
- **F.Residual**: 0.0% (0.0/1.0)

## High-Risk Indicators
- Special-category data present (Art.9).
- Automated decision-making/profiling reported (Art.22).

## Coverage Gaps
- Q-DPIA-002 (A.Context): requires ANY of ANALYTICS, COMPLIANCE_REPORTING, CUSTOMER_MANAGEMENT, HR_ADMINISTRATION, SECURITY_MONITORING, SERVICE_PROVISION; selected FRAUD_PREVENTION, PAYROLL
- Q-DPIA-003 (A.Context): requires FRACTION of CONTACT, CUSTOMER_BEHAVIOR, FINANCIAL, IDENTITY, LOCATION, ONLINE_IDENTIFIER; selected EDUCATION, IDENTITY
- Q-DPIA-014A (C.Risk): requires ANY of BIOMETRIC_IDENTIFICATION, PROFILING, SYSTEMATIC_OBSERVATION; selected [none]
- Q-DPIA-025 (E.Rights): requires ALL of ACCESS, ERASURE, OBJECTION, PORTABILITY, RECTIFICATION, RESTRICTION; selected ACCESS, RECTIFICATION

## GDPR Article Traceability
### Art.13-14
- Q-DPIA-024: YES

### Art.15-22
- Q-DPIA-025: ACCESS, RECTIFICATION

### Art.21
- Q-DPIA-026: YES

### Art.22
- Q-DPIA-014: YES

### Art.26
- Q-DPIA-010: YES

### Art.28
- Q-DPIA-013: YES

### Art.30
- Q-DPIA-021: YES

### Art.32
- Q-DPIA-018: YES
- Q-DPIA-021: YES

### Art.32(1)(a)
- Q-DPIA-019A: YES
- Q-DPIA-019B: YES

### Art.32(1)(c)
- Q-DPIA-020: YES

### Art.33-34
- Q-DPIA-023: YES

### Art.35(7)(d)
- Q-DPIA-029: NO

### Art.39(1)(b)
- Q-DPIA-022: YES

### Art.4(1)
- Q-DPIA-001: YES
- Q-DPIA-003: IDENTITY, EDUCATION

### Art.4(7)-(8)
- Q-DPIA-009: JOINT_CONTROLLER

### Art.44-49
- Q-DPIA-011: YES

### Art.46
- Q-DPIA-012: ADEQUACY, SCC

### Art.5(1)(a)
- Q-DPIA-001A: EMPLOYEES

### Art.5(1)(b)
- Q-DPIA-002: PAYROLL, FRAUD_PREVENTION
- Q-DPIA-007: NO

### Art.5(1)(e)
- Q-DPIA-008: 12

### Art.6
- Q-DPIA-006: CONSENT, CONTRACT

### Art.7
- Q-DPIA-026: YES

### Art.9
- Q-DPIA-004: HEALTH, BIOMETRIC

### Recital 75
- Q-DPIA-015: NO
- Q-DPIA-017: YES

### Recital 76
- Q-DPIA-027: VERY_LOW
- Q-DPIA-028: LOW

### Recital 91
- Q-DPIA-005: LOW_<=1000
- Q-DPIA-014A: [none]
- Q-DPIA-016: NO
