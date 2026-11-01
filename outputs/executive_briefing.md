# Cyber Risk Briefing: Northfield Powertrain (fictional)
*Week ending 2026-10-25 · synthetic data · prepared for the Risk Committee*

## Bottom line
- **Ransomware halts plant production** is the top risk (score 20/25, High), driven by Critical patch latency, Critical/high vulns open > 30 days, OT assets on unsupported OS.
- **Early warning:** Critical patch latency is at 23.2 days (amber) and is projected to reach 30.6 days (red) by about 2026-12-13 if the trend holds.

## Risk register

| Risk | Likelihood | Impact | Score | Rating | Drivers |
|---|---|---|---|---|---|
| R1 Ransomware halts plant production | 4 | 5 | 20 | High | Critical patch latency, Critical/high vulns open > 30 days, OT assets on unsupported OS |
| R3 Undetected theft of engineering IP | 3 | 4 | 12 | Medium | Mean time to detect |
| R2 Privileged credential compromise | 2 | 4 | 8 | Medium | None |

## Key Risk Indicators

| KRI | Current | 4 weeks ago | Status | NIST CSF 2.0 |
|---|---|---|---|---|
| Critical patch latency | 23.2 days | 14.2 days | AMBER | PR.PS (Protect - Platform Security) |
| Critical/high vulns open > 30 days | 6 | 7 | AMBER | ID.RA (Identify - Risk Assessment) |
| OT assets on unsupported OS | 13.8% | 13.4% | AMBER | ID.AM (Identify - Asset Management) |
| Backup restore test success | 97.6% | 98.6% | GREEN | RC.RP (Recover - Incident Recovery Plan Execution) |
| Phishing simulation click rate | 4.2% | 3.7% | GREEN | PR.AT (Protect - Awareness and Training) |
| Privileged accounts without MFA | 2 | 2 | GREEN | PR.AA (Protect - Identity Mgmt, Authentication, Access Control) |
| Mean time to detect | 25.8 hours | 31.8 hours | AMBER | DE.CM (Detect - Continuous Monitoring) |
| Mean time to contain | 38.7 hours | 25.5 hours | GREEN | RS.MI (Respond - Incident Mitigation) |

## Threat activity (MITRE ATT&CK, last 13 weeks)
- T1566 Phishing: 12 incidents (prior 13 weeks: 12)
- T1190 Exploit Public-Facing Application: 5 incidents (prior 13 weeks: 4)
- T1078 Valid Accounts: 3 incidents (prior 13 weeks: 7)

## Recommended actions (highest-scoring risk first)
1. **Critical patch latency** (R1): Add an emergency patch window for critical CVEs and escalate aging items to asset owners weekly.
2. **Critical/high vulns open > 30 days** (R1): Require documented risk acceptance or compensating controls for every critical/high item past 30 days.
3. **OT assets on unsupported OS** (R1): Segment unsupported OT hosts behind industrial firewalls and fund a phased upgrade plan with plant leadership.
4. **Mean time to detect** (R3): Tune detections for the most frequent ATT&CK techniques and extend log coverage to OT networks.

## Method and limits
KRIs are computed weekly; each is forecast 8 weeks ahead with a simple ARIMA model. Forecasts are trend signals, not predictions. Thresholds are illustrative and should be set to the organization's risk appetite. Patch latency only counts closed items, so it can understate a growing backlog; read it alongside the open-vulnerability aging KRI.
