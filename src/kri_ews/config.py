"""
Central configuration: KRI definitions, thresholds, framework mappings, and
the enterprise risk scenarios each KRI feeds.

Every threshold here is an illustrative assumption for a fictional
manufacturer, not an industry standard. Tune them to your risk appetite.
"""

FORECAST_HORIZON_WEEKS = 8   # how far ahead the early-warning model looks
TRAILING_WINDOW_WEEKS = 4    # rolling window for event-based KRIs

# direction: "up" = higher is worse, "down" = lower is worse
KRIS = {
    "patch_latency_critical": {
        "name": "Critical patch latency",
        "unit": "days",
        "direction": "up",
        "amber": 14,
        "red": 30,
        "nist_csf": "PR.PS (Protect - Platform Security)",
        "description": "Mean days to remediate critical vulnerabilities closed in the trailing 4 weeks.",
        "mitigation": "Add an emergency patch window for critical CVEs and escalate aging items to asset owners weekly.",
    },
    "crit_high_open_over_30d": {
        "name": "Critical/high vulns open > 30 days",
        "unit": "count",
        "direction": "up",
        "amber": 5,
        "red": 9,
        "nist_csf": "ID.RA (Identify - Risk Assessment)",
        "description": "Critical and high-severity vulnerabilities still open more than 30 days after discovery.",
        "mitigation": "Require documented risk acceptance or compensating controls for every critical/high item past 30 days.",
    },
    "ot_unsupported_pct": {
        "name": "OT assets on unsupported OS",
        "unit": "%",
        "direction": "up",
        "amber": 10,
        "red": 20,
        "nist_csf": "ID.AM (Identify - Asset Management)",
        "description": "Share of plant-floor (OT/ICS) assets running an end-of-support operating system.",
        "mitigation": "Segment unsupported OT hosts behind industrial firewalls and fund a phased upgrade plan with plant leadership.",
    },
    "backup_restore_success": {
        "name": "Backup restore test success",
        "unit": "%",
        "direction": "down",
        "amber": 95,
        "red": 90,
        "nist_csf": "RC.RP (Recover - Incident Recovery Plan Execution)",
        "description": "Share of scheduled restore tests that completed successfully.",
        "mitigation": "Investigate failed restores and add immutable/offline copies for production-critical systems.",
    },
    "phishing_click_rate": {
        "name": "Phishing simulation click rate",
        "unit": "%",
        "direction": "up",
        "amber": 5,
        "red": 8,
        "nist_csf": "PR.AT (Protect - Awareness and Training)",
        "description": "Share of employees who clicked the link in the weekly phishing simulation.",
        "mitigation": "Target just-in-time training at repeat clickers and the highest-risk business units.",
    },
    "privileged_no_mfa": {
        "name": "Privileged accounts without MFA",
        "unit": "count",
        "direction": "up",
        "amber": 3,
        "red": 6,
        "nist_csf": "PR.AA (Protect - Identity Mgmt, Authentication, Access Control)",
        "description": "Admin or service accounts with privileged access and no multi-factor authentication.",
        "mitigation": "Enforce MFA via conditional access; vault service-account credentials that cannot use MFA.",
    },
    "mttd_hours": {
        "name": "Mean time to detect",
        "unit": "hours",
        "direction": "up",
        "amber": 24,
        "red": 48,
        "nist_csf": "DE.CM (Detect - Continuous Monitoring)",
        "description": "Mean hours from initial malicious activity to detection, trailing 4 weeks.",
        "mitigation": "Tune detections for the most frequent ATT&CK techniques and extend log coverage to OT networks.",
    },
    "mttr_hours": {
        "name": "Mean time to contain",
        "unit": "hours",
        "direction": "up",
        "amber": 48,
        "red": 96,
        "nist_csf": "RS.MI (Respond - Incident Mitigation)",
        "description": "Mean hours from detection to containment, trailing 4 weeks.",
        "mitigation": "Pre-approve containment playbooks so analysts can isolate hosts without waiting on change approval.",
    },
}

# Enterprise risk scenarios. Impact is on a 1-5 scale (5 = severe).
# Likelihood is derived at run time from the status of the linked KRIs.
RISKS = {
    "R1": {
        "name": "Ransomware halts plant production",
        "impact": 5,
        "impact_rationale": "Production stoppage, missed customer deliveries, recovery cost.",
        "kris": ["patch_latency_critical", "crit_high_open_over_30d", "ot_unsupported_pct", "backup_restore_success"],
    },
    "R2": {
        "name": "Privileged credential compromise",
        "impact": 4,
        "impact_rationale": "Attacker gains admin control of business systems.",
        "kris": ["privileged_no_mfa", "phishing_click_rate"],
    },
    "R3": {
        "name": "Undetected theft of engineering IP",
        "impact": 4,
        "impact_rationale": "Loss of product designs and competitive position; possible export-control exposure.",
        "kris": ["mttd_hours", "mttr_hours"],
    },
}

# Likelihood (1-5) from the worst linked KRI status; +1 if any early warning fires.
STATUS_LIKELIHOOD = {"green": 2, "amber": 3, "red": 4}

# MITRE ATT&CK (Enterprise) techniques used to label synthetic incidents.
ATTACK_TECHNIQUES = {
    "T1566": ("Phishing", "Initial Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1567": ("Exfiltration Over Web Service", "Exfiltration"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
}
