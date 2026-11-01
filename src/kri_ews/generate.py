"""
Synthetic security telemetry for a fictional manufacturer, "Northfield Powertrain".

Produces three raw tables (vulnerabilities, incidents, weekly control metrics)
covering 104 weeks. A few deliberate storylines are planted so the KRI and
early-warning logic has something real to find:

  * Critical patching slows over the last ~16 weeks (staffing gap).
  * Detection times creep up over the last ~12 weeks.
  * OT assets on unsupported operating systems drift upward all year.
  * MFA coverage for privileged accounts improves after a remediation project.

All data is fake. Seeded, so every run is reproducible.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .config import ATTACK_TECHNIQUES

N_WEEKS = 104
DEFAULT_AS_OF = pd.Timestamp("2026-10-25")  # a Sunday; last full week ends here
BUSINESS_UNITS = ["Corporate IT", "Plant OT", "Engineering", "Supply Chain"]
ASSET_TYPES = ["Server", "Workstation", "OT/ICS", "Cloud"]
ASSET_TYPE_P = [0.30, 0.35, 0.20, 0.15]
SEVERITIES = ["Critical", "High", "Medium", "Low"]
SEVERITY_P = [0.10, 0.25, 0.45, 0.20]
# median remediation days by severity before any drift
SEVERITY_MEDIAN_DAYS = {"Critical": 9, "High": 18, "Medium": 35, "Low": 60}


def _week_starts(as_of: pd.Timestamp) -> pd.DatetimeIndex:
    last_start = as_of - pd.Timedelta(days=6)
    return pd.date_range(end=last_start, periods=N_WEEKS, freq="7D")


def generate_vulnerabilities(rng: np.random.Generator, as_of: pd.Timestamp) -> pd.DataFrame:
    rows = []
    for w, start in enumerate(_week_starts(as_of)):
        for _ in range(rng.poisson(22)):
            sev = rng.choice(SEVERITIES, p=SEVERITY_P)
            asset = rng.choice(ASSET_TYPES, p=ASSET_TYPE_P)
            discovered = start + pd.Timedelta(days=int(rng.integers(0, 7)))
            median = SEVERITY_MEDIAN_DAYS[sev]
            if asset == "OT/ICS":
                median *= 1.6  # plant downtime windows make OT patching slower
            if w >= 88:
                median *= 1 + (w - 88) * 0.09  # staffing gap: critical work backs up
            days = max(1.0, rng.lognormal(np.log(median), 0.45))
            closed = discovered + pd.Timedelta(days=round(days))
            rows.append({
                "vuln_id": f"V{len(rows) + 1:05d}",
                "severity": sev,
                "asset_type": asset,
                "discovered": discovered,
                "closed": closed if closed <= as_of else pd.NaT,
            })
    return pd.DataFrame(rows)


def generate_incidents(rng: np.random.Generator, as_of: pd.Timestamp) -> pd.DataFrame:
    tech_ids = list(ATTACK_TECHNIQUES)
    base_p = np.array([0.30, 0.15, 0.12, 0.12, 0.10, 0.09, 0.07, 0.05])
    rows = []
    for w, start in enumerate(_week_starts(as_of)):
        p = base_p.copy()
        p[0] += 0.10 * w / N_WEEKS  # phishing share grows over the period
        p /= p.sum()
        for _ in range(rng.poisson(3)):
            tid = rng.choice(tech_ids, p=p)
            detect_median = 16 * (1 + max(0, w - 90) * 0.09)
            rows.append({
                "incident_id": f"INC{len(rows) + 1:04d}",
                "opened": start + pd.Timedelta(days=int(rng.integers(0, 7))),
                "business_unit": rng.choice(BUSINESS_UNITS),
                "attack_technique_id": tid,
                "attack_technique": ATTACK_TECHNIQUES[tid][0],
                "attack_tactic": ATTACK_TECHNIQUES[tid][1],
                "hours_to_detect": round(rng.lognormal(np.log(detect_median), 0.55), 1),
                "hours_to_contain": round(rng.lognormal(np.log(32), 0.5), 1),
            })
    return pd.DataFrame(rows)


def generate_weekly_metrics(rng: np.random.Generator, as_of: pd.Timestamp) -> pd.DataFrame:
    weeks = _week_starts(as_of)
    t = np.arange(N_WEEKS)
    phishing = 6.0 - 2.2 * (t > 40) + 0.8 * np.sin(t / 8) + rng.normal(0, 0.5, N_WEEKS)
    mfa = np.where(t < 60, 5, np.where(t < 75, 3, 1)) + rng.integers(0, 2, N_WEEKS)
    ot_unsupported = 7.5 + 0.06 * t + rng.normal(0, 0.4, N_WEEKS)
    backup = 97.5 + rng.normal(0, 1.0, N_WEEKS)
    return pd.DataFrame({
        "week_start": weeks,
        "phishing_click_rate": np.clip(phishing, 0.5, None).round(2),
        "privileged_no_mfa": mfa.astype(int),
        "ot_unsupported_pct": ot_unsupported.round(2),
        "backup_restore_success": np.clip(backup, 0, 100).round(2),
    })


def generate_all(seed: int = 42, as_of: pd.Timestamp = DEFAULT_AS_OF) -> dict[str, pd.DataFrame]:
    rng = np.random.default_rng(seed)
    return {
        "vulnerabilities": generate_vulnerabilities(rng, as_of),
        "incidents": generate_incidents(rng, as_of),
        "weekly_metrics": generate_weekly_metrics(rng, as_of),
    }
