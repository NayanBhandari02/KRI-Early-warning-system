"""Turn raw security telemetry into a weekly Key Risk Indicator (KRI) table."""
from __future__ import annotations

import pandas as pd

from .config import KRIS, TRAILING_WINDOW_WEEKS


def status(value: float, kri_key: str) -> str:
    """Return green / amber / red for one KRI value against its thresholds."""
    cfg = KRIS[kri_key]
    if pd.isna(value):
        return "unknown"
    if cfg["direction"] == "up":
        if value >= cfg["red"]:
            return "red"
        if value >= cfg["amber"]:
            return "amber"
        return "green"
    if value <= cfg["red"]:
        return "red"
    if value <= cfg["amber"]:
        return "amber"
    return "green"


def compute_kris(vulns: pd.DataFrame, incidents: pd.DataFrame, weekly: pd.DataFrame) -> pd.DataFrame:
    """One row per week (indexed by week end), one column per KRI."""
    window = pd.Timedelta(weeks=TRAILING_WINDOW_WEEKS)
    crit = vulns[vulns["severity"] == "Critical"].copy()
    crit["days_open"] = (crit["closed"] - crit["discovered"]).dt.days
    crit_high = vulns[vulns["severity"].isin(["Critical", "High"])]

    rows = []
    for start in weekly["week_start"]:
        end = start + pd.Timedelta(days=6)
        lo = end - window

        closed_recent = crit[(crit["closed"] > lo) & (crit["closed"] <= end)]
        still_open = crit_high[
            (crit_high["discovered"] <= end - pd.Timedelta(days=30))
            & (crit_high["closed"].isna() | (crit_high["closed"] > end))
        ]
        inc = incidents[(incidents["opened"] > lo) & (incidents["opened"] <= end)]

        rows.append({
            "week_end": end,
            "patch_latency_critical": closed_recent["days_open"].mean(),
            "crit_high_open_over_30d": len(still_open),
            "mttd_hours": inc["hours_to_detect"].mean(),
            "mttr_hours": inc["hours_to_contain"].mean(),
        })

    kri = pd.DataFrame(rows).set_index("week_end")
    w = weekly.assign(week_end=weekly["week_start"] + pd.Timedelta(days=6)).set_index("week_end")
    kri = kri.join(w.drop(columns="week_start"))
    # Weeks with no qualifying events carry the last known value forward.
    kri = kri.ffill()
    # Drop the warm-up weeks before the trailing window is full.
    kri = kri.iloc[TRAILING_WINDOW_WEEKS:]
    return kri[list(KRIS)].round(2)
