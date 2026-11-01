"""Roll KRIs and early warnings up into a prioritized enterprise risk register."""
from __future__ import annotations

import pandas as pd

from .config import KRIS, RISKS, STATUS_LIKELIHOOD
from .forecast import STATUS_RANK
from .kris import status


def risk_register(kri: pd.DataFrame, ewis: list[dict]) -> pd.DataFrame:
    """Score each risk scenario as likelihood x impact (each 1-5, score 1-25)."""
    latest = kri.iloc[-1]
    ewi_kris = {e["kri"] for e in ewis}
    rows = []
    for rid, r in RISKS.items():
        statuses = {k: status(latest[k], k) for k in r["kris"]}
        worst = max(statuses.values(), key=lambda s: STATUS_RANK[s])
        likelihood = STATUS_LIKELIHOOD.get(worst, 2)
        drivers = [KRIS[k]["name"] for k, s in statuses.items() if s != "green"]
        warned = [KRIS[k]["name"] for k in r["kris"] if k in ewi_kris]
        if warned:
            likelihood = min(5, likelihood + 1)
        rows.append({
            "risk_id": rid,
            "risk": r["name"],
            "likelihood": likelihood,
            "impact": r["impact"],
            "score": likelihood * r["impact"],
            "worst_kri_status": worst,
            "drivers": ", ".join(drivers) or "None",
            "early_warnings": ", ".join(warned) or "None",
            "impact_rationale": r["impact_rationale"],
        })
    return pd.DataFrame(rows).sort_values("score", ascending=False).reset_index(drop=True)


def rating(score: int) -> str:
    if score >= 15:
        return "High"
    if score >= 8:
        return "Medium"
    return "Low"
