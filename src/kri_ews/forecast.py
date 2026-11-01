"""
Early Warning Indicators (EWIs): forecast each KRI forward and flag any that
are projected to cross a worse threshold within the forecast horizon.

The model is a small SARIMA-family model (ARIMA(1,1,1) with drift) fit on the
last 52 weeks. It is deliberately simple: the goal is a transparent early
signal a risk committee can question, not a precise prediction.
"""
from __future__ import annotations

import warnings

import numpy as np
import pandas as pd
from statsmodels.tsa.statespace.sarimax import SARIMAX

from .config import FORECAST_HORIZON_WEEKS, KRIS
from .kris import status

STATUS_RANK = {"unknown": -1, "green": 0, "amber": 1, "red": 2}


def forecast_kri(series: pd.Series, horizon: int = FORECAST_HORIZON_WEEKS) -> pd.DataFrame:
    """Return a forecast frame with mean, lower and upper (80% interval)."""
    y = series.dropna().iloc[-52:].astype(float)
    future_idx = pd.date_range(y.index[-1] + pd.Timedelta(weeks=1), periods=horizon, freq="7D")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            fit = SARIMAX(y.values, order=(1, 1, 1), trend="t",
                          enforce_stationarity=False, enforce_invertibility=False).fit(disp=False)
            fc = fit.get_forecast(horizon)
            mean = fc.predicted_mean
            ci = fc.conf_int(alpha=0.2)
            lower, upper = ci[:, 0], ci[:, 1]
    except Exception:  # fall back to a straight-line trend if the model fails
        slope = np.polyfit(np.arange(len(y)), y.values, 1)[0]
        mean = y.values[-1] + slope * np.arange(1, horizon + 1)
        spread = y.std()
        lower, upper = mean - spread, mean + spread
    fc = pd.DataFrame({"mean": mean, "lower": lower, "upper": upper}, index=future_idx)
    # Counts and percentages cannot go below 0 (or above 100 for percentages).
    upper_cap = 100 if KRIS.get(series.name, {}).get("unit") == "%" else None
    return fc.clip(lower=0, upper=upper_cap)


def early_warnings(kri: pd.DataFrame, horizon: int = FORECAST_HORIZON_WEEKS):
    """Forecast every KRI. Returns (forecasts dict, warnings list)."""
    forecasts, ewis = {}, []
    for key, cfg in KRIS.items():
        fc = forecast_kri(kri[key], horizon)
        forecasts[key] = fc
        current = status(kri[key].iloc[-1], key)
        for week_ahead, (date, value) in enumerate(fc["mean"].items(), start=1):
            projected = status(value, key)
            if STATUS_RANK[projected] > STATUS_RANK[current]:
                ewis.append({
                    "kri": key,
                    "kri_name": cfg["name"],
                    "current_value": round(float(kri[key].iloc[-1]), 2),
                    "current_status": current,
                    "projected_status": projected,
                    "projected_value": round(float(value), 2),
                    "weeks_until": week_ahead,
                    "projected_week": date.date().isoformat(),
                })
                break
    return forecasts, ewis
