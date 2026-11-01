import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from kri_ews.config import KRIS, RISKS  # noqa: E402
from kri_ews.forecast import early_warnings  # noqa: E402
from kri_ews.generate import generate_all  # noqa: E402
from kri_ews.kris import compute_kris, status  # noqa: E402
from kri_ews.risk import risk_register  # noqa: E402


@pytest.fixture(scope="module")
def pipeline():
    raw = generate_all(seed=42)
    kri = compute_kris(raw["vulnerabilities"], raw["incidents"], raw["weekly_metrics"])
    forecasts, ewis = early_warnings(kri)
    return raw, kri, forecasts, ewis


@pytest.mark.parametrize("value,expected", [(5, "green"), (14, "amber"), (29.9, "amber"), (30, "red")])
def test_status_higher_is_worse(value, expected):
    assert status(value, "patch_latency_critical") == expected


@pytest.mark.parametrize("value,expected", [(99, "green"), (95, "amber"), (90, "red"), (80, "red")])
def test_status_lower_is_worse(value, expected):
    assert status(value, "backup_restore_success") == expected


def test_generation_is_reproducible():
    a, b = generate_all(seed=7), generate_all(seed=7)
    for name in a:
        pd.testing.assert_frame_equal(a[name], b[name])


def test_kri_table_complete(pipeline):
    _, kri, _, _ = pipeline
    assert list(kri.columns) == list(KRIS)
    assert not kri.isna().any().any()
    assert kri.index.is_monotonic_increasing


def test_open_aging_matches_manual_count(pipeline):
    raw, kri, _, _ = pipeline
    v = raw["vulnerabilities"]
    end = kri.index[-1]
    manual = v[v["severity"].isin(["Critical", "High"])
               & (v["discovered"] <= end - pd.Timedelta(days=30))
               & (v["closed"].isna() | (v["closed"] > end))]
    assert kri["crit_high_open_over_30d"].iloc[-1] == len(manual)


def test_planted_patching_slowdown_triggers_early_warning(pipeline):
    _, _, _, ewis = pipeline
    assert "patch_latency_critical" in {e["kri"] for e in ewis}


def test_forecast_shape(pipeline):
    _, _, forecasts, _ = pipeline
    for fc in forecasts.values():
        assert len(fc) == 8
        assert (fc["lower"] <= fc["upper"]).all()


def test_risk_register_scores_and_order(pipeline):
    _, kri, _, ewis = pipeline
    reg = risk_register(kri, ewis)
    assert set(reg["risk_id"]) == set(RISKS)
    assert (reg["score"] == reg["likelihood"] * reg["impact"]).all()
    assert reg["score"].is_monotonic_decreasing
    assert reg["likelihood"].between(1, 5).all()
