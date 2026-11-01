"""
End-to-end pipeline:
  synthetic telemetry -> weekly KRIs -> early-warning forecasts -> risk register
  -> HTML dashboard + executive briefing + CSV extracts.

Usage:
    python run_pipeline.py [--seed 42] [--out outputs]
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from kri_ews.forecast import early_warnings  # noqa: E402
from kri_ews.generate import DEFAULT_AS_OF, generate_all  # noqa: E402
from kri_ews.kris import compute_kris  # noqa: E402
from kri_ews.report import attack_summary, render_briefing, render_dashboard  # noqa: E402
from kri_ews.risk import risk_register  # noqa: E402

COMPANY = "Northfield Powertrain (fictional)"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="outputs")
    args = ap.parse_args()

    out = Path(args.out)
    (out / "data").mkdir(parents=True, exist_ok=True)

    raw = generate_all(seed=args.seed)
    for name, df in raw.items():
        df.to_csv(out / "data" / f"{name}.csv", index=False)

    kri = compute_kris(raw["vulnerabilities"], raw["incidents"], raw["weekly_metrics"])
    forecasts, ewis = early_warnings(kri)
    register = risk_register(kri, ewis)
    attack = attack_summary(raw["incidents"], DEFAULT_AS_OF)

    kri.to_csv(out / "kri_weekly.csv")
    register.to_csv(out / "risk_register.csv", index=False)
    (out / "early_warnings.json").write_text(json.dumps(ewis, indent=2))
    (out / "dashboard.html").write_text(
        render_dashboard(kri, forecasts, ewis, register, attack, DEFAULT_AS_OF, COMPANY))
    (out / "executive_briefing.md").write_text(
        render_briefing(kri, ewis, register, attack, DEFAULT_AS_OF, COMPANY))

    print(f"Top risk: {register.iloc[0]['risk']} (score {register.iloc[0]['score']}/25)")
    print(f"Early warnings: {len(ewis)}")
    for e in ewis:
        print(f"  - {e['kri_name']}: {e['current_status']} -> {e['projected_status']} in ~{e['weeks_until']} weeks")
    print(f"Outputs written to {out.resolve()}")


if __name__ == "__main__":
    main()
