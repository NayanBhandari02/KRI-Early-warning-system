# Cyber KRI Early-Warning System

A risk-intelligence pipeline that turns raw security telemetry into **Key Risk Indicators (KRIs)**, forecasts them to raise **Early Warning Indicators (EWIs)** before they breach risk appetite, and rolls everything up into a **likelihood × impact risk register** and an executive briefing.

It is built for a fictional manufacturer, *Northfield Powertrain*, so the risks reflect a plant environment: ransomware stopping production, aging OT/ICS systems, and theft of engineering IP. All data is synthetic.

## The question it answers

> Which cyber risks should leadership act on this week, and which ones are about to get worse?

Most security dashboards show where metrics are today. This one also asks where they are heading, the same way a production line watches leading indicators to catch defects before they happen.

## Pipeline

```
synthetic telemetry ──► weekly KRIs ──► 8-week forecasts ──► early warnings
 (vulns, incidents,      (8 KRIs,         (ARIMA w/ drift)         │
  control metrics)        RAG status)                              ▼
                                         risk register (L × I) ◄───┘
                                                  │
                                 HTML dashboard + executive briefing
```

| Module | Role |
|---|---|
| `src/kri_ews/generate.py` | Seeded synthetic data: ~2,300 vulnerabilities, ~300 incidents tagged with MITRE ATT&CK techniques, weekly control metrics |
| `src/kri_ews/kris.py` | Computes the weekly KRI table and green/amber/red status |
| `src/kri_ews/forecast.py` | Forecasts each KRI and flags projected threshold breaches (EWIs) |
| `src/kri_ews/risk.py` | Scores enterprise risk scenarios as likelihood × impact |
| `src/kri_ews/report.py` | Dashboard (Plotly, works offline) and markdown executive briefing |
| `src/kri_ews/config.py` | Every KRI, threshold, NIST CSF mapping, risk scenario and mitigation, all in one place |

## KRIs and framework mapping

| KRI | Amber / Red | NIST CSF 2.0 | Feeds risk |
|---|---|---|---|
| Critical patch latency (days) | 14 / 30 | PR.PS | R1 Ransomware |
| Critical/high vulns open > 30 days | 5 / 9 | ID.RA | R1 Ransomware |
| OT assets on unsupported OS (%) | 10 / 20 | ID.AM | R1 Ransomware |
| Backup restore test success (%) | 95 / 90 (lower is worse) | RC.RP | R1 Ransomware |
| Phishing simulation click rate (%) | 5 / 8 | PR.AT | R2 Credential compromise |
| Privileged accounts without MFA | 3 / 6 | PR.AA | R2 Credential compromise |
| Mean time to detect (hours) | 24 / 48 | DE.CM | R3 IP theft |
| Mean time to contain (hours) | 48 / 96 | RS.MI | R3 IP theft |

Thresholds are illustrative assumptions, not industry standards. In practice they come from the organization's risk appetite.

## Method

- **KRIs.** Event-based KRIs (patch latency, MTTD, MTTR) use a trailing 4-week window. The first 4 warm-up weeks are dropped.
- **Early warnings.** Each KRI is forecast 8 weeks ahead with ARIMA(1,1,1) with drift, fit on the last 52 weeks. An EWI fires when the forecast mean crosses into a worse status band than today's. The model is deliberately simple and transparent, so a risk committee can question it.
- **Risk scoring.** Likelihood (1–5) comes from the worst status among a risk's linked KRIs (green 2, amber 3, red 4), plus 1 if any linked KRI has an early warning. Impact (1–5) is set per scenario. Score = L × I (max 25): High ≥ 15, Medium ≥ 8.
- **Threat context.** Incidents are grouped by MITRE ATT&CK technique, comparing the last 13 weeks with the prior 13.

## Run it

```bash
pip install -r requirements.txt
python run_pipeline.py            # writes outputs/
python -m pytest -q               # 14 tests
```

Outputs in `outputs/`:
- `dashboard.html`: open in any browser, no internet needed
- `executive_briefing.md`: one-page risk committee brief
- `kri_weekly.csv`, `risk_register.csv`, `early_warnings.json`, `data/*.csv`

## What the current run finds

With the default seed, the system catches the planted slowdown in critical patching. Patch latency is amber at about 23 days and is projected to cross the 30-day red line in about 7 weeks. That early warning raises the likelihood of **R1 Ransomware halts plant production** to 4, giving it the top score of 20/25 (High).

## Known limits

- Patch latency counts only *closed* vulnerabilities, so it understates a growing backlog. That is why it is paired with the open-aging KRI.
- Weekly event counts are small, so MTTD and MTTR are noisy. A real deployment would add volume-aware confidence checks.
- Synthetic data has no real correlation between KRIs and incidents. Don't read causal stories into the charts.

## Possible extensions

- Replace synthetic vulnerabilities with the NVD/CISA KEV feeds and EPSS exploit probabilities.
- Map incidents to MITRE ATT&CK for ICS techniques for plant-floor events.
- Add an LLM step that drafts the briefing narrative, with a human reviewer approving it before it goes out.
