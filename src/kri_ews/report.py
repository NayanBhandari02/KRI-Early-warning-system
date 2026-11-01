"""Render the HTML dashboard and the markdown executive briefing."""
from __future__ import annotations

import html

import pandas as pd
import plotly.graph_objects as go
from plotly.offline import get_plotlyjs

from .config import FORECAST_HORIZON_WEEKS, KRIS, RISKS
from .kris import status
from .risk import rating

STATUS_COLOR = {"green": "#2e7d32", "amber": "#b26a00", "red": "#c62828", "unknown": "#757575"}
HISTORY_WEEKS = 52


def _fmt(value: float, unit: str) -> str:
    if unit == "count":
        return f"{value:.0f}"
    if unit == "%":
        return f"{value:.1f}%"
    return f"{value:.1f} {unit}"


def attack_summary(incidents: pd.DataFrame, as_of: pd.Timestamp) -> pd.DataFrame:
    """Incidents per ATT&CK technique: last 13 weeks vs. the 13 weeks before."""
    recent_lo = as_of - pd.Timedelta(weeks=13)
    prior_lo = recent_lo - pd.Timedelta(weeks=13)
    label = incidents["attack_technique_id"] + " " + incidents["attack_technique"]
    recent = label[(incidents["opened"] > recent_lo) & (incidents["opened"] <= as_of)].value_counts()
    prior = label[(incidents["opened"] > prior_lo) & (incidents["opened"] <= recent_lo)].value_counts()
    out = pd.DataFrame({"last_13w": recent, "prior_13w": prior}).fillna(0).astype(int)
    out["change"] = out["last_13w"] - out["prior_13w"]
    return out.sort_values("last_13w", ascending=False)


def executive_summary(register: pd.DataFrame, ewis: list[dict]) -> str:
    top = register.iloc[0]
    text = (f"Top enterprise cyber risk this week is <b>{html.escape(top['risk'])}</b> "
            f"(score {top['score']}/25, {rating(top['score'])}), driven by {html.escape(top['drivers'])}.")
    if ewis:
        e = ewis[0]
        text += (f" Early warning: <b>{html.escape(e['kri_name'])}</b> is projected to move from "
                 f"{e['current_status']} to {e['projected_status']} in about {e['weeks_until']} weeks "
                 f"if the current trend holds.")
    else:
        text += " No KRI is projected to worsen within the forecast horizon."
    return text


def _kri_figure(key: str, series: pd.Series, fc: pd.DataFrame) -> go.Figure:
    cfg = KRIS[key]
    hist = series.iloc[-HISTORY_WEEKS:]
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=list(fc.index) + list(fc.index[::-1]),
                             y=list(fc["upper"]) + list(fc["lower"][::-1]),
                             mode="lines", fill="toself", fillcolor="rgba(31,58,95,0.15)", line=dict(width=0),
                             hoverinfo="skip", name="80% interval"))
    fig.add_trace(go.Scatter(x=hist.index, y=hist.values, mode="lines", name="Actual",
                             line=dict(color="#1f3a5f", width=2)))
    fig.add_trace(go.Scatter(x=fc.index, y=fc["mean"], mode="lines", name="Forecast",
                             line=dict(color="#1f3a5f", width=2, dash="dot")))
    for level in ("amber", "red"):
        fig.add_hline(y=cfg[level], line=dict(color=STATUS_COLOR[level], width=1, dash="dash"),
                      annotation_text=level, annotation_position="top right",
                      annotation_font_color=STATUS_COLOR[level])
    fig.update_layout(height=260, margin=dict(l=40, r=10, t=36, b=30), showlegend=False,
                      title=dict(text=f"{cfg['name']} ({cfg['unit']})", font=dict(size=14)),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      font=dict(color="#555"), xaxis=dict(gridcolor="rgba(128,128,128,0.15)"),
                      yaxis=dict(gridcolor="rgba(128,128,128,0.15)"))
    return fig


def _attack_figure(attack: pd.DataFrame) -> go.Figure:
    a = attack.iloc[::-1]
    fig = go.Figure()
    fig.add_trace(go.Bar(y=a.index, x=a["prior_13w"], orientation="h", name="Prior 13 weeks",
                         marker_color="rgba(128,128,128,0.45)"))
    fig.add_trace(go.Bar(y=a.index, x=a["last_13w"], orientation="h", name="Last 13 weeks",
                         marker_color="#1f3a5f"))
    fig.update_layout(barmode="group", height=360, margin=dict(l=10, r=10, t=10, b=30),
                      legend=dict(orientation="h", y=-0.12), paper_bgcolor="rgba(0,0,0,0)",
                      plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#555"),
                      xaxis=dict(title="Incidents", gridcolor="rgba(128,128,128,0.15)"),
                      yaxis=dict(automargin=True))
    return fig


CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1c2430;--muted:#5d6876;--line:#dde2e8;--accent:#1f3a5f}
@media (prefers-color-scheme:dark){:root{--bg:#12161c;--card:#1b212a;--ink:#e6e9ee;--muted:#9aa5b3;--line:#2c3440;--accent:#8fb3e0}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:1.5rem;margin:0 0 4px;color:var(--accent)} h2{font-size:1.1rem;margin:32px 0 12px}
.sub{color:var(--muted);font-size:.9rem}
.summary{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:8px;padding:14px 16px;margin-top:16px}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:12px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.tile .n{font-size:.85rem;color:var(--muted)} .tile .v{font-size:1.5rem;font-weight:650;margin:2px 0}
.tile .f{font-size:.75rem;color:var(--muted)}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;color:#fff;font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.03em}
.ewi{display:inline-block;margin-left:6px;padding:1px 8px;border-radius:999px;border:1px solid #c62828;color:#c62828;font-size:.72rem;font-weight:600}
.tablewrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:.88rem} th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:.78rem;text-transform:uppercase;letter-spacing:.03em}
tr:last-child td{border-bottom:0}
.score{font-weight:700;border-radius:6px;padding:2px 8px;color:#fff}
.charts{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:12px}
.chart{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:4px}
.note{color:var(--muted);font-size:.82rem;margin-top:32px}
@media (max-width:420px){.charts{grid-template-columns:1fr}}
"""


def render_dashboard(kri, forecasts, ewis, register, attack, as_of, company) -> str:
    ewi_keys = {e["kri"]: e for e in ewis}
    latest = kri.iloc[-1]

    tiles = []
    for key, cfg in KRIS.items():
        st = status(latest[key], key)
        badge = ""
        if key in ewi_keys:
            e = ewi_keys[key]
            badge = f'<span class="ewi">EWI: {e["projected_status"]} in ~{e["weeks_until"]}w</span>'
        tiles.append(
            f'<div class="tile"><div class="n">{html.escape(cfg["name"])}</div>'
            f'<div class="v">{_fmt(latest[key], cfg["unit"])}</div>'
            f'<span class="pill" style="background:{STATUS_COLOR[st]}">{st}</span>{badge}'
            f'<div class="f">NIST CSF 2.0: {html.escape(cfg["nist_csf"])}</div></div>')

    reg_rows = []
    for _, r in register.iterrows():
        color = {"High": "#c62828", "Medium": "#b26a00", "Low": "#2e7d32"}[rating(r["score"])]
        reg_rows.append(
            f"<tr><td><b>{r['risk_id']}</b> {html.escape(r['risk'])}</td>"
            f"<td>{r['likelihood']}</td><td>{r['impact']}</td>"
            f'<td><span class="score" style="background:{color}">{r["score"]}</span></td>'
            f"<td>{html.escape(r['drivers'])}</td><td>{html.escape(r['early_warnings'])}</td></tr>")

    charts = []
    for i, key in enumerate(KRIS):
        fig = _kri_figure(key, kri[key], forecasts[key])
        charts.append('<div class="chart">' + fig.to_html(full_html=False, include_plotlyjs=False,
                                                          config={"displayModeBar": False},
                                                          div_id=f"kri{i}") + "</div>")
    attack_html = _attack_figure(attack).to_html(full_html=False, include_plotlyjs=False,
                                                 config={"displayModeBar": False}, div_id="attack")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cyber Risk Early Warning</title>
<script>{get_plotlyjs()}</script>
<style>{CSS}</style></head><body><div class="wrap">
<h1>Cyber Risk Early-Warning Dashboard</h1>
<div class="sub">{html.escape(company)} &middot; week ending {as_of.date().isoformat()} &middot; synthetic data</div>
<div class="summary">{executive_summary(register, ewis)}</div>

<h2>Enterprise risk register (likelihood &times; impact)</h2>
<div class="tablewrap"><table><thead><tr><th>Risk</th><th>L</th><th>I</th><th>Score</th><th>KRI drivers</th><th>Early warnings</th></tr></thead>
<tbody>{''.join(reg_rows)}</tbody></table></div>

<h2>Key Risk Indicators</h2>
<div class="tiles">{''.join(tiles)}</div>

<h2>KRI trends and {FORECAST_HORIZON_WEEKS}-week forecast</h2>
<div class="charts">{''.join(charts)}</div>

<h2>Incidents by MITRE ATT&amp;CK technique</h2>
<div class="chart">{attack_html}</div>

<p class="note">Method: KRIs are computed weekly from vulnerability, incident and control telemetry.
Each KRI is forecast {FORECAST_HORIZON_WEEKS} weeks ahead with an ARIMA(1,1,1)-with-drift model on the last 52 weeks;
an early warning fires when the forecast crosses into a worse status band. Risk likelihood (1&ndash;5) comes from the worst linked
KRI status, raised one level when an early warning fires. All thresholds are illustrative. All data is synthetic.</p>
</div></body></html>"""


def render_briefing(kri, ewis, register, attack, as_of, company) -> str:
    latest = kri.iloc[-1]
    prev = kri.iloc[-5]  # four weeks earlier
    top = register.iloc[0]
    lines = [
        f"# Cyber Risk Briefing: {company}",
        f"*Week ending {as_of.date().isoformat()} · synthetic data · prepared for the Risk Committee*",
        "",
        "## Bottom line",
        f"- **{top['risk']}** is the top risk (score {top['score']}/25, {rating(top['score'])}), "
        f"driven by {top['drivers']}.",
    ]
    for e in ewis:
        unit = KRIS[e["kri"]]["unit"]
        lines.append(f"- **Early warning:** {e['kri_name']} is at {_fmt(e['current_value'], unit)} "
                     f"({e['current_status']}) and is projected to reach {_fmt(e['projected_value'], unit)} "
                     f"({e['projected_status']}) by about {e['projected_week']} if the trend holds.")
    if not ewis:
        lines.append("- No KRI is projected to worsen within the forecast horizon.")

    lines += ["", "## Risk register", "",
              "| Risk | Likelihood | Impact | Score | Rating | Drivers |",
              "|---|---|---|---|---|---|"]
    for _, r in register.iterrows():
        lines.append(f"| {r['risk_id']} {r['risk']} | {r['likelihood']} | {r['impact']} | "
                     f"{r['score']} | {rating(r['score'])} | {r['drivers']} |")

    lines += ["", "## Key Risk Indicators", "",
              "| KRI | Current | 4 weeks ago | Status | NIST CSF 2.0 |", "|---|---|---|---|---|"]
    for key, cfg in KRIS.items():
        lines.append(f"| {cfg['name']} | {_fmt(latest[key], cfg['unit'])} | "
                     f"{_fmt(prev[key], cfg['unit'])} | {status(latest[key], key).upper()} | {cfg['nist_csf']} |")

    rising = attack[attack["change"] >= 2].sort_values("change", ascending=False)
    lines += ["", "## Threat activity (MITRE ATT&CK, last 13 weeks)"]
    for tech, r in attack.head(3).iterrows():
        lines.append(f"- {tech}: {r['last_13w']} incidents (prior 13 weeks: {r['prior_13w']})")
    if not rising.empty:
        lines.append(f"- Fastest rising: {rising.index[0]} (+{rising.iloc[0]['change']})")

    lines += ["", "## Recommended actions (highest-scoring risk first)"]
    seen = set()
    for _, r in register.iterrows():
        for key in RISKS[r["risk_id"]]["kris"]:
            if key in seen or status(latest[key], key) == "green":
                continue
            seen.add(key)
            lines.append(f"{len(seen)}. **{KRIS[key]['name']}** ({r['risk_id']}): {KRIS[key]['mitigation']}")
    if not seen:
        lines.append("No KRIs outside appetite; maintain current controls.")

    lines += ["", "## Method and limits",
              f"KRIs are computed weekly; each is forecast {FORECAST_HORIZON_WEEKS} weeks ahead with a simple "
              "ARIMA model. Forecasts are trend signals, not predictions. Thresholds are illustrative and "
              "should be set to the organization's risk appetite. Patch latency only counts closed items, so it "
              "can understate a growing backlog; read it alongside the open-vulnerability aging KRI."]
    return "\n".join(lines) + "\n"
