"""
NetSentinel - Cyberpunk Report Generator
"""

import json
import datetime

RISK_COLORS = {
    "CRITICAL": "#ff003c",
    "HIGH": "#ff6600",
    "MEDIUM": "#ffcc00",
    "LOW": "#00ff88",
    "NONE": "#444466",
    "UNKNOWN": "#444466"
}

RISK_GLOW = {
    "CRITICAL": "rgba(255,0,60,0.6)",
    "HIGH": "rgba(255,102,0,0.6)",
    "MEDIUM": "rgba(255,204,0,0.6)",
    "LOW": "rgba(0,255,136,0.6)",
    "NONE": "rgba(68,68,102,0.3)",
    "UNKNOWN": "rgba(68,68,102,0.3)"
}

RISK_ICON = {
    "CRITICAL": "☠",
    "HIGH": "⚠",
    "MEDIUM": "◈",
    "LOW": "◉",
    "NONE": "○",
    "UNKNOWN": "○"
}


def generate_html_report(scan_results: dict, ai_results: dict, output_path: str = "report.html"):
    hosts_html = ""
    for host in scan_results.get("hosts", []):
        ai = ai_results.get(host["ip"], {})
        risk = ai.get("risk_level", "UNKNOWN")
        color = RISK_COLORS.get(risk, "#444466")
        glow = RISK_GLOW.get(risk, "rgba(68,68,102,0.3)")
        icon = RISK_ICON.get(risk, "○")

        port_rows = ""
        for p in host.get("open_ports", []):
            rc = RISK_COLORS.get(p["known_risk"], "#444466")
            rg = RISK_GLOW.get(p["known_risk"], "rgba(68,68,102,0.3)")
            ri = RISK_ICON.get(p["known_risk"], "○")
            port_rows += f"""
            <tr class="port-row">
                <td><span class="mono" style="color:#00ccff">{p['port']}</span><span style="color:#334466">/{p['protocol']}</span></td>
                <td style="color:#aabbdd">{p['service']}</td>
                <td style="color:#7788aa">{p.get('product','')} {p.get('version','')}</td>
                <td><span class="risk-pill" style="color:{rc};border-color:{rc};box-shadow:0 0 8px {rg}">{ri} {p['known_risk']}</span></td>
                <td style="color:#556677;font-size:12px">{p.get('risk_reason','N/A')}</td>
            </tr>"""

        if not port_rows:
            port_rows = '<tr><td colspan="5" style="text-align:center;color:#334466;padding:20px">[ NO OPEN PORTS DETECTED ]</td></tr>'

        explanations_html = ""
        for e in ai.get("explanation", []):
            explanations_html += f'<div class="analysis-line"><span class="prompt">&gt;&gt;</span> {e}</div>'

        threat_html = ""
        for t in ai.get("top_threats", []):
            tc = RISK_COLORS.get(t["known_risk"], "#444466")
            tg = RISK_GLOW.get(t["known_risk"], "rgba(68,68,102,0.3)")
            threat_html += f"""
            <div class="threat-card" style="border-left:2px solid {tc};box-shadow:-4px 0 12px {tg}">
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
                    <span class="mono" style="color:{tc}">PORT {t['port']}</span>
                    <span style="color:#7788aa">{t['service']}</span>
                    <span class="risk-pill" style="color:{tc};border-color:{tc};font-size:10px">{t['known_risk']}</span>
                </div>
                <div style="color:#556677;font-size:12px">{t.get('risk_reason','')}</div>
            </div>"""

        is_anomaly = bool(ai.get("is_anomaly", False))
        anomaly_html = (
            '<span class="anomaly-tag blink">⚡ ANOMALY</span>'
            if is_anomaly else
            '<span class="normal-tag">✓ BASELINE</span>'
        )

        hosts_html += f"""
        <div class="host-block" style="--accent:{color};--glow:{glow}">
            <div class="host-header">
                <div class="scan-line"></div>
                <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:16px">
                    <div>
                        <div class="host-ip">{icon} {host['ip']}</div>
                        <div class="host-meta">{host.get('hostname','N/A')} &nbsp;|&nbsp; {host.get('os_guess','OS: Unknown')}</div>
                    </div>
                    <div style="text-align:right">
                        <div class="risk-badge" style="color:{color};text-shadow:0 0 20px {glow}">{risk}</div>
                        <div style="color:#334466;font-size:12px;margin-top:4px">AI CONFIDENCE: <span style="color:#00ccff">{ai.get('confidence',0)}%</span></div>
                        <div style="margin-top:8px">{anomaly_html}</div>
                    </div>
                </div>
            </div>

            <div class="host-body">
                <div class="panel-left">
                    <div class="section-label">◈ OPEN PORTS</div>
                    <table class="port-table">
                        <thead>
                            <tr>
                                <th>PORT</th><th>SERVICE</th><th>VERSION</th><th>RISK</th><th>VECTOR</th>
                            </tr>
                        </thead>
                        <tbody>{port_rows}</tbody>
                    </table>
                </div>
                <div class="panel-right">
                    <div class="section-label">◈ AI ANALYSIS</div>
                    <div class="analysis-box">{explanations_html}</div>
                    <div class="section-label" style="margin-top:20px">◈ TOP THREATS</div>
                    <div class="threats-box">
                        {threat_html if threat_html else '<div style="color:#334466;font-size:13px">[ NO CRITICAL THREATS ]</div>'}
                    </div>
                </div>
            </div>
        </div>"""

    total_hosts = len(scan_results.get("hosts", []))
    total_ports = sum(len(h.get("open_ports", [])) for h in scan_results.get("hosts", []))
    scan_time = scan_results.get("scan_time", "")
    target = scan_results.get("target", "N/A")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>NetSentinel // Vulnerability Report</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {{
  --bg: #02030a;
  --bg2: #05080f;
  --bg3: #080c18;
  --border: #0a1428;
  --border2: #0f1e3a;
  --cyan: #00ccff;
  --green: #00ff88;
  --text: #8899bb;
  --text2: #aabbdd;
  --dim: #334466;
}}

* {{ margin:0; padding:0; box-sizing:border-box; }}

body {{
  font-family: 'Rajdhani', sans-serif;
  background: var(--bg);
  color: var(--text2);
  min-height: 100vh;
  overflow-x: hidden;
}}

.mono {{ font-family: 'Share Tech Mono', monospace; }}

/* Matrix rain canvas */
#matrix {{
  position: fixed;
  top: 0; left: 0;
  width: 100%; height: 100%;
  opacity: 0.03;
  pointer-events: none;
  z-index: 0;
}}

/* Grid overlay */
body::before {{
  content: '';
  position: fixed;
  inset: 0;
  background-image:
    linear-gradient(rgba(0,204,255,0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,204,255,0.03) 1px, transparent 1px);
  background-size: 40px 40px;
  pointer-events: none;
  z-index: 0;
}}

/* Hero */
.hero {{
  position: relative;
  z-index: 1;
  padding: 48px 48px 40px;
  border-bottom: 1px solid var(--border2);
  background: linear-gradient(180deg, #040814 0%, transparent 100%);
}}

.hero-tag {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: var(--cyan);
  letter-spacing: 6px;
  margin-bottom: 16px;
  opacity: 0.7;
}}

.hero h1 {{
  font-size: 48px;
  font-weight: 700;
  letter-spacing: 4px;
  color: #fff;
  text-transform: uppercase;
  line-height: 1;
  margin-bottom: 8px;
  text-shadow: 0 0 40px rgba(0,204,255,0.3);
}}

.hero-sub {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 13px;
  color: var(--dim);
  margin-top: 8px;
}}

.hero-sub span {{ color: var(--cyan); }}

.stats-row {{
  display: flex;
  gap: 16px;
  margin-top: 36px;
  flex-wrap: wrap;
}}

.stat-card {{
  background: var(--bg3);
  border: 1px solid var(--border2);
  border-top: 2px solid var(--cyan);
  padding: 16px 24px;
  min-width: 160px;
  position: relative;
  overflow: hidden;
}}

.stat-card::after {{
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, var(--cyan), transparent);
  animation: scan-line 3s linear infinite;
}}

@keyframes scan-line {{
  0% {{ transform: translateX(-100%); }}
  100% {{ transform: translateX(100%); }}
}}

.stat-label {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  letter-spacing: 3px;
  color: var(--dim);
  margin-bottom: 8px;
}}

.stat-val {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 32px;
  color: var(--cyan);
  font-weight: 400;
}}

/* Content */
.content {{
  position: relative;
  z-index: 1;
  max-width: 1200px;
  margin: 0 auto;
  padding: 40px 48px 80px;
}}

/* Host block */
.host-block {{
  background: var(--bg2);
  border: 1px solid var(--border2);
  border-left: 3px solid var(--accent);
  margin-bottom: 32px;
  position: relative;
  overflow: hidden;
  box-shadow: -8px 0 32px var(--glow), inset 0 0 80px rgba(0,204,255,0.01);
}}

.host-block::before {{
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 1px;
  background: linear-gradient(90deg, var(--accent), transparent);
  opacity: 0.5;
}}

.scan-line {{
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, var(--accent), transparent);
  animation: scan 4s linear infinite;
  opacity: 0.4;
}}

@keyframes scan {{
  0% {{ transform: translateY(0); opacity: 0.4; }}
  100% {{ transform: translateY(200px); opacity: 0; }}
}}

.host-header {{
  padding: 24px 28px;
  border-bottom: 1px solid var(--border2);
  background: rgba(0,0,0,0.3);
  position: relative;
}}

.host-ip {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 22px;
  color: var(--accent);
  text-shadow: 0 0 20px var(--glow);
  margin-bottom: 6px;
}}

.host-meta {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 12px;
  color: var(--dim);
}}

.risk-badge {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 28px;
  letter-spacing: 4px;
  font-weight: 700;
}}

.host-body {{
  display: grid;
  grid-template-columns: 1fr 360px;
}}

@media(max-width:900px) {{ .host-body {{ grid-template-columns: 1fr; }} }}

.panel-left {{ padding: 24px 28px; }}

.panel-right {{
  padding: 24px 24px;
  border-left: 1px solid var(--border2);
  background: rgba(0,0,0,0.2);
}}

.section-label {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  letter-spacing: 4px;
  color: var(--cyan);
  margin-bottom: 16px;
  opacity: 0.7;
}}

/* Port table */
.port-table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}}

.port-table th {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  letter-spacing: 2px;
  color: var(--dim);
  text-align: left;
  padding: 8px 12px;
  border-bottom: 1px solid var(--border2);
}}

.port-table td {{
  padding: 12px 12px;
  border-bottom: 1px solid rgba(10,20,40,0.8);
  vertical-align: middle;
}}

.port-row:hover td {{
  background: rgba(0,204,255,0.03);
}}

.port-row:last-child td {{ border-bottom: none; }}

.risk-pill {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  border: 1px solid;
  padding: 2px 10px;
  letter-spacing: 1px;
  white-space: nowrap;
}}

/* Analysis */
.analysis-box {{
  background: rgba(0,0,0,0.3);
  border: 1px solid var(--border2);
  padding: 16px;
  font-size: 13px;
  line-height: 1.8;
}}

.analysis-line {{
  margin-bottom: 8px;
  color: #7799aa;
}}

.prompt {{
  color: var(--cyan);
  font-family: 'Share Tech Mono', monospace;
  margin-right: 8px;
  opacity: 0.6;
}}

.threats-box {{
  display: flex;
  flex-direction: column;
  gap: 10px;
}}

.threat-card {{
  background: rgba(0,0,0,0.3);
  border-left: 2px solid;
  padding: 12px 14px;
}}

/* Badges */
.anomaly-tag {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: #ff003c;
  border: 1px solid #ff003c;
  padding: 3px 12px;
  letter-spacing: 2px;
  box-shadow: 0 0 12px rgba(255,0,60,0.4);
}}

.normal-tag {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: #00ff88;
  border: 1px solid #00ff88;
  padding: 3px 12px;
  letter-spacing: 2px;
}}

.blink {{ animation: blink 1.5s steps(1) infinite; }}
@keyframes blink {{
  0%, 100% {{ opacity: 1; }}
  50% {{ opacity: 0.2; }}
}}

/* Footer */
.footer {{
  position: relative;
  z-index: 1;
  text-align: center;
  padding: 32px;
  border-top: 1px solid var(--border2);
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: var(--dim);
  letter-spacing: 2px;
}}

.footer a {{ color: var(--cyan); text-decoration: none; }}

/* Corner decorations */
.corner {{
  position: absolute;
  width: 12px;
  height: 12px;
  border-color: var(--cyan);
  border-style: solid;
  opacity: 0.4;
}}
.corner-tl {{ top: 8px; left: 8px; border-width: 1px 0 0 1px; }}
.corner-tr {{ top: 8px; right: 8px; border-width: 1px 1px 0 0; }}
.corner-bl {{ bottom: 8px; left: 8px; border-width: 0 0 1px 1px; }}
.corner-br {{ bottom: 8px; right: 8px; border-width: 0 1px 1px 0; }}
</style>
</head>
<body>

<canvas id="matrix"></canvas>

<div class="hero">
  <div class="corner corner-tl"></div>
  <div class="corner corner-tr"></div>
  <div class="hero-tag">// NETSENTINEL AI-POWERED SCANNER // v1.0</div>
  <h1>Vulnerability<br>Report</h1>
  <div class="hero-sub">
    TARGET: <span>{target}</span> &nbsp;//&nbsp;
    SCANNED: <span>{scan_time[:19].replace('T',' ') if scan_time else 'N/A'}</span>
  </div>
  <div class="stats-row">
    <div class="stat-card">
      <div class="stat-label">HOSTS SCANNED</div>
      <div class="stat-val">{str(total_hosts).zfill(2)}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">OPEN PORTS</div>
      <div class="stat-val" style="color:#ff6600">{str(total_ports).zfill(2)}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">AI ENGINE</div>
      <div class="stat-val" style="font-size:14px;color:#00ff88;margin-top:4px">RAND.FOREST<br>+ ISO.FOREST</div>
    </div>
    <div class="stat-card" style="border-top-color:#ff003c">
      <div class="stat-label">LEGAL STATUS</div>
      <div class="stat-val" style="font-size:13px;color:#ff003c;margin-top:4px">AUTHORIZED<br>USE ONLY</div>
    </div>
  </div>
</div>

<div class="content">
  {hosts_html if hosts_html else '<div style="text-align:center;color:#334466;padding:60px;font-family:Share Tech Mono">[ NO HOSTS DETECTED ]</div>'}
</div>

<div class="footer">
  <div class="corner corner-tl"></div>
  <div class="corner corner-br"></div>
  NETSENTINEL v1.0 &nbsp;//&nbsp;
  AI-POWERED NETWORK VULNERABILITY SCANNER &nbsp;//&nbsp;
  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br><br>
  ⚠ USE ONLY ON NETWORKS YOU OWN OR HAVE EXPLICIT WRITTEN PERMISSION TO TEST
</div>

<script>
const canvas = document.getElementById('matrix');
const ctx = canvas.getContext('2d');
canvas.width = window.innerWidth;
canvas.height = window.innerHeight;
const cols = Math.floor(canvas.width / 20);
const drops = Array(cols).fill(1);
const chars = '01アイウエオカキクケコサシスセソタチツテト';
function draw() {{
  ctx.fillStyle = 'rgba(2,3,10,0.05)';
  ctx.fillRect(0,0,canvas.width,canvas.height);
  ctx.fillStyle = '#00ccff';
  ctx.font = '14px Share Tech Mono, monospace';
  drops.forEach((y, i) => {{
    const char = chars[Math.floor(Math.random()*chars.length)];
    ctx.fillText(char, i*20, y*20);
    if(y*20 > canvas.height && Math.random() > 0.975) drops[i] = 0;
    drops[i]++;
  }});
}}
setInterval(draw, 60);
window.addEventListener('resize', () => {{
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
}});
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[✓] HTML report saved: {output_path}")
    return output_path


def generate_json_report(scan_results: dict, ai_results: dict, output_path: str = "report.json"):
    def safe_convert(obj):
        if hasattr(obj, 'item'):
            return obj.item()
        if isinstance(obj, bool):
            return bool(obj)
        raise TypeError(f"Type {type(obj)} not serializable")

    report = {
        "meta": {
            "tool": "NetSentinel",
            "version": "1.0",
            "generated_at": datetime.datetime.now().isoformat(),
            "target": scan_results.get("target"),
            "scan_time": scan_results.get("scan_time")
        },
        "summary": {
            "total_hosts": len(scan_results.get("hosts", [])),
            "total_open_ports": sum(len(h.get("open_ports", [])) for h in scan_results.get("hosts", []))
        },
        "hosts": []
    }

    for host in scan_results.get("hosts", []):
        ai = ai_results.get(host["ip"], {})
        ai_clean = dict(ai)
        ai_clean["is_anomaly"] = bool(ai.get("is_anomaly", False))
        report["hosts"].append({
            "host_info": host,
            "ai_analysis": ai_clean
        })

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=safe_convert)
    print(f"[✓] JSON report saved: {output_path}")
    return output_path