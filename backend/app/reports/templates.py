REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8f9fa; color: #333; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 30px; }
        .header { background: linear-gradient(135deg, #0d1b2a 0%, #1b263b 50%, #415a77 100%); color: white; padding: 50px 40px; border-radius: 16px; margin-bottom: 30px; }
        .header h1 { font-size: 32px; margin-bottom: 8px; }
        .header .subtitle { opacity: 0.85; font-size: 15px; }
        .header .meta { display: flex; gap: 25px; margin-top: 15px; font-size: 13px; opacity: 0.7; }
        .section { background: white; border-radius: 12px; padding: 30px; margin-bottom: 25px; box-shadow: 0 2px 12px rgba(0,0,0,0.06); }
        .section h2 { font-size: 20px; margin-bottom: 20px; color: #1b263b; border-bottom: 2px solid #e9ecef; padding-bottom: 10px; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-bottom: 25px; }
        .metric { padding: 20px; border-radius: 10px; text-align: center; }
        .metric .value { font-size: 42px; font-weight: 700; line-height: 1; }
        .metric .label { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-top: 6px; }
        .metric.critical { background: #fff5f5; color: #c0392b; border: 1px solid #f5c6cb; }
        .metric.high { background: #fff8f0; color: #e67e22; border: 1px solid #ffeaa7; }
        .metric.medium { background: #fffbf0; color: #f39c12; border: 1px solid #ffeeba; }
        .metric.low { background: #f0fff4; color: #27ae60; border: 1px solid #c3e6cb; }
        .metric.info { background: #f0f9ff; color: #2980b9; border: 1px solid #bee5eb; }
        .metric.total { background: #f8f9fa; color: #495057; border: 1px solid #dee2e6; }
        .chart-bar { display: flex; height: 30px; border-radius: 6px; overflow: hidden; margin: 15px 0; }
        .chart-bar .seg { transition: width 0.3s; }
        .seg.critical { background: #c0392b; }
        .seg.high { background: #e67e22; }
        .seg.medium { background: #f39c12; }
        .seg.low { background: #27ae60; }
        .seg.info { background: #2980b9; }
        .legend { display: flex; gap: 20px; flex-wrap: wrap; margin-top: 10px; font-size: 13px; }
        .legend-item { display: flex; align-items: center; gap: 6px; }
        .legend-dot { width: 12px; height: 12px; border-radius: 3px; }
        .finding { border: 1px solid #e9ecef; border-radius: 10px; padding: 20px; margin-bottom: 15px; border-left: 5px solid #ddd; }
        .finding.critical { border-left-color: #c0392b; }
        .finding.high { border-left-color: #e67e22; }
        .finding.medium { border-left-color: #f39c12; }
        .finding.low { border-left-color: #27ae60; }
        .finding.info { border-left-color: #2980b9; }
        .finding-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px; }
        .finding-header h4 { font-size: 16px; flex: 1; }
        .badges { display: flex; gap: 8px; flex-wrap: wrap; }
        .badge { padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
        .badge.sev { background: #e9ecef; color: #495057; }
        .badge.tool { background: #e3f2fd; color: #1565c0; }
        .badge.cwe { background: #f3e5f5; color: #7b1fa2; }
        .badge.status { background: #e8f5e9; color: #2e7d32; }
        .finding p { color: #555; font-size: 14px; margin-bottom: 8px; }
        .finding pre { background: #f8f9fa; border: 1px solid #e9ecef; padding: 12px; border-radius: 6px; font-size: 12px; overflow-x: auto; white-space: pre-wrap; }
        .finding .label-sm { font-weight: 600; color: #495057; font-size: 12px; text-transform: uppercase; margin-bottom: 4px; }
        .tbl { width: 100%; border-collapse: collapse; margin-top: 15px; }
        .tbl th, .tbl td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #e9ecef; font-size: 14px; }
        .tbl th { background: #f8f9fa; font-weight: 600; font-size: 12px; text-transform: uppercase; }
        .footer { text-align: center; padding: 40px; color: #888; font-size: 12px; }
        @media print { .container { padding: 15px; } .section { box-shadow: none; border: 1px solid #ddd; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Scan Report</h1>
            <div class="subtitle">{{ project_name }} - {{ target_url }}</div>
            <div class="meta">
                <span>Scan ID: {{ scan_id }}</span>
                <span>Status: {{ scan_status }}</span>
                <span>Generated: {{ generated_at }}</span>
            </div>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <div class="metrics">
                <div class="metric critical"><div class="value">{{ summary.critical }}</div><div class="label">Critical</div></div>
                <div class="metric high"><div class="value">{{ summary.high }}</div><div class="label">High</div></div>
                <div class="metric medium"><div class="value">{{ summary.medium }}</div><div class="label">Medium</div></div>
                <div class="metric low"><div class="value">{{ summary.low }}</div><div class="label">Low</div></div>
                <div class="metric info"><div class="value">{{ summary.info }}</div><div class="label">Info</div></div>
                <div class="metric total"><div class="value">{{ summary.total }}</div><div class="label">Total</div></div>
            </div>
            <div class="chart-bar">
                {% if summary.total > 0 %}
                <div class="seg critical" style="width:{{ (summary.critical / summary.total * 100)|round(1) }}%"></div>
                <div class="seg high" style="width:{{ (summary.high / summary.total * 100)|round(1) }}%"></div>
                <div class="seg medium" style="width:{{ (summary.medium / summary.total * 100)|round(1) }}%"></div>
                <div class="seg low" style="width:{{ (summary.low / summary.total * 100)|round(1) }}%"></div>
                <div class="seg info" style="width:{{ (summary.info / summary.total * 100)|round(1) }}%"></div>
                {% endif %}
            </div>
            <div class="legend">
                <div class="legend-item"><div class="legend-dot" style="background:#c0392b"></div>Critical</div>
                <div class="legend-item"><div class="legend-dot" style="background:#e67e22"></div>High</div>
                <div class="legend-item"><div class="legend-dot" style="background:#f39c12"></div>Medium</div>
                <div class="legend-item"><div class="legend-dot" style="background:#27ae60"></div>Low</div>
                <div class="legend-item"><div class="legend-dot" style="background:#2980b9"></div>Info</div>
            </div>
        </div>

        {% if owasp_breakdown %}
        <div class="section">
            <h2>OWASP Top 10</h2>
            <table class="tbl">
                <thead><tr><th>Category</th><th>Count</th><th>Findings</th></tr></thead>
                <tbody>
                    {% for cat, data in owasp_breakdown.items() %}
                    <tr><td><strong>{{ cat }}</strong></td><td>{{ data.count }}</td><td>{{ data.titles|join(', ') }}</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        {% if cwe_breakdown %}
        <div class="section">
            <h2>CWE Breakdown</h2>
            <table class="tbl">
                <thead><tr><th>CWE</th><th>Count</th><th>Max Severity</th></tr></thead>
                <tbody>
                    {% for cwe_id, data in cwe_breakdown.items() %}
                    <tr><td><strong>{{ cwe_id }}</strong></td><td>{{ data.count }}</td><td>{{ data.max_severity }}</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <div class="section">
            <h2>Findings ({{ findings|length }})</h2>
            {% for f in findings %}
            <div class="finding {{ f.severity|lower }}">
                <div class="finding-header">
                    <h4>{{ f.title }}</h4>
                    <div class="badges">
                        <span class="badge sev">{{ f.severity }}</span>
                        <span class="badge tool">{{ f.scanner }}</span>
                        {% if f.cwe %}<span class="badge cwe">{{ f.cwe }}</span>{% endif %}
                        <span class="badge status">{{ f.status }}</span>
                    </div>
                </div>
                <p>{{ f.description or 'No description.' }}</p>
                {% if f.url %}<p><strong>Endpoint:</strong> {{ f.url }}</p>{% endif %}
                {% if f.evidence %}
                <div class="label-sm">Evidence</div>
                <pre>{{ f.evidence[:500] }}{% if f.evidence|length > 500 %}...{% endif %}</pre>
                {% endif %}
                {% if f.remediation %}
                <div class="label-sm">Remediation</div>
                <pre>{{ f.remediation[:500] }}{% if f.remediation|length > 500 %}...{% endif %}</pre>
                {% endif %}
                {% if f.ai_summary %}
                <div class="label-sm">AI Analysis</div>
                <p>{{ f.ai_summary }}</p>
                {% endif %}
            </div>
            {% endfor %}
        </div>

        <div class="footer">
            <p>Generated by AI Security Orchestrator</p>
            <p>{{ generated_at }}</p>
        </div>
    </div>
</body>
</html>"""
