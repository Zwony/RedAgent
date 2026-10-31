"""HTML audit report renderer.

Generates standalone, air-gapped single-file HTML reports presenting
security posture evaluations, vulnerability traces, and remediation roadmaps.
"""
import html
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redagent.schemas.report import AuditReport


def render_html_report(report: "AuditReport") -> str:
    """Renders an AuditReport model as an interactive HTML document.

    Args:
        report: Evaluated security audit report containing posture metrics,
            vulnerability findings, and mitigation recommendations.

    Returns:
        str: Self-contained HTML markup string with embedded CSS styling.
    """
    
    # Rating color mappings
    rating_colors = {
        "SECURE": ("#10b981", "rgba(16, 185, 129, 0.15)"),
        "LOW_RISK": ("#3b82f6", "rgba(59, 130, 246, 0.15)"),
        "MEDIUM_RISK": ("#f59e0b", "rgba(245, 158, 11, 0.15)"),
        "HIGH_RISK": ("#f97316", "rgba(249, 115, 22, 0.15)"),
        "CRITICAL_RISK": ("#ef4444", "rgba(239, 68, 68, 0.15)"),
    }
    
    accent_color, accent_bg = rating_colors.get(
        report.overall_rating.value,
        ("#ef4444", "rgba(239, 68, 68, 0.15)")
    )

    # Format findings rows
    findings_html = []
    for f in report.findings:
        is_vuln = f.status.value == "confirmed_vuln"
        badge_color = "#ef4444" if is_vuln else "#10b981"
        badge_bg = "rgba(239, 68, 68, 0.15)" if is_vuln else "rgba(16, 185, 129, 0.15)"
        
        repro_snippet = ""
        if f.reproduction_prompt:
            escaped_prompt = html.escape(f.reproduction_prompt)
            repro_snippet = f"""
            <div class="code-box">
                <div class="code-header">Reproduction Payload:</div>
                <pre><code>{escaped_prompt}</code></pre>
            </div>
            """
        
        resp_snippet = ""
        if f.observed_output:
            escaped_resp = html.escape(f.observed_output)
            resp_snippet = f"""
            <div class="code-box">
                <div class="code-header">Observed Output:</div>
                <pre><code>{escaped_resp}</code></pre>
            </div>
            """

        remediation_html = ""
        if f.remediation_suggestion:
            rule_html = ""
            if f.suggested_guardrail_rule:
                rule_html = f"<div style='margin-top: 0.5rem; font-family: monospace; font-size: 0.8rem; color: #a5f3fc;'>Rule: {html.escape(f.suggested_guardrail_rule)}</div>"
            remediation_html = f"""
            <div class="remediation-box">
                <strong>Remediation:</strong> {html.escape(f.remediation_suggestion)}
                {rule_html}
            </div>
            """

        card = f"""
        <div class="card finding-card">
            <div class="finding-top">
                <div>
                    <span class="badge" style="color: {badge_color}; background: {badge_bg}; border-color: {badge_color};">
                        {html.escape(f.status.value.upper())}
                    </span>
                    <span class="badge badge-outline">{html.escape(f.severity.value.upper())}</span>
                    <span class="category-tag">{html.escape(f.category.value)}</span>
                </div>
                <span class="finding-id">#{html.escape(f.finding_id)}</span>
            </div>
            <h3 class="finding-title">{html.escape(f.title)}</h3>
            <p class="finding-desc">{html.escape(f.description)}</p>
            {repro_snippet}
            {resp_snippet}
            {remediation_html}
        </div>
        """
        findings_html.append(card)

    # Format remediation roadmap
    roadmap_html = []
    for item in report.remediation_roadmap:
        example_box = ""
        if item.example_mitigation:
            example_box = f"""
            <div class="code-box">
                <div class="code-header">Example Mitigation:</div>
                <pre><code>{html.escape(item.example_mitigation)}</code></pre>
            </div>
            """
        
        prio_color = "#ef4444" if item.priority == 1 else "#f97316" if item.priority == 2 else "#3b82f6"
        prio_bg = "rgba(239, 68, 68, 0.15)" if item.priority == 1 else "rgba(249, 115, 22, 0.15)" if item.priority == 2 else "rgba(59, 130, 246, 0.15)"

        r_card = f"""
        <div class="card roadmap-card">
            <div class="finding-top">
                <span class="badge" style="color: {prio_color}; background: {prio_bg}; border-color: {prio_color};">
                    PRIORITY {item.priority}
                </span>
                <span class="category-tag">{html.escape(item.target_component)}</span>
            </div>
            <p class="roadmap-rec">{html.escape(item.recommendation)}</p>
            {example_box}
        </div>
        """
        roadmap_html.append(r_card)

    date_str = report.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RedAgent Audit Report: {html.escape(report.target_name)}</title>
    <style>
        :root {{
            --bg: #090d16;
            --surface: #111827;
            --surface-hover: #1f2937;
            --border: #1f2937;
            --border-highlight: #374151;
            --text-main: #f9fafb;
            --text-muted: #9ca3af;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --info: #3b82f6;
            --accent: {accent_color};
            --accent-bg: {accent_bg};
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }}
        body {{
            background-color: var(--bg);
            color: var(--text-main);
            padding: 2.5rem 1.5rem;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 1.5rem;
            padding-bottom: 2rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 2rem;
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        .brand-title {{
            font-size: 1.75rem;
            font-weight: 800;
            letter-spacing: -0.025em;
            color: #ffffff;
        }}
        .brand-tag {{
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--danger);
            background: rgba(239, 68, 68, 0.15);
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }}
        .meta-list {{
            font-size: 0.875rem;
            color: var(--text-muted);
            text-align: right;
        }}
        .meta-list strong {{
            color: var(--text-main);
        }}
        .grid-metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.25rem;
            margin-bottom: 2.5rem;
        }}
        .card {{
            background-color: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
        }}
        .metric-label {{
            font-size: 0.8125rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 0.5rem;
        }}
        .metric-value {{
            font-size: 1.875rem;
            font-weight: 800;
            color: var(--text-main);
        }}
        .badge {{
            display: inline-flex;
            align-items: center;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.05em;
            padding: 0.25rem 0.6rem;
            border-radius: 4px;
            border: 1px solid transparent;
        }}
        .badge-outline {{
            color: var(--text-muted);
            border-color: var(--border-highlight);
            background: rgba(255, 255, 255, 0.05);
        }}
        .category-tag {{
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-left: 0.5rem;
        }}
        .section-title {{
            font-size: 1.35rem;
            font-weight: 700;
            margin-bottom: 1.25rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .section-container {{
            margin-bottom: 3rem;
        }}
        .finding-card {{
            margin-bottom: 1rem;
            border-left: 4px solid var(--border-highlight);
        }}
        .finding-top {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.75rem;
        }}
        .finding-id {{
            font-family: monospace;
            font-size: 0.8rem;
            color: var(--text-muted);
        }}
        .finding-title {{
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: #ffffff;
        }}
        .finding-desc {{
            font-size: 0.925rem;
            color: var(--text-muted);
            margin-bottom: 1rem;
        }}
        .code-box {{
            background: #05080f;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 0.75rem 1rem;
            margin-top: 0.75rem;
            overflow-x: auto;
        }}
        .code-header {{
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 0.4rem;
        }}
        pre code {{
            font-family: "JetBrains Mono", Consolas, "Courier New", monospace;
            font-size: 0.85rem;
            color: #38bdf8;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .remediation-box {{
            margin-top: 0.75rem;
            padding: 0.75rem 1rem;
            border-radius: 6px;
            background: rgba(59, 130, 246, 0.08);
            border: 1px solid rgba(59, 130, 246, 0.25);
            font-size: 0.9rem;
            color: #93c5fd;
        }}
        .roadmap-card {{
            margin-bottom: 1rem;
        }}
        .roadmap-rec {{
            font-size: 0.95rem;
            color: var(--text-main);
            margin-top: 0.5rem;
        }}
        .footer {{
            text-align: center;
            padding-top: 2rem;
            border-top: 1px solid var(--border);
            font-size: 0.8125rem;
            color: var(--text-muted);
        }}
        @media print {{
            body {{
                background-color: #ffffff;
                color: #000000;
                padding: 0;
            }}
            .card {{
                border-color: #e5e7eb;
                background: #ffffff;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div>
                <div class="brand">
                    <h1 class="brand-title">RedAgent</h1>
                    <span class="brand-tag">Security Audit</span>
                </div>
                <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 0.25rem;">
                    Target: <strong style="color: var(--text-main);">{html.escape(report.target_name)}</strong> ({html.escape(report.target_id)})
                </p>
            </div>
            <div class="meta-list">
                <div>Report ID: <strong>{html.escape(report.report_id)}</strong></div>
                <div>Audit Date: <strong>{date_str}</strong></div>
                <div>Duration: <strong>{report.audit_duration_seconds:.2f}s</strong></div>
            </div>
        </header>

        <section class="grid-metrics">
            <div class="card">
                <div class="metric-label">Overall Posture</div>
                <div class="metric-value" style="color: {accent_color}; font-size: 1.5rem;">
                    {html.escape(report.overall_rating.value)}
                </div>
            </div>
            <div class="card">
                <div class="metric-label">Max Risk Score</div>
                <div class="metric-value" style="color: {accent_color};">
                    {report.overall_risk_score:.1f} <span style="font-size: 1rem; color: var(--text-muted);">/ 10</span>
                </div>
            </div>
            <div class="card">
                <div class="metric-label">Tests Executed</div>
                <div class="metric-value">{report.total_tests_executed}</div>
            </div>
            <div class="card">
                <div class="metric-label">Vulnerabilities Detected</div>
                <div class="metric-value" style="color: {'#ef4444' if report.vulnerabilities_found > 0 else '#10b981'};">
                    {report.vulnerabilities_found}
                </div>
            </div>
        </section>

        <section class="section-container">
            <h2 class="section-title">Vulnerability Findings & Evaluator Analysis</h2>
            {''.join(findings_html) if findings_html else '<p style="color: var(--text-muted);">No findings recorded.</p>'}
        </section>

        <section class="section-container">
            <h2 class="section-title">Remediation Roadmap</h2>
            {''.join(roadmap_html) if roadmap_html else '<p style="color: var(--text-muted);">No remediation actions required.</p>'}
        </section>

        <footer class="footer">
            Generated autonomously by RedAgent AI Security Platform &bull; OWASP Top 10 for LLM Standards
        </footer>
    </div>
</body>
</html>
"""
    return doc
