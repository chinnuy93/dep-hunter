from __future__ import annotations

import html

from dephunter.core.models import Confidence
from dephunter.core.util import format_duration
from dephunter.reporting.base import ReportContext, display_ref_location

_ORDER = [
    Confidence.CONFIRMED,
    Confidence.HIGH_CONFIDENCE,
    Confidence.CANDIDATE,
    Confidence.INSUFFICIENT_EVIDENCE,
]

_CSS = """
:root { color-scheme: light dark; --ink: #17202e; --muted: #667085; --line: #d8deea;
        --panel: #ffffff; --page: #f5f7fc; }
@media (prefers-color-scheme: dark) {
  :root { --ink: #e8eefc; --muted: #9aa8c2; --line: #2d3a57; --panel: #111a2e; --page: #070d1c; }
}
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       max-width: 1120px; margin: 0 auto; padding: 2rem 1rem 4rem; line-height: 1.55;
       color: var(--ink); background: var(--page); }
h1, h2, h3 { line-height: 1.25; }
a { color: #0891b2; }
.hero { background: linear-gradient(135deg, #0e7490 0%, #4f46e5 55%, #7c3aed 100%);
        color: #f8fbff; border-radius: 1rem; padding: 1.5rem 1.6rem 1.3rem;
        box-shadow: 0 18px 40px #0f172a33; }
.eyebrow { font-size: 0.72rem; letter-spacing: 0.16em; text-transform: uppercase;
           opacity: 0.8; font-weight: 700; }
.hero h1 { margin: 0.35rem 0 0.2rem; font-size: clamp(1.55rem, 4vw, 2.4rem); }
.program { margin: 0; font-size: 1.05rem; opacity: 0.95; }
.tagline { margin: 0.2rem 0 1rem; opacity: 0.8; }
.hero-meta { display: flex; flex-wrap: wrap; gap: 0.45rem 1rem; font-size: 0.85rem;
             align-items: center; }
.pill { background: #ffffff1f; border: 1px solid #ffffff33; border-radius: 999px;
        padding: 0.16rem 0.6rem; font-weight: 600; }
.progress { height: 0.55rem; background: #ffffff2e; border-radius: 999px; overflow: hidden;
            margin-top: 1rem; }
.progress > span { display: block; height: 100%; background: #a7f3d0; border-radius: inherit; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
         gap: 0.75rem; margin: 1rem 0 1.25rem; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 0.75rem;
        padding: 0.85rem 1rem; }
.card .num { display: block; font-size: 1.45rem; font-weight: 800; letter-spacing: -0.02em; }
.card .label { color: var(--muted); font-size: 0.82rem; text-transform: uppercase;
               letter-spacing: 0.06em; }
table { border-collapse: collapse; width: 100%; margin: 0.75rem 0 1.25rem;
        background: var(--panel); border-radius: 0.6rem; overflow: hidden; }
th, td { border: 1px solid var(--line); padding: 0.4rem 0.55rem; text-align: left;
         vertical-align: top; word-break: break-word; }
th { background: #8882; }
code { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
.badge { display: inline-block; padding: 0.1rem 0.45rem; border-radius: 0.35rem;
         border: 1px solid #8886; font-size: 0.85em; font-weight: 600; }
.CONFIRMED { background: #b91c1c22; }
.HIGH_CONFIDENCE { background: #c2410c22; }
.CANDIDATE { background: #a1620722; }
.INSUFFICIENT_EVIDENCE { background: #52525222; }
.finding { border-left: 4px solid #8886; padding-left: 1rem; margin: 2rem 0; }
.muted { color: var(--muted); }
ul.meta { list-style: none; padding: 0; display: flex; flex-wrap: wrap; gap: 0.4rem 1.2rem;
          font-size: 0.9rem; }
blockquote { border-left: 3px solid #8886; margin-left: 0; padding-left: 1rem; }
"""


def e(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def render(context: ReportContext) -> str:
    counts = context.confidence_counts()
    parts: list[str] = []
    add = parts.append
    add("<!doctype html>")
    add('<html lang="en"><head><meta charset="utf-8">')
    add('<meta name="viewport" content="width=device-width, initial-scale=1">')
    add(f"<title>Dep-Hunter report — {e(context.program)}</title>")
    add(f"<style>{_CSS}</style></head><body>")
    add('<header class="hero">')
    add('<div class="eyebrow">Dep-Hunter · authorized scope · static evidence</div>')
    add("<h1>Dependency confusion report</h1>")
    add(f'<p class="program">{e(context.program)}</p>')
    add('<p class="tagline">Passive discovery · GET/HEAD only · no exploitation</p>')
    add('<div class="hero-meta">')
    add(f'<span class="pill">Scan #{context.scan_id}</span>')
    add(f'<span class="pill">{e(context.scan.get("status"))}</span>')
    add(f'<span class="pill">{e(context.progress_percent)}% complete</span>')
    if context.runtime:
        add(f'<span class="pill">{e(format_duration(context.runtime.get("duration_seconds")))} runtime</span>')
    add("</div>")
    add(f'<div class="progress"><span style="width:{context.progress_percent}%"></span></div>')
    add("</header>")

    add('<ul class="meta">')
    add(f"<li><strong>Phase:</strong> {e(context.scan.get('phase'))}</li>")
    add(f"<li><strong>Generated:</strong> {e(context.generated_at)}</li>")
    add(f"<li><strong>Tool version:</strong> {e(context.tool_version)}</li>")
    if context.runtime:
        add(f"<li><strong>Run time:</strong> {e(format_duration(context.runtime.get('duration_seconds')))}</li>")
        add(f"<li><strong>Progress:</strong> {context.progress_percent}%</li>")
    authorization = (context.scan.get("scope") or {}).get("authorization")
    if authorization:
        add(f"<li><strong>Authorization basis:</strong> {e(authorization)}</li>")
    add("</ul>")

    add("<h2>Summary</h2>")
    add('<div class="cards">')
    cards = [
        (len(context.findings), "Findings"),
        (context.stats.get("dependencies", 0), "Dependencies"),
        ((context.stats.get("registry_checks") or {}).get("total", 0), "Registry checks"),
        (f"{context.progress_percent}%", "Scan progress"),
    ]
    for number, label in cards:
        add(f'<div class="card"><span class="num">{e(number)}</span><span class="label">{e(label)}</span></div>')
    add("</div>")
    add("<table><thead><tr><th>Class</th><th>Findings</th></tr></thead><tbody>")
    for confidence in _ORDER:
        add(f"<tr><td>{confidence.value}</td><td>{counts.get(confidence.value, 0)}</td></tr>")
    add(f"<tr><td><strong>Total</strong></td><td><strong>{len(context.findings)}</strong></td></tr>")
    add("</tbody></table>")
    add(
        f"<p>Dependencies parsed: <strong>{e(context.stats.get('dependencies', 0))}</strong>. "
        f"Registry checks: <strong>{e((context.stats.get('registry_checks') or {}).get('total', 0))}</strong>.</p>"
    )

    if context.runtime:
        add("<h2>Execution</h2>")
        add("<table><thead><tr><th>Phase</th><th>Seconds</th></tr></thead><tbody>")
        for phase, seconds in context.phase_seconds.items():
            add(f"<tr><td>{e(phase)}</td><td>{seconds:.2f}</td></tr>")
        add("</tbody></table>")

    scope = context.scan.get("scope") or {}
    add("<h2>Scope</h2><ul>")
    web = scope.get("web") or []
    add(f"<li>Web targets: {e(', '.join(str(item.get('url')) for item in web) or 'none')}</li>")
    github = scope.get("github") or {}
    add(f"<li>GitHub orgs: {e(github.get('orgs') or [])}; repos: {e(github.get('repos') or [])}</li>")
    gitlab = scope.get("gitlab") or {}
    add(f"<li>GitLab projects: {e(gitlab.get('projects') or [])}</li>")
    registries = scope.get("registries") or {}
    add(f"<li>Registries: {e(', '.join(registries.get('enabled') or []))}</li>")
    add("</ul>")

    add("<h2>Method</h2>")
    add(
        "<p>Passive collection only: public web assets and public repository contents were fetched with "
        "GET/HEAD; manifests, lockfiles, JavaScript, source maps, and CI configuration were parsed as data. "
        "Public registry metadata was queried with authoritative 200/404 semantics. No package was published, "
        "installed, reserved, or executed; no callback or credential collection was performed.</p>"
    )

    add("<h2>Findings</h2>")
    if not context.findings:
        add("<p>No findings met the configured minimum classification.</p>")
    for index, finding in enumerate(context.sorted_findings(), 1):
        _render_finding(parts, index, finding, context)

    add("<h2>Limitations</h2><ul>")
    add("<li>Static evidence cannot prove that a target's build or install path selects an attacker-controlled package.</li>")
    add("<li>Target-side confirmation requires separate written authorization and an isolated environment.</li>")
    add("<li>Registry absence can change; statuses are point-in-time.</li>")
    add("<li>Publisher and repository metadata are self-reported by package maintainers.</li>")
    add("</ul>")
    add("<p class=\"muted\">Generated by Dep-Hunter. Findings are static indicators, not proof of compromise.</p>")
    add("</body></html>")
    return "\n".join(parts)


def _render_finding(parts: list[str], index: int, finding: dict, context: ReportContext) -> None:
    classification = str(finding.get("classification"))
    add = parts.append
    add(f'<section class="finding">')
    add(
        f"<h3>{index}. <span class=\"badge {e(classification)}\">{e(classification)}</span> "
        f"{e(finding.get('title') or finding.get('name'))}</h3>"
    )
    add("<ul>")
    add(
        f"<li><strong>Ecosystem:</strong> {e(finding.get('ecosystem'))} &middot; "
        f"<strong>Package:</strong> <code>{e(finding.get('name'))}</code> &middot; "
        f"<strong>Score:</strong> {e(finding.get('score'))} &middot; "
        f"<strong>CWE:</strong> {e(finding.get('cwe_primary'))} / {e(finding.get('cwe_secondary'))}</li>"
    )
    evidence = finding.get("evidence") or {}
    registry = evidence.get("registry") or {}
    add(
        f"<li><strong>Registry:</strong> {e(registry.get('status'))} "
        f"(HTTP {e(registry.get('http_status') if registry.get('http_status') is not None else 'n/a')}) &middot; "
        f"latest={e(registry.get('latest_version') or 'unknown')} &middot; "
        f"publisher={e(registry.get('publisher') or 'not exposed')}</li>"
    )
    resolution = finding.get("resolution") or {}
    add(
        f"<li><strong>Routing:</strong> public={e(resolution.get('public_routing'))} &middot; "
        f"private={e(resolution.get('private_routing'))} &middot; "
        f"public evidence={e(bool(resolution.get('public_resolution_evidence')))} &middot; "
        f"mixed provenance={e(bool(resolution.get('mixed_provenance')))}</li>"
    )
    add("</ul>")

    add("<h4>Why it was flagged</h4><ul>")
    for reason in finding.get("reasons") or []:
        add(f"<li>{e(reason)}</li>")
    if not finding.get("reasons"):
        add("<li>No reasons recorded.</li>")
    add("</ul>")

    refs = evidence.get("refs") or []
    if refs:
        add("<h4>Evidence locations</h4><table><thead><tr><th>Source</th><th>Location</th>")
        add("<th>Version</th><th>Resolved URL</th></tr></thead><tbody>")
        for ref in refs[:25]:
            add(
                f"<tr><td>{e(ref.get('source_kind'))}</td>"
                f"<td>{e(display_ref_location(ref))}</td>"
                f"<td>{e(ref.get('version_constraint') or '')}</td>"
                f"<td>{e(ref.get('resolved_url') or '')}</td></tr>"
            )
        add("</tbody></table>")
        if len(refs) > 25:
            add(f"<p class=\"muted\">{len(refs) - 25} additional occurrence(s) omitted.</p>")

    facts = evidence.get("facts") or []
    if facts:
        add("<h4>Registry configuration evidence</h4><table><thead><tr><th>Fact</th><th>Value</th>")
        add("<th>Location</th></tr></thead><tbody>")
        for fact in facts[:20]:
            location = fact.get("file_path") or fact.get("source_url") or ""
            if fact.get("line"):
                location = f"{location}:{fact['line']}"
            add(
                f"<tr><td>{e(fact.get('fact_type'))}</td><td>{e(fact.get('value'))}</td>"
                f"<td>{e(location)}</td></tr>"
            )
        add("</tbody></table>")

    missing = finding.get("missing") or []
    if missing:
        add("<h4>Missing evidence / required confirmation</h4><ul>")
        for item in missing:
            add(f"<li>{e(item)}</li>")
        add("</ul>")

    verification = context.verification_for(finding)
    if verification:
        add(f"<h4>Static verification: {e(verification.verdict)}</h4><ul>")
        for check in verification.checks:
            add(f"<li><strong>{e(check.status)}</strong>: {e(check.name)} — {e(check.detail)}</li>")
        add("</ul>")
        add(f"<blockquote>{e(verification.allowed_claim)}</blockquote>")
    add("</section>")
