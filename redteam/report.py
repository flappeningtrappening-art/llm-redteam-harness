"""Rendering: a terminal summary for you, a markdown file for the ticket."""

from __future__ import annotations

import json

from .probes import CLASSES

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}

CLASS_TITLES = {
    "prompt_injection": "Direct prompt injection",
    "indirect_injection": "Indirect prompt injection (via retrieved content)",
    "cross_user_injection": "Cross-user / tenant injection",
    "jailbreak": "Jailbreak / guardrail bypass",
    "system_prompt_extraction": "System prompt extraction",
    "tool_abuse": "Tool and agent abuse",
    "rag_poisoning": "RAG poisoning",
    "exfiltration": "Data exfiltration",
    "availability": "Availability and cost",
    "manual": "Not automatable by this harness",
}


def to_json(report) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=False)


def terminal_summary(report, max_rows: int = 6) -> str:
    lines = []
    target = report.target
    lines.append("target : %s  (%s)" % (target.get("model"), target.get("base_url")))
    lines.append("repeat : %d per probe   duration: %.1fs" % (report.repeat, report.duration))

    hits = report.findings()
    lines.append("firing : %d probe(s) with at least one success" % len(hits))
    lines.append("")

    by_class = {}
    for result in report.results:
        by_class.setdefault(result.cls, []).append(result)

    for cls in CLASSES:
        results = by_class.get(cls)
        if not results:
            continue
        live = [r for r in results if not r.skipped]
        skipped = [r for r in results if r.skipped]
        fired = [r for r in live if r.successes > 0]
        if not live:
            lines.append("== %s : %d manual check(s) required" % (CLASS_TITLES[cls], len(skipped)))
            for r in skipped:
                lines.append("   - %s %s: %s" % (r.id, r.name, _first_sentence(r.skip_reason)))
            lines.append("")
            continue

        worst = min(fired, key=lambda r: SEVERITY_ORDER.get(r.severity, 9)) if fired else None
        lines.append("== %s" % CLASS_TITLES[cls])
        lines.append("   probes %d, fired %d%s" % (
            len(live), len(fired),
            ", worst %s" % SEVERITY_LABEL[worst.severity] if worst else "",
        ))
        for result in sorted(live, key=lambda r: (-r.success_rate, SEVERITY_ORDER.get(r.severity, 9))):
            if result.successes == 0 and cls != "jailbreak":
                continue
            label = {"critical": "C", "high": "H", "medium": "M", "low": "L", "info": "i"}[
                result.severity
            ]
            detail = ""
            if result.kind == "bypass":
                detail = "  bypass=%s (baseline %s refused=%s)" % (
                    "YES" if result.bypass else "no",
                    result.baseline_id or "jb-000",
                    "yes" if result.baseline_refused else "no",
                )
            elif result.kind == "baseline":
                detail = "  baseline refused in %d/%d" % (result.blocked, result.runs)
            elif cls == "availability":
                detail = "  %d tok, %.1fs" % (result.cost_tokens, result.mean_latency)
            lines.append("   [%s] %-8s %-26s %3d/%d  %3d%% success  %3d%% blocked%s" % (
                label, result.id, result.name, result.successes, result.runs,
                round(result.success_rate * 100), round(result.block_rate * 100), detail,
            ))
            if result.errors:
                lines.append("           ^ %d/%d calls errored: %s" % (
                    result.errors, result.runs, result.error_sample[:110]))
        lines.append("")

    return "\n".join(lines)


def _first_sentence(text: str) -> str:
    text = (text or "").strip()
    for marker in (". ", ".\n"):
        if marker in text:
            text = text.split(marker)[0]
            break
    return text.strip()[:110]


def to_markdown(report, diff: dict = None) -> str:
    out = []
    target = report.target
    out.append("# LLM Red Team Report")
    out.append("")
    out.append("| Field | Value |")
    out.append("|---|---|")
    out.append("| Target | `%s` |" % target.get("base_url"))
    out.append("| Model | `%s` |" % target.get("model"))
    out.append("| Started | %s |" % report.started_at)
    out.append("| Duration | %.1fs |" % report.duration)
    out.append("| Repeats per probe | %d |" % report.repeat)
    out.append("| Canary planted | %s |" % ("yes" if target.get("canary") else "no"))
    out.append("")
    out.append("> Authorised testing only. All probe payloads are synthetic.")
    out.append("")

    hits = report.findings()
    out.append("## Summary")
    out.append("")
    out.append("- Probes that fired: **%d**" % len(hits))
    if hits:
        worst = min(hits, key=lambda r: SEVERITY_ORDER.get(r.severity, 9))
        out.append("- Highest severity observed: **%s** (%s)" % (
            SEVERITY_LABEL[worst.severity], worst.id))
    out.append("")

    if hits:
        out.append("| Severity | Probe | Class | Success rate | Evidence |")
        out.append("|---|---|---|---|---|")
        for result in hits[:40]:
            evidence = ""
            if result.kind == "bypass":
                evidence = "bypass" if result.bypass else "complied"
            elif result.samples:
                evidence = "`%s`" % result.samples[0].replace("|", "\\|")[:90].replace("\n", " ")
            out.append("| %s | `%s` %s | %s | %d/%d (%d%%) | %s |" % (
                SEVERITY_LABEL[result.severity], result.id, result.name,
                CLASS_TITLES.get(result.cls, result.cls),
                result.successes, result.runs, round(result.success_rate * 100),
                evidence,
            ))
        out.append("")

    by_class = {}
    for result in report.results:
        by_class.setdefault(result.cls, []).append(result)

    out.append("## Full results by class")
    out.append("")
    for cls in CLASSES:
        results = by_class.get(cls)
        if not results:
            continue
        out.append("### %s" % CLASS_TITLES[cls])
        out.append("")
        out.append("| Probe | Severity | Runs | Success | Blocked | Tokens | Mean latency |")
        out.append("|---|---|---|---|---|---|---|")
        for result in sorted(results, key=lambda r: r.id):
            runs = "%d" % result.runs if result.runs else "-"
            out.append("| `%s` %s | %s | %s | %d/%d | %d/%d | %d | %.2fs |" % (
                result.id, result.name,
                "manual" if result.skipped else SEVERITY_LABEL[result.severity],
                runs,
                result.successes, result.runs or 0,
                result.blocked, result.runs or 0,
                result.cost_tokens, result.mean_latency,
            ))
        notes = [r for r in results if r.notes]
        for result in notes:
            out.append("")
            out.append("- `%s` — %s" % (result.id, result.notes))
        out.append("")

    manual = [r for r in report.results if r.skipped]
    if manual:
        out.append("## Manual follow-ups")
        out.append("")
        for result in manual:
            out.append("- **`%s` %s** (%s) — %s" % (
                result.id, result.name, CLASS_TITLES.get(result.cls, result.cls),
                result.skip_reason))
        out.append("")

    if diff:
        out.append("## Regression vs previous run")
        out.append("")
        out.extend(_diff_markdown(diff))
        out.append("")

    out.append("## Next steps")
    out.append("")
    out.append("1. Triage the critical/high rows first; a single one is enough to block a release.")
    out.append("2. Promote every confirmed probe to a permanent case: `python3 run.py --compare baseline.json`.")
    out.append("3. Re-run after every model, prompt or tool change and diff.")
    out.append("")
    return "\n".join(out)


def _diff_markdown(diff: dict) -> list:
    out = []
    if diff["regressions"]:
        out.append("**Regressions** (success rate went up)")
        out.append("")
        out.append("| Probe | Previous | Current | Delta |")
        out.append("|---|---|---|---|")
        for entry in diff["regressions"]:
            out.append("| `%s` %s | %d%% | %d%% | +%d%% |" % (
                entry["id"], entry["name"], round(entry["previous"] * 100),
                round(entry["current"] * 100), round(entry["delta"] * 100)))
        out.append("")
    else:
        out.append("No regressions against the previous run.")
        out.append("")
    if diff["fixes"]:
        out.append("**Fixed** (success rate went down)")
        out.append("")
        for entry in diff["fixes"]:
            out.append("- `%s` %s: %d%% -> %d%%" % (
                entry["id"], entry["name"], round(entry["previous"] * 100),
                round(entry["current"] * 100)))
        out.append("")
    if diff["new_findings"]:
        out.append("**Newly firing**")
        out.append("")
        for entry in diff["new_findings"]:
            out.append("- `%s` %s at %d%%" % (
                entry["id"], entry["name"], round(entry["success_rate"] * 100)))
        out.append("")
    return out