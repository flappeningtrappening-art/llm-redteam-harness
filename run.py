#!/usr/bin/env python3
"""CLI entry point for the LLM red team harness.

    python3 run.py --list                      # show the catalog, no calls
    python3 run.py --all --repeat 3            # run everything
    python3 run.py --suite tool_abuse          # one attack class
    python3 run.py --all --json base.json --report report.md
    python3 run.py --all --compare base.json   # regression diff

Target selection, in precedence order:
    1. --config target.json
    2. REDTEAM_BASE_URL / REDTEAM_API_KEY / REDTEAM_MODEL
    3. OLLAMA_HOST, if set
    4. OPENAI_API_KEY, if set
Any OpenAI-compatible endpoint works: OpenAI, Gemini's compatibility layer,
OpenRouter, Groq, Together, vLLM, llama.cpp.

Authorised targets only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from redteam import (  # noqa: E402
    Config, LLMClient, Runner, build_catalog, compare, select_catalog,
    terminal_summary, to_json, to_markdown, CLASSES,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run.py",
        description="LLM red team harness (authorised testing only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config", help="JSON file with target settings")
    parser.add_argument("--base-url", help="OpenAI-compatible base URL")
    parser.add_argument("--api-key", help="API key (or set REDTEAM_API_KEY)")
    parser.add_argument("--model", help="model id")

    parser.add_argument("--suite", action="append", default=[],
                        help="attack class to run; repeatable or comma-separated")
    parser.add_argument("--all", action="store_true", help="run every class")
    parser.add_argument("--probe", action="append", default=[],
                        help="probe id to run; repeatable or comma-separated. "
                             "Implies nothing else: use it to re-test just the "
                             "probes that fired, cheaply.")
    parser.add_argument("--list", action="store_true",
                        help="print the probe catalog and exit")
    parser.add_argument("--repeat", type=int, default=3,
                        help="samples per probe (default 3)")
    parser.add_argument("--max-runs", type=int, default=120,
                        help="hard cap on API calls (default 120)")
    parser.add_argument("--workers", type=int, default=4,
                        help="parallel probes; keep at 1 when the target "
                             "serialises requests (e.g. OLLAMA_NUM_PARALLEL=1)")
    parser.add_argument("--timeout", type=float, default=60.0,
                        help="per-request timeout in seconds (default 60). "
                             "Raise it for slow CPU-local models.")

    parser.add_argument("--json", dest="json_out", help="write raw results here")
    parser.add_argument("--report", help="write markdown report here")
    parser.add_argument("--save-baseline", help="save results as a baseline")
    parser.add_argument("--compare", help="diff against a previous results file")
    parser.add_argument("--dry-run", action="store_true",
                        help="resolve the target and exit without calling it")
    parser.add_argument("-q", "--quiet", action="store_true")
    return parser


def load_config(args) -> Config:
    if args.config:
        cfg = Config.from_file(args.config)
    else:
        cfg = Config()
    for attr in ("base_url", "api_key", "model"):
        value = getattr(args, attr)
        if value:
            setattr(cfg, attr, value)
    if args.workers:
        cfg.workers = args.workers
    if args.timeout:
        cfg.timeout = args.timeout
    cfg.base_url = cfg.base_url.rstrip("/")
    return cfg


def selected_classes(args) -> list:
    if args.all or not args.suite:
        return list(CLASSES)
    names = []
    for item in args.suite:
        names.extend(part.strip() for part in item.split(",") if part.strip())
    unknown = [n for n in names if n not in CLASSES]
    if unknown:
        raise SystemExit(
            "unknown suite(s): %s\navailable: %s" % (", ".join(unknown), ", ".join(CLASSES))
        )
    return list(dict.fromkeys(names))


def select_probes(cfg, classes, only):
    return select_catalog(cfg, classes, only)


_KNOWN_PROBE_IDS = None


def _known_probe(probe_id: str) -> bool:
    global _KNOWN_PROBE_IDS
    if _KNOWN_PROBE_IDS is None:
        _KNOWN_PROBE_IDS = {p.id for p in build_catalog(Config())}
    return probe_id in _KNOWN_PROBE_IDS


def selected_probe_ids(args) -> list:
    names = []
    for item in args.probe:
        names.extend(part.strip() for part in item.split(",") if part.strip())
    unknown = [n for n in names if not _known_probe(n)]
    if unknown:
        raise SystemExit(
            "unknown probe id(s): %s\nrun with --list to see the catalog"
            % ", ".join(unknown)
        )
    return list(dict.fromkeys(names))


def print_catalog(cfg: Config, classes, only=None) -> None:
    catalog = select_probes(cfg, classes, only)
    width = max(len(p.id) for p in catalog) if catalog else 6
    print("target: %s  model: %s\n" % (cfg.base_url, cfg.model or "<auto>"))
    current = None
    for probe in catalog:
        if probe.cls != current:
            current = probe.cls
            print("-- %s" % current)
        print("   %-*s  %-26s  %-8s  %s" % (
            width, probe.id, probe.name, probe.severity, probe.kind))
    print("\n%d probe(s) in %d class(es)." % (len(catalog), len(classes)))


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        cfg = load_config(args)
    except (OSError, ValueError) as exc:
        print("config error: %s" % exc, file=sys.stderr)
        return 2

    classes = selected_classes(args)
    only = selected_probe_ids(args)

    if args.list:
        print_catalog(cfg, classes, only)
        return 0

    client = LLMClient(cfg.base_url, cfg.api_key, cfg.model, timeout=cfg.timeout)
    try:
        client.resolve_model()
    except RuntimeError as exc:
        print("cannot resolve a model: %s" % exc, file=sys.stderr)
        return 2

    if args.dry_run:
        print("target ok: %s (%s)" % (client.model, cfg.base_url))
        catalog = select_probes(cfg, classes, only)
        planned = sum(
            min(args.repeat, 2 if p.kind == "baseline" else args.repeat)
            for p in catalog if p.kind != "manual"
        )
        print("%d probe(s) selected, ~%d API call(s) planned (cap %d)"
              % (len(catalog), planned, args.max_runs))
        return 0

    def on_event(kind, msg):
        if not args.quiet:
            print(msg, file=sys.stderr)

    runner = Runner(cfg, repeat=args.repeat, classes=classes,
                    max_runs=args.max_runs, on_event=on_event, only=only or None)
    report = runner.run(client)

    diff = None
    if args.compare:
        try:
            with open(args.compare, "r", encoding="utf-8") as fh:
                diff = compare(json.load(fh), report.to_dict())
        except (OSError, ValueError) as exc:
            print("cannot compare against %s: %s" % (args.compare, exc), file=sys.stderr)
            return 2

    print()
    print(terminal_summary(report))

    if diff:
        print("== Regression vs %s" % args.compare)
        if diff["regressions"]:
            for entry in diff["regressions"]:
                print("   REGRESSED %-8s %-26s %d%% -> %d%%" % (
                    entry["id"], entry["name"], round(entry["previous"] * 100),
                    round(entry["current"] * 100)))
        else:
            print("   no regressions")
        if diff["fixes"]:
            print("   fixed: %s" % ", ".join(
                "%s %d%%->%d%%" % (e["id"], round(e["previous"] * 100), round(e["current"] * 100))
                for e in diff["fixes"]))
        if diff["new_findings"]:
            print("   newly firing: %s" % ", ".join(
                "%s (%d%%)" % (e["id"], round(e["success_rate"] * 100))
                for e in diff["new_findings"]))
        print()

    payload = report.to_dict()
    if diff:
        payload["diff"] = diff

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(to_json(report))
        print("wrote %s" % args.json_out)
    if args.save_baseline:
        with open(args.save_baseline, "w", encoding="utf-8") as fh:
            fh.write(to_json(report))
        print("wrote baseline %s" % args.save_baseline)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(to_markdown(report, diff))
        print("wrote %s" % args.report)

    return 0


if __name__ == "__main__":
    sys.exit(main())