"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .errors import Error, InputError
from .report import render
from .rules import SEVERITY_RANK
from .scanner import scan_path
from .scanner import load_rules
from .version import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secscan",
        description="Análise estática de segredos, entropia e rotas de API.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Arquivo ou diretório (default: .)")
    parser.add_argument("--format", default="table", choices=["table", "json", "sarif", "csv", "markdown"])
    parser.add_argument("--rules", help="JSON com regras adicionais")
    parser.add_argument("--ignore", default="", help="Padrões extras, separados por vírgula")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"], help="Exit 1 se houver achado nessa severidade ou acima")
    parser.add_argument("--max-risk", type=float, help="Exit 1 se o impact score (0-100) passar do teto")
    parser.add_argument("--output", help="Grava o relatório neste arquivo")
    parser.add_argument("--reveal-secrets", action="store_true", help="Inclui o valor encontrado no relatório")
    parser.add_argument("--version", action="version", version=f"secscan {__version__}")
    return parser


def gate_message(report, fail_on: str | None, max_risk: float | None) -> str | None:
    """Return a quality-gate failure message, or None when the scan passes."""
    reasons = []
    if fail_on:
        threshold = SEVERITY_RANK[fail_on.upper()]
        if any(SEVERITY_RANK[finding.severity] >= threshold for finding in report.findings):
            reasons.append(f"achados com severidade >= {fail_on.upper()}")
    if max_risk is not None and report.metrics.security_impact_score > max_risk:
        reasons.append(
            f"impact score {report.metrics.security_impact_score} acima de {max_risk:g}"
        )
    if not reasons:
        return None
    return "SecScan quality gate: " + "; ".join(reasons)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        rules = load_rules(args.rules) if args.rules else None
        ignore = [item.strip() for item in args.ignore.split(",") if item.strip()]
        report = scan_path(args.path, rules=rules, ignore=ignore)
        text = render(report, args.format, reveal_secrets=args.reveal_secrets)
    except InputError as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2
    except Error as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"Relatório gravado em {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)

    failure = gate_message(report, args.fail_on, args.max_risk)
    if failure:
        print(failure, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
