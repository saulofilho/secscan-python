"""Render a scan report as table, JSON, CSV, SARIF, or Markdown."""

from __future__ import annotations

import csv
import io
import json

from .scanner import ScanReport

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def to_dict(report: ScanReport, *, reveal_secrets: bool = False) -> dict:
    """JSON-ready mapping. Secret literals stay out unless ``reveal_secrets`` is set."""
    findings = []
    for finding in report.findings:
        item = {
            "id": finding.id,
            "ruleId": finding.rule_id,
            "ruleName": finding.rule_name,
            "category": finding.category,
            "severity": finding.severity,
            "file": finding.file,
            "line": finding.line,
            "column": finding.column,
            "snippet": finding.public_snippet(reveal_secrets),
            "maskedSecret": finding.masked_secret,
            "entropy": finding.entropy,
            "description": finding.description,
            "remediation": finding.remediation,
            "fileCriticality": finding.file_criticality,
            "fileCriticalityWeight": finding.file_criticality_weight,
            "weightedScore": finding.weighted_score,
        }
        if reveal_secrets:
            item["matchedSecret"] = finding.matched_secret
        findings.append(item)

    metrics = report.metrics
    return {
        "scanner": report.scanner,
        "version": report.version,
        "timestamp": report.timestamp,
        "target": report.target,
        "totalFiles": report.total_files,
        "scannedFilesCount": report.scanned_files_count,
        "ignoredFilesCount": report.ignored_files_count,
        "findings": findings,
        "apiEndpoints": [
            {
                "id": endpoint.id,
                "file": endpoint.file,
                "line": endpoint.line,
                "method": endpoint.method,
                "path": endpoint.path,
                "isInternalOrAdmin": endpoint.is_internal_or_admin,
                "snippet": endpoint.snippet,
            }
            for endpoint in report.api_endpoints
        ],
        "metrics": {
            "criticalCount": metrics.critical_count,
            "highCount": metrics.high_count,
            "mediumCount": metrics.medium_count,
            "lowCount": metrics.low_count,
            "infoCount": metrics.info_count,
            "securityScore": metrics.security_score,
            "securityImpactScore": metrics.security_impact_score,
            "impactLevel": metrics.impact_level,
            "totalWeightedRisk": metrics.total_weighted_risk,
            "averageEntropy": metrics.average_entropy,
        },
        "durationMs": report.duration_ms,
    }


def to_json(report: ScanReport, *, reveal_secrets: bool = False) -> str:
    return json.dumps(to_dict(report, reveal_secrets=reveal_secrets), indent=2, ensure_ascii=False)


def to_csv(report: ScanReport, *, reveal_secrets: bool = False) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["ID", "Severity", "Rule Name", "Category", "File", "Line", "Column", "Entropy", "Masked Secret", "Remediation"]
    )
    for finding in report.findings:
        writer.writerow(
            [
                finding.id,
                finding.severity,
                finding.rule_name,
                finding.category,
                finding.file,
                finding.line,
                finding.column,
                finding.entropy,
                finding.matched_secret if reveal_secrets else finding.masked_secret,
                finding.remediation,
            ]
        )
    return buffer.getvalue()


def to_sarif(report: ScanReport, *, reveal_secrets: bool = False) -> str:
    rules = []
    seen: set[str] = set()
    for finding in report.findings:
        if finding.rule_id in seen:
            continue
        seen.add(finding.rule_id)
        level = "error" if finding.severity in {"CRITICAL", "HIGH"} else "warning"
        rules.append(
            {
                "id": finding.rule_id,
                "name": finding.rule_name,
                "shortDescription": {"text": finding.description},
                "help": {"text": finding.remediation},
                "defaultConfiguration": {"level": level},
            }
        )

    results = []
    for finding in report.findings:
        level = "error" if finding.severity in {"CRITICAL", "HIGH"} else "warning"
        shown = finding.matched_secret if reveal_secrets else finding.masked_secret
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": level,
                "message": {"text": f"{finding.rule_name}. Value: {shown}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file},
                            "region": {
                                "startLine": finding.line,
                                "startColumn": finding.column,
                                "snippet": {"text": finding.public_snippet(reveal_secrets)},
                            },
                        }
                    }
                ],
            }
        )

    payload = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecScan",
                        "semanticVersion": report.version,
                        "informationUri": "https://github.com/saulofilho/secscan",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def to_markdown(report: ScanReport, *, reveal_secrets: bool = False) -> str:
    metrics = report.metrics
    if report.findings:
        blocks = []
        for finding in report.findings:
            shown = finding.matched_secret if reveal_secrets else finding.masked_secret
            blocks.append(
                "\n".join(
                    [
                        f"### [{finding.severity}] {finding.rule_name}",
                        f"- **File:** `{finding.file}` (line {finding.line})",
                        f"- **Value:** `{shown}`",
                        f"- **Entropy:** {finding.entropy}",
                        f"- **Description:** {finding.description}",
                        f"- **Remediation:** {finding.remediation}",
                    ]
                )
            )
        findings_md = "\n\n".join(blocks)
    else:
        findings_md = "_No secrets or sensitive routes found._"

    if report.api_endpoints:
        routes = "\n".join(
            f"- `{item.method}` `{item.path}` in `{item.file}:{item.line}`"
            + (" **(sensitive)**" if item.is_internal_or_admin else "")
            for item in report.api_endpoints
        )
    else:
        routes = "_No endpoints mapped._"

    return "\n".join(
        [
            "# SecScan report",
            "",
            f"- **Target:** `{report.target}`",
            f"- **When:** {report.timestamp}",
            f"- **Files scanned:** {report.scanned_files_count} (ignored: {report.ignored_files_count})",
            f"- **Findings:** {len(report.findings)}",
            f"- **Security score:** {metrics.security_score}/100",
            f"- **Impact score:** {metrics.security_impact_score}/100 ({metrics.impact_level})",
            "",
            "## Severity",
            "",
            "| Severity | Count |",
            "|---|---|",
            f"| CRITICAL | {metrics.critical_count} |",
            f"| HIGH | {metrics.high_count} |",
            f"| MEDIUM | {metrics.medium_count} |",
            f"| LOW | {metrics.low_count} |",
            f"| INFO | {metrics.info_count} |",
            "",
            "## Findings",
            "",
            findings_md,
            "",
            f"## Endpoints ({len(report.api_endpoints)})",
            "",
            routes,
            "",
        ]
    )


def to_table(report: ScanReport, *, reveal_secrets: bool = False) -> str:
    metrics = report.metrics
    lines = [
        "SecScan Static Security Analysis",
        f"Target: {report.target} | Files: {report.scanned_files_count} | Findings: {len(report.findings)} | {report.duration_ms}ms",
        f"Impact: {metrics.security_impact_score}/100 ({metrics.impact_level}) | Security score: {metrics.security_score}/100",
        "-" * 72,
    ]
    if not report.findings:
        lines.append("No exposed secrets or sensitive API paths detected.")
    for finding in report.findings:
        shown = finding.matched_secret if reveal_secrets else finding.masked_secret
        lines.extend(
            [
                f"{finding.severity:<8} [{finding.rule_name}]",
                f"  File:    {finding.file}:{finding.line}",
                f"  Secret:  {shown} (entropy {finding.entropy})",
                f"  Snippet: {finding.public_snippet(reveal_secrets)}",
                f"  Info:    {finding.description}",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def render(report: ScanReport, fmt: str, *, reveal_secrets: bool = False) -> str:
    kind = fmt.lower()
    if kind == "json":
        return to_json(report, reveal_secrets=reveal_secrets) + "\n"
    if kind == "csv":
        return to_csv(report, reveal_secrets=reveal_secrets)
    if kind == "sarif":
        return to_sarif(report, reveal_secrets=reveal_secrets) + "\n"
    if kind == "markdown":
        return to_markdown(report, reveal_secrets=reveal_secrets)
    if kind == "table":
        return to_table(report, reveal_secrets=reveal_secrets)
    raise ValueError(f"unknown format: {fmt}")
