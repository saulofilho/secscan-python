"""Directory and in-memory SAST scan."""

from __future__ import annotations

import json
import math
import os
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .errors import InputError
from .rules import (
    DEFAULT_RULES,
    FILE_CRITICALITY_MULTIPLIERS,
    SEVERITY_BASE_WEIGHTS,
    SEVERITY_RANK,
    Rule,
)

SCAN_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".env", ".yaml", ".yml"}
SKIP_DIR_NAMES = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "out",
    "coverage",
    "bower_components",
    ".cache",
}
MAX_FILE_BYTES = 1_048_576

API_CALL_RE = re.compile(
    r"""(?:app\.(get|post|put|delete|patch)|router\.(get|post|put|delete|patch)|axios\.(get|post|put|delete|patch)|fetch)\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)
SENSITIVE_PATH_RE = re.compile(r"admin|internal|superadmin|debug|token|actuator|secret", re.IGNORECASE)


@dataclass
class Finding:
    """One match. ``matched_secret`` stays in memory and is omitted from reports by default."""

    id: str
    rule_id: str
    rule_name: str
    category: str
    severity: str
    file: str
    line: int
    column: int
    snippet: str
    matched_secret: str = field(repr=False)
    masked_secret: str
    entropy: float
    description: str
    remediation: str
    file_criticality: str
    file_criticality_weight: float
    weighted_score: float

    def public_snippet(self, reveal: bool = False) -> str:
        if reveal or not self.matched_secret:
            return self.snippet
        return self.snippet.replace(self.matched_secret, self.masked_secret)


@dataclass(frozen=True)
class ApiEndpoint:
    id: str
    file: str
    line: int
    method: str
    path: str
    is_internal_or_admin: bool
    snippet: str


@dataclass(frozen=True)
class Metrics:
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    security_score: int
    security_impact_score: int
    impact_level: str
    total_weighted_risk: float
    average_entropy: float


@dataclass
class ScanReport:
    scanner: str
    version: str
    timestamp: str
    target: str
    total_files: int
    scanned_files_count: int
    ignored_files_count: int
    findings: list[Finding]
    api_endpoints: list[ApiEndpoint]
    metrics: Metrics
    duration_ms: int


def calculate_entropy(value: str) -> float:
    """Shannon entropy, rounded to two decimals, matching the JS engine."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return float(f"{entropy:.2f}")


def mask_secret(secret: str) -> str:
    """Mask a matched value so reports can be shared without the literal."""
    if not secret:
        return ""
    clean = secret.strip().strip("'\"")
    if len(clean) <= 8:
        return "••••••••"
    prefix = clean[:4]
    suffix = clean[-4:]
    hidden = "•" * min(16, max(6, len(clean) - 8))
    return f"{prefix}{hidden}{suffix}"


def _normalize_rel(value: str) -> str:
    text = value.strip().replace("\\", "/")
    if text.startswith("./"):
        text = text[2:]
    elif text.startswith("/"):
        text = text[1:]
    return text.lower()


def matches_ignore_pattern(file_path: str, raw_pattern: str) -> bool:
    """Subset of the SecScan ignore matcher: folders, suffixes, and globs."""
    if not raw_pattern or not file_path:
        return False
    pattern = raw_pattern.strip().replace("\\", "/")
    if not pattern or pattern.startswith("#"):
        return False

    normalized_path = _normalize_rel(file_path)
    normalized_pattern = _normalize_rel(pattern)

    if normalized_path == normalized_pattern:
        return True

    if normalized_pattern.endswith(("/*", "/**", "/")):
        folder = re.sub(r"(/\*+|/)$", "", normalized_pattern)
        if (
            normalized_path == folder
            or normalized_path.startswith(folder + "/")
            or f"/{folder}/" in f"/{normalized_path}"
        ):
            return True

    if "*" not in normalized_pattern and "." not in normalized_pattern:
        if (
            normalized_path == normalized_pattern
            or normalized_path.startswith(normalized_pattern + "/")
            or f"/{normalized_pattern}/" in f"/{normalized_path}"
            or normalized_path.endswith("/" + normalized_pattern)
        ):
            return True

    if normalized_pattern.startswith("*."):
        suffix = normalized_pattern[1:]
        if suffix.endswith(".*"):
            base = suffix[:-2]
            if f"{base}." in normalized_path or normalized_path.endswith(base):
                return True
        elif normalized_path.endswith(suffix):
            return True

    parts: list[str] = []
    index = 0
    while index < len(normalized_pattern):
        if normalized_pattern.startswith("**", index):
            parts.append(".*")
            index += 2
        elif normalized_pattern[index] == "*":
            parts.append("[^/]*")
            index += 1
        elif normalized_pattern[index] == "?":
            parts.append(".")
            index += 1
        else:
            parts.append(re.escape(normalized_pattern[index]))
            index += 1
    return re.search("(^|/)" + "".join(parts) + "($|/)", normalized_path) is not None


def ignore_reason(file_path: str, custom_patterns: list[str] | None = None) -> str | None:
    """Return why a path is skipped, or None when it should be scanned."""
    for pattern in custom_patterns or []:
        if matches_ignore_pattern(file_path, pattern):
            return f"ignore:{pattern}"

    normalized = file_path.replace("\\", "/").lower()
    if "/node_modules/" in f"/{normalized}" or normalized.startswith("node_modules/"):
        return "node_modules"
    if "/vendor/" in f"/{normalized}" or normalized.startswith("vendor/"):
        return "vendor"
    if "/bower_components/" in f"/{normalized}":
        return "bower_components"
    if "/.git/" in f"/{normalized}" or normalized.startswith(".git/"):
        return "git"
    if any(token in f"/{normalized}" for token in ("/dist/", "/build/", "/out/")) or normalized.startswith(
        ("dist/", "build/", "out/")
    ):
        return "build"
    if normalized.endswith((".min.js", ".bundle.js")) or ".chunk.js" in normalized:
        return "bundle"
    if normalized.endswith(("package-lock.json", "yarn.lock", "pnpm-lock.yaml")):
        return "lockfile"
    if "/coverage/" in f"/{normalized}" or "/.cache/" in f"/{normalized}":
        return "cache"
    return None


def evaluate_file_criticality(file_path: str) -> tuple[str, float, str]:
    """Return ``(level, weight, category)`` for a relative path."""
    normalized = file_path.replace("\\", "/").lower()
    file_name = normalized.rsplit("/", 1)[-1]

    if (
        ".env" in normalized
        or "credentials" in normalized
        or "secret" in normalized
        or "id_rsa" in normalized
        or file_name.endswith((".pem", ".key", ".pfx", ".keystore"))
        or normalized.startswith("config/")
        or "/config/" in normalized
        or "cloudconfig" in file_name
        or "dbconfig" in file_name
        or "database" in file_name
        or file_name == "dockerfile"
        or file_name.startswith("docker-compose")
        or any(part in normalized for part in ("k8s/", "kubernetes/", "helm/"))
        or file_name in {"server.ts", "server.js"}
    ):
        return "CRITICAL", FILE_CRITICALITY_MULTIPLIERS["CRITICAL"], "CONFIG_INFRA_SECRETS"

    if (
        any(part in normalized for part in ("/services/", "/controllers/", "/routes/", "/api/", "/handlers/", "/backend/", "/auth"))
        or "payment" in normalized
        or "checkout" in normalized
        or "webhook" in normalized
        or "authservice" in file_name
        or "paymentcontroller" in file_name
        or "firebase.json" in normalized
        or "cloudbuild" in normalized
        or "terraform" in normalized
    ):
        return "HIGH", FILE_CRITICALITY_MULTIPLIERS["HIGH"], "BACKEND_API_SERVICE"

    if (
        any(part in normalized for part in ("/test/", "/tests/", "/__tests__/", "/mocks/", "/fixtures/", "/docs/"))
        or file_name.endswith((".test.ts", ".test.js", ".spec.ts", ".spec.js", ".md", ".txt", ".css", ".svg"))
    ):
        return "LOW", FILE_CRITICALITY_MULTIPLIERS["LOW"], "TEST_DOC_FIXTURE"

    return "MEDIUM", FILE_CRITICALITY_MULTIPLIERS["MEDIUM"], "APPLICATION_CLIENT"


def calculate_security_impact(findings: list[Finding]) -> tuple[int, float, str]:
    """Asymptotic 0-100 score from severity weight times file criticality."""
    if not findings:
        return 0, 0.0, "NOMINAL"

    total = 0.0
    for finding in findings:
        total += finding.weighted_score
    total = float(f"{total:.1f}")
    normalized = 100 * (1 - math.exp(-total / 55))
    score = min(100, max(1, round(normalized)))
    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 35:
        level = "ELEVATED"
    elif score >= 15:
        level = "MODERATE"
    elif score > 0:
        level = "LOW"
    else:
        level = "NOMINAL"
    return score, total, level


def load_rules(path: str | Path | None = None, *, replace: bool = False) -> list[Rule]:
    """Load built-in rules, optionally merged with a JSON file."""
    rules = [] if replace else list(DEFAULT_RULES)
    if path is None:
        return [rule for rule in rules if rule.enabled]

    rules_path = Path(path)
    try:
        payload = json.loads(rules_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise InputError(f"rules file not found: {rules_path}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"rules file is not valid JSON: {rules_path}") from exc
    if not isinstance(payload, list):
        raise InputError("rules file must be a JSON array")

    for item in payload:
        if not isinstance(item, dict):
            raise InputError("each rule must be a JSON object")
        try:
            rules.append(
                Rule(
                    id=str(item["id"]),
                    name=str(item["name"]),
                    pattern=str(item["pattern"]),
                    severity=str(item.get("severity", "MEDIUM")),
                    category=str(item.get("category", "CUSTOM")),
                    description=str(item.get("description", "")),
                    remediation=str(item.get("remediation", "")),
                    flags=str(item.get("flags", "g")),
                    min_entropy=float(item["minEntropy"]) if item.get("minEntropy") is not None else (
                        float(item["min_entropy"]) if item.get("min_entropy") is not None else None
                    ),
                    enabled=bool(item.get("enabled", True)),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise InputError(f"invalid rule: {exc}") from exc
    return [rule for rule in rules if rule.enabled]


def _compile_rule(rule: Rule) -> re.Pattern[str] | None:
    pattern = rule.pattern
    flags = rule.flags or "g"
    if pattern.startswith("(?i)"):
        pattern = pattern[4:]
        if "i" not in flags:
            flags += "i"
    re_flags = re.IGNORECASE if "i" in flags else 0
    try:
        return re.compile(pattern, re_flags)
    except re.error:
        return None


def _line_column(content: str, index: int) -> tuple[int, int, str]:
    prefix = content[:index]
    line = prefix.count("\n") + 1
    column = len(prefix.rsplit("\n", 1)[-1]) + 1
    lines = content.split("\n")
    snippet = lines[line - 1] if line - 1 < len(lines) else ""
    return line, column, snippet.strip()


def _scannable(path: Path) -> bool:
    name = path.name
    if name == ".env" or name.startswith(".env."):
        return True
    return path.suffix.lower() in SCAN_SUFFIXES


def _iter_files(root: Path, custom_ignores: list[str]) -> tuple[list[tuple[str, str]], int, int]:
    """Return ``(files, seen, ignored)`` with contents already loaded."""
    files: list[tuple[str, str]] = []
    seen = 0
    ignored = 0
    if root.is_file():
        rel = root.as_posix()
        seen = 1
        reason = ignore_reason(rel, custom_ignores)
        if reason or not _scannable(root):
            return [], 1, 1
        text = _read_text(root)
        if text is None:
            return [], 1, 1
        return [(rel, text)], 1, 0

    for current_root, dir_names, file_names in os.walk(root):
        current_root = Path(current_root)
        dir_names[:] = [name for name in dir_names if name not in SKIP_DIR_NAMES]
        for name in file_names:
            full = current_root / name
            rel = full.relative_to(root).as_posix()
            if not _scannable(full):
                continue
            seen += 1
            if ignore_reason(rel, custom_ignores):
                ignored += 1
                continue
            text = _read_text(full)
            if text is None:
                ignored += 1
                continue
            files.append((rel, text))
    return files, seen, ignored


def _read_text(path: Path) -> str | None:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > MAX_FILE_BYTES:
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data:
        return None
    return data.decode("utf-8", errors="replace")


def scan_files(
    files: list[tuple[str, str]],
    *,
    rules: list[Rule] | None = None,
    ignore: list[str] | None = None,
    target: str = "memory",
    ignored_files_count: int = 0,
    total_files: int | None = None,
) -> ScanReport:
    """Scan already loaded ``(relative_path, content)`` pairs."""
    from .version import __version__

    started = time.perf_counter()
    active_rules = rules if rules is not None else list(DEFAULT_RULES)
    compiled = [(rule, _compile_rule(rule)) for rule in active_rules]
    findings: list[Finding] = []
    endpoints: list[ApiEndpoint] = []
    scanned = 0
    extra_ignored = 0

    for rel_path, content in files:
        if ignore_reason(rel_path, ignore):
            extra_ignored += 1
            continue
        scanned += 1
        level, weight, _category = evaluate_file_criticality(rel_path)

        for rule, pattern in compiled:
            if pattern is None:
                continue
            for match in pattern.finditer(content):
                literal = match.group(0)
                if not literal:
                    continue
                entropy = calculate_entropy(literal)
                if rule.min_entropy is not None and entropy < rule.min_entropy:
                    continue
                line, column, snippet = _line_column(content, match.start())
                base = SEVERITY_BASE_WEIGHTS.get(rule.severity, 5)
                findings.append(
                    Finding(
                        id=f"finding-{len(findings) + 1}",
                        rule_id=rule.id,
                        rule_name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        file=rel_path,
                        line=line,
                        column=column,
                        snippet=snippet,
                        matched_secret=literal,
                        masked_secret=mask_secret(literal),
                        entropy=entropy,
                        description=rule.description,
                        remediation=rule.remediation,
                        file_criticality=level,
                        file_criticality_weight=weight,
                        weighted_score=float(f"{base * weight:.1f}"),
                    )
                )

        for match in API_CALL_RE.finditer(content):
            raw_path = match.group(4) or ""
            if not (raw_path.startswith("/") or raw_path.startswith("http")):
                continue
            method = (match.group(1) or match.group(2) or match.group(3) or "GET").upper()
            line, _column, snippet = _line_column(content, match.start())
            endpoints.append(
                ApiEndpoint(
                    id=f"endpoint-{len(endpoints) + 1}",
                    file=rel_path,
                    line=line,
                    method=method,
                    path=raw_path,
                    is_internal_or_admin=bool(SENSITIVE_PATH_RE.search(raw_path)),
                    snippet=snippet,
                )
            )

    counts = {name: 0 for name in SEVERITY_RANK}
    for finding in findings:
        counts[finding.severity] += 1
    deduction = counts["CRITICAL"] * 25 + counts["HIGH"] * 12 + counts["MEDIUM"] * 5 + counts["LOW"] * 2
    security_score = max(0, min(100, 100 - deduction))
    impact, weighted, impact_level = calculate_security_impact(findings)
    average = 0.0
    if findings:
        average = float(f"{sum(item.entropy for item in findings) / len(findings):.2f}")

    elapsed = int(round((time.perf_counter() - started) * 1000))
    return ScanReport(
        scanner="SecScan SAST",
        version=__version__,
        timestamp=datetime.now(timezone.utc).isoformat(),
        target=target,
        total_files=total_files if total_files is not None else len(files),
        scanned_files_count=scanned,
        ignored_files_count=ignored_files_count + extra_ignored,
        findings=findings,
        api_endpoints=endpoints,
        metrics=Metrics(
            critical_count=counts["CRITICAL"],
            high_count=counts["HIGH"],
            medium_count=counts["MEDIUM"],
            low_count=counts["LOW"],
            info_count=counts["INFO"],
            security_score=security_score,
            security_impact_score=impact,
            impact_level=impact_level,
            total_weighted_risk=weighted,
            average_entropy=average,
        ),
        duration_ms=elapsed,
    )


def scan_text(content: str, *, path: str = "snippet", rules: list[Rule] | None = None, ignore: list[str] | None = None) -> ScanReport:
    """Scan one source string."""
    return scan_files([(path, content)], rules=rules, ignore=ignore, target=path)


def scan_path(
    path: str | Path,
    *,
    rules: list[Rule] | None = None,
    ignore: list[str] | None = None,
) -> ScanReport:
    """Scan a file or directory of JS/TS/JSON/YAML/env sources."""
    root = Path(path)
    if not root.exists():
        raise InputError(f"path not found: {root}")
    files, seen, ignored = _iter_files(root, list(ignore or []))
    return scan_files(
        files,
        rules=rules,
        ignore=ignore,
        target=root.as_posix(),
        ignored_files_count=ignored,
        total_files=seen,
    )
