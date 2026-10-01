# secscan

Static analysis engine extracted from [SecScan](https://github.com/saulofilho/secscan). It walks JavaScript and TypeScript trees, looks for hardcoded secrets and sensitive API paths, scores the workspace, and fails CI when a policy is exceeded.

Python package and CLI. The same engine ships as the Ruby gem `secscan`. The React dashboard stays in the original repository.

```bash
pip install secscan-sast
secscan .
secscan . --fail-on high --max-risk 50
secscan . --format sarif --output secscan.sarif
```

Serialized reports **mask** the matched value. Use `--reveal-secrets` only when the artifact is restricted. The in-memory `Finding` object still keeps the literal.

## Contents

- [What it does](#what-it-does)
- [Use cases](#use-cases)
- [Proof of concept](#proof-of-concept)
- [Installation](#installation)
- [CLI](#cli)
- [Output formats](#output-formats)
- [Quality gates](#quality-gates)
- [Scoring](#scoring)
- [Built-in rules](#built-in-rules)
- [Custom rules](#custom-rules)
- [Ignore patterns](#ignore-patterns)
- [Programmatic API](#programmatic-api)
- [GitHub Actions](#github-actions)
- [What it does not do](#what-it-does-not-do)

## What it does

| Capability | Detail |
|---|---|
| Secret scan | AWS, GCP/Gemini, GitHub, Stripe, JWT, Slack, private keys, database URIs, hardcoded passwords, OpenAI, SendGrid |
| Route scan | Admin/internal paths and hardcoded `/api`, `/v1`, `/graphql`, `/webhook` endpoints |
| Entropy | Shannon entropy; a match below `minEntropy` is dropped |
| File walk | `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.json`, `.env`, `.yaml`, `.yml` |
| Ignore | `node_modules`, `vendor`, `dist`, `build`, lockfiles, plus `--ignore` |
| Score | Severity × file criticality, then an impact score from 0 to 100 |
| Reports | `table`, `json`, `csv`, `sarif`, `markdown` |
| CI gate | `--fail-on` and `--max-risk`, exit `1` |

## Use cases

**Pre-commit or local review.** Scan a branch before you open a PR. The default table is meant for a terminal.

```bash
secscan ./src --fail-on high
```

**CI quality gate.** Block a merge when a critical secret lands, or when the workspace impact score goes above the team cap.

```bash
secscan . --fail-on critical --max-risk 50 --format json --output secscan.json
```

**GitHub Code Scanning.** Emit SARIF 2.1.0 and upload it so findings show on the Security tab.

```bash
secscan . --format sarif --output secscan.sarif
```

**Compliance export.** CSV for a spreadsheet, Markdown for an audit note.

```bash
secscan . --format csv --output findings.csv
secscan . --format markdown --output findings.md
```

**Library in a Python tool.** Call `secscan.scan_path` or `secscan.scan_text` from a script, a bot, or a larger AppSec pipeline.

**Custom policy.** Add org-specific regex in a JSON file and merge it with the built-in set.

```bash
secscan . --rules ./examples/poc/custom-rules.json
```

## Proof of concept

The repo ships a tiny tree under [`examples/poc`](examples/poc): one source file with public sample values (the official AWS example access key, a fake database URI, and an admin route).

```bash
# from the package root
PYTHONPATH=src python3 -m secscan examples/poc --format table
```

After `pip install secscan-sast`:

```bash
secscan examples/poc --format table
secscan examples/poc --format json
secscan examples/poc --fail-on high; echo $?
```

The POC source is:

```javascript
// Proof of concept only. Values are public samples, not live credentials.
const awsKey = "AKIAIOSFODNN7EXAMPLE";
const db = "postgres://admin:SuperSecretPass123@db.prod.internal:5432/main";

app.get("/api/v1/admin/users", handler);
```

Expected findings (masked in every serialized format):

| Rule | Severity | Why it fires |
|---|---|---|
| `sec-aws-akid` | CRITICAL | AWS access key pattern |
| `sec-db-uri` | CRITICAL | Database URI with a password |
| `sec-sensitive-api-path` | MEDIUM | `/api/v1/admin/...` |
| `sec-api-endpoint` | LOW | Hardcoded `/api/...` path |

The same file also maps `GET /api/v1/admin/users` as a sensitive API endpoint.

A clean tree exits `0` and prints no findings:

```bash
mkdir -p /tmp/secscan-clean && echo 'const ok = 1;' > /tmp/secscan-clean/app.js
secscan /tmp/secscan-clean --fail-on critical --format table
```

## Installation

```bash
pip install secscan-sast
```

From this repository, without publishing:

```bash
pip install -e .
secscan --version
```

Requires Python 3.10 or newer.

## CLI

```text
Usage: secscan [path] [options]

  --format FORMAT        table (default), json, sarif, csv, markdown
  --rules FILE           extra rules JSON, merged with the built-in set
  --ignore LIST          extra ignore patterns, comma-separated
  --fail-on LEVEL        critical | high | medium | low | info
  --max-risk SCORE       fail if impact score (0-100) exceeds SCORE
  --output FILE          write the report to FILE instead of stdout
  --reveal-secrets       include the matched literal (restricted artifacts only)
  --version              print version
```

`path` may be a file or a directory. Default is `.`.

| Exit | Meaning |
|---|---|
| `0` | Scan finished; quality gate passed or was not set |
| `1` | Quality gate failed (`--fail-on` or `--max-risk`) |
| `2` | Invalid path, rules file, or CLI option |

`--output` writes the chosen format to a file and prints `Report written to …` on stderr. `--fail-on` / `--max-risk` still apply.

## Output formats

Every serialized format masks secrets unless you pass `--reveal-secrets`. JSON never includes `matchedSecret` by default.

### `table` (default)

Human-readable terminal report.

```text
SecScan Static Security Analysis
Target: examples/poc | Files: 1 | Findings: 4 | 4ms
Impact: 66/100 (HIGH) | Security score: 43/100
------------------------------------------------------------------------
CRITICAL [AWS Access Key ID]
  File:    src/app.js:2
  Secret:  AKIA••••••••••••MPLE (entropy 3.84)
  Snippet: const awsKey = "AKIA••••••••••••MPLE";
  Info:    AWS public access key hardcoded in source.
```

### `json`

Machine-readable report for CI, bots, and later processing.

```json
{
  "scanner": "SecScan SAST",
  "version": "0.1.0",
  "target": "examples/poc",
  "totalFiles": 1,
  "scannedFilesCount": 1,
  "ignoredFilesCount": 0,
  "findings": [
    {
      "id": "finding-1",
      "ruleId": "sec-aws-akid",
      "ruleName": "AWS Access Key ID",
      "category": "CLOUD_CREDENTIAL",
      "severity": "CRITICAL",
      "file": "src/app.js",
      "line": 2,
      "column": 17,
      "snippet": "const awsKey = \"AKIA••••••••••••MPLE\";",
      "maskedSecret": "AKIA••••••••••••MPLE",
      "entropy": 3.84,
      "fileCriticality": "MEDIUM",
      "fileCriticalityWeight": 1.0,
      "weightedScore": 25.0
    }
  ],
  "apiEndpoints": [
    {
      "id": "endpoint-1",
      "file": "src/app.js",
      "line": 5,
      "method": "GET",
      "path": "/api/v1/admin/users",
      "isInternalOrAdmin": true
    }
  ],
  "metrics": {
    "criticalCount": 2,
    "highCount": 0,
    "mediumCount": 1,
    "lowCount": 1,
    "infoCount": 0,
    "securityScore": 43,
    "securityImpactScore": 66,
    "impactLevel": "HIGH",
    "totalWeightedRisk": 60.0,
    "averageEntropy": 4.12
  },
  "durationMs": 4
}
```

Finding fields: `id`, `ruleId`, `ruleName`, `category`, `severity`, `file`, `line`, `column`, `snippet`, `maskedSecret`, `entropy`, `description`, `remediation`, `fileCriticality`, `fileCriticalityWeight`, `weightedScore`. With `--reveal-secrets`, `matchedSecret` is added.

### `csv`

One row per finding. Header:

```text
ID,Severity,Rule Name,Category,File,Line,Column,Entropy,Masked Secret,Remediation
```

```text
finding-1,CRITICAL,AWS Access Key ID,CLOUD_CREDENTIAL,src/app.js,2,17,3.84,AKIA••••••••••••MPLE,Use IAM roles, environment variables, or AWS Secrets Manager.
```

Useful in Sheets or Excel. Endpoints are not included; use JSON if you need them.

### `sarif`

OASIS SARIF 2.1.0 for GitHub Code Scanning (`github/codeql-action/upload-sarif`).

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "SecScan",
          "semanticVersion": "0.1.0",
          "informationUri": "https://github.com/saulofilho/secscan"
        }
      },
      "results": [
        {
          "ruleId": "sec-aws-akid",
          "level": "error",
          "message": { "text": "AWS Access Key ID. Value: AKIA••••••••••••MPLE" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "src/app.js" },
                "region": { "startLine": 2, "startColumn": 17 }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

`CRITICAL` and `HIGH` map to SARIF `error`. Everything else maps to `warning`.

### `markdown`

Audit-style document for pull requests or tickets.

```markdown
# SecScan report

- **Target:** `examples/poc`
- **Files scanned:** 1 (ignored: 0)
- **Findings:** 4
- **Security score:** 43/100
- **Impact score:** 66/100 (HIGH)

## Findings

### [CRITICAL] AWS Access Key ID
- **File:** `src/app.js` (line 2)
- **Value:** `AKIA••••••••••••MPLE`
- **Entropy:** 3.84
```

Impact and file counts in the samples above are representative of `examples/poc`. Entropy and duration can vary slightly by platform.

## Quality gates

`--fail-on` uses this order: `info` < `low` < `medium` < `high` < `critical`. A finding at the chosen level **or above** fails the process.

```bash
secscan . --fail-on critical    # only CRITICAL fails the build
secscan . --fail-on high        # HIGH and CRITICAL fail
secscan . --max-risk 50         # impact score 51+ fails
secscan . --fail-on high --max-risk 50
```

Stderr on failure:

```text
SecScan quality gate: findings with severity >= HIGH
SecScan quality gate: impact score 66 above 50
```

A scan with findings still exits `0` if you set neither flag.

## Scoring

Each finding gets `weightedScore = severityWeight × fileCriticality`.

| Severity | Weight |
|---|---|
| CRITICAL | 25 |
| HIGH | 14 |
| MEDIUM | 7 |
| LOW | 3 |
| INFO | 1 |

| File class | Multiplier | Examples |
|---|---|---|
| CRITICAL | 2.0 | `.env`, secrets, keys, `Dockerfile`, `config/` |
| HIGH | 1.5 | `services/`, `routes/`, `auth`, payments |
| MEDIUM | 1.0 | regular application code |
| LOW | 0.5 | tests, docs, fixtures |

```text
impactScore = 100 × (1 − e^(−totalWeightedRisk / 55))
```

| Impact score | Level |
|---|---|
| 0 | NOMINAL |
| 1–14 | LOW |
| 15–34 | MODERATE |
| 35–59 | ELEVATED |
| 60–79 | HIGH |
| 80–100 | CRITICAL |

`securityScore` starts at 100 and subtracts `25` per CRITICAL, `12` per HIGH, `5` per MEDIUM, `2` per LOW.

## Built-in rules

| ID | Severity | Category |
|---|---|---|
| `sec-aws-akid` | CRITICAL | CLOUD_CREDENTIAL |
| `sec-aws-secret` | CRITICAL | CLOUD_CREDENTIAL |
| `sec-github-pat` | CRITICAL | AUTH_TOKEN |
| `sec-stripe-secret` | CRITICAL | API_KEY |
| `sec-private-key` | CRITICAL | PRIVATE_KEY |
| `sec-db-uri` | CRITICAL | DATABASE_URI |
| `sec-openai-key` | CRITICAL | API_KEY |
| `sec-google-api` | HIGH | API_KEY |
| `sec-jwt-token` | HIGH | AUTH_TOKEN |
| `sec-slack-webhook` | HIGH | AUTH_TOKEN |
| `sec-hardcoded-pass` | HIGH | PASSWORD |
| `sec-sendgrid-key` | HIGH | API_KEY |
| `sec-sensitive-api-path` | MEDIUM | API_PATH |
| `sec-api-endpoint` | LOW | API_PATH |

Rule IDs, names, severities, categories, descriptions, and remediations are English.

## Custom rules

`--rules` loads a JSON **array** and **appends** it to the built-in set. See [`examples/poc/custom-rules.json`](examples/poc/custom-rules.json).

```json
[
  {
    "id": "sec-demo-token",
    "name": "Demo corp token",
    "pattern": "\\bCORP-[A-Z0-9]{24}\\b",
    "severity": "HIGH",
    "category": "CUSTOM",
    "description": "Internal token format for the POC.",
    "remediation": "Move CORP-* tokens to an environment variable.",
    "flags": "g",
    "minEntropy": 3.0
  }
]
```

| Field | Required | Notes |
|---|---|---|
| `id` | yes | Stable rule id |
| `name` | yes | Shown in reports |
| `pattern` | yes | Python/JavaScript-style regular expression |
| `severity` | no | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` (default `MEDIUM`) |
| `category` | no | Default `CUSTOM` |
| `description` | no | |
| `remediation` | no | |
| `flags` | no | `g`, `i`, or `gi`. `(?i)` prefixes are accepted |
| `minEntropy` / `min_entropy` | no | Drop matches below this Shannon value |
| `enabled` | no | Default `true` |

An invalid file exits `2` (`rules file not found` or `rules file is not valid JSON`).

## Ignore patterns

Always skipped: `node_modules`, `vendor`, `bower_components`, `.git`, `dist`, `build`, `out`, `coverage`, `.cache`, `*.min.js`, `*.bundle.js`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`.

`--ignore` adds comma-separated patterns:

```bash
secscan . --ignore "tests/*,docs/*,*.spec.ts"
```

Supported shapes: `tests/*`, `vendor/**`, `*.test.*`, `package-lock.json`, or a directory name such as `fixtures`.

## Programmatic API

```python
import secscan
from secscan.report import render

report = secscan.scan_path("./src", ignore=["tests/*"])
report.metrics.security_impact_score  # 0..100
report.metrics.impact_level           # NOMINAL, LOW, MODERATE, ELEVATED, HIGH, CRITICAL
for finding in report.findings:
    print(f"{finding.severity} {finding.file}:{finding.line} {finding.masked_secret}")

inline = secscan.scan_text(
    'const key = "AKIAIOSFODNN7EXAMPLE";\n',
    path="src/app.js",
)

rules = secscan.load_rules("examples/poc/custom-rules.json")
secscan.scan_path(".", rules=rules)

secscan.calculate_entropy("AKIAIOSFODNN7EXAMPLE")
secscan.mask_secret("AKIAIOSFODNN7EXAMPLE")
# => "AKIA••••••••••••MPLE"

text = render(report, "sarif")
```

`secscan.scan_path` accepts a file or a directory. `scan_text` scans one string. Both return a `ScanReport`.

## GitHub Actions

```yaml
name: SecScan

on:
  push:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install secscan-sast
      - name: Scan
        run: |
          secscan . \
            --format sarif \
            --output secscan.sarif \
            --ignore "tests/*,docs/*"
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: secscan.sarif
      - name: Quality gate
        run: secscan . --fail-on critical --max-risk 50
```

## Publish to PyPI

Trusted Publishing (OIDC) from GitHub Actions. No API token in the repo.

1. Push `main` so [`.github/workflows/publish.yml`](.github/workflows/publish.yml) exists on the default branch.
2. In [PyPI publishing](https://pypi.org/manage/account/publishing/), add a **pending publisher**:

   | Field | Value |
   |---|---|
   | PyPI project name | `secscan-sast` |
   | Owner | `saulofilho` |
   | Repository | `secscan-python` |
   | Workflow name | `publish.yml` |
   | Environment name | leave empty |

3. On GitHub: **Actions → Publish to PyPI → Run workflow**, or create release `v0.1.0`.

The first successful run creates the project on PyPI. After that the pending publisher becomes a trusted publisher on the project.

## What it does not do

- DAST, fuzzing, live HTTP attacks, WAF, or EDR
- Dynamic confirmation that a secret is still valid
- Auto-remediation patches
- Skills, agents, or MCP (next step)

License: MIT. Changelog: [CHANGELOG.md](CHANGELOG.md).
