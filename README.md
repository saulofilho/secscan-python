# secscan

Motor de **análise estática** extraído do [SecScan](https://github.com/saulofilho/secscan): segredos hardcoded, entropia de Shannon, rotas de API no código, impact score e quality gate para CI.

Biblioteca Python e CLI. O dashboard React continua no repositório original.

## O que este pacote faz

- Aplica as regras do motor (AWS, GCP, GitHub, Stripe, JWT, Slack, chave privada, URI de banco, senha fixa, OpenAI, SendGrid, rotas admin e endpoints)
- Calcula entropia e descarta match abaixo do `minEntropy` da regra
- Ignora `node_modules`, `vendor`, `dist`, lockfiles e padrões extras
- Pondera achado por severidade e criticidade do arquivo
- Impact score de 0 a 100: `100 * (1 - e^(-risco / 55))`
- Exporta tabela, JSON, CSV, SARIF 2.1.0 e Markdown
- Falha o processo com exit code `1` em `--fail-on` ou `--max-risk`

## O que fica de fora

O README do app descreve DAST, fuzzer, WAF, EDR e módulos parecidos. Eles não entram nesta biblioteca. Skill, agente e MCP são o passo seguinte, no mesmo espírito do security-pentest-planner.

Relatórios em arquivo mascaram o segredo. Use `--reveal-secrets` só quando o artefato for restrito. O objeto `Finding` em memória guarda o literal.

## Instalação

```bash
pip install secscan
```

Confirme o nome no PyPI antes de publicar: o pacote local se chama `secscan`.

## CLI

```bash
secscan .
secscan ./src --fail-on critical
secscan . --max-risk 50 --format sarif --output secscan.sarif
secscan . --ignore "tests/*,docs/*" --rules ./rules.json
```

| Flag | Efeito |
|------|--------|
| `--format` | `table` (padrão), `json`, `sarif`, `csv`, `markdown` |
| `--rules` | JSON extra, somado às regras internas |
| `--ignore` | Padrões separados por vírgula |
| `--fail-on` | Exit 1 se houver achado nessa severidade ou acima |
| `--max-risk` | Exit 1 se o impact score passar do teto |
| `--output` | Grava o relatório |
| `--reveal-secrets` | Inclui o valor encontrado |

Exit `0` passa, `1` é quality gate, `2` é caminho ou regras inválidas.

## Uso programático

```python
import secscan

report = secscan.scan_path("./src", ignore=["tests/*"])
print(report.metrics.security_impact_score, report.metrics.impact_level)

inline = secscan.scan_text('const key = "AKIAIOSFODNN7EXAMPLE";\n', path="src/app.js")
print(inline.findings[0].masked_secret)
```

Um arquivo de regras é uma lista de objetos com `id`, `name`, `pattern`, `severity`, `category`, `description`, `remediation`, `flags` e `minEntropy`.
