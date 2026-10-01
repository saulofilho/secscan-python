# Changelog

## 0.1.0

Primeira biblioteca do motor SAST do [SecScan](https://github.com/saulofilho/secscan): regras de segredo e rota, entropia de Shannon, impact score, relatórios JSON/CSV/SARIF/Markdown e quality gate na CLI.

Relatórios serializados mascaram o valor encontrado. O objeto em memória ainda guarda o literal para quem chama `scan_path` / `scan_text` no mesmo processo.
