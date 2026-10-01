# Changelog

## 0.1.0

First PyPI package of the [SecScan](https://github.com/saulofilho/secscan) SAST engine, published as `secscan-sast` because `secscan` collides with the existing [sec-scan](https://pypi.org/project/sec-scan/) project. Secret and route rules, Shannon entropy, impact score, JSON/CSV/SARIF/Markdown reports, and a CLI quality gate. The import and console script stay `secscan`.

Serialized reports mask the matched value. The in-memory object still keeps the literal.
