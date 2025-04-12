![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-green)

Advanced API security scanner with OWASP API Top 10 detection and SQLi analysis.

## Features
- Multi-method API endpoint discovery
- OWASP API Top 10 2023 vulnerability checks
- SQLi detection via SQLMap integration
- Real-time progress tracking
- Color-coded threat assessment
- Burp/Postman compatible reports

## Installation

```bash
git clone https://github.com/yourusername/API-Sentinel-X.git
cd API-Sentinel-X
pip install -r requirements.txt
```
Usage

```bash
python3 src/scanner.py -f targets.txt -o results -t 10
```
