# Secret Scanner — CLI + Desktop GUI

Scan Git repositories and folders for secrets using regex + entropy detectors.  
Output pretty console, JSON, or SARIF; manage suppressions via a baseline; extend detection with a YAML rules file;  
and use a desktop GUI (Tkinter) with one-click GitHub repo cloning.

This project includes two entry points:
- CLI scanner: `secretscan.py` (or `SecretScanner.py`)
- Desktop GUI: `SecretScannerGui.py` (Tkinter)

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Files](#files)
- [CLI Usage](#cli-usage)
- [Pre-commit Hook](#pre-commit-hook)
- [YAML Custom Detectors](#yaml-custom-detectors)
- [Suppressions](#suppressions)
- [Desktop GUI (Tkinter)](#desktop-gui-tkinter)
- [Outputs](#outputs)
  - [JSON](#json)
  - [SARIF](#sarif)
- [Tips and Troubleshooting](#tips-and-troubleshooting)
- [Security Notes](#security-notes)
- [License](#license)
- [Credits](#credits)

---
## Features

- Regex + entropy-based detectors (AWS keys, GitHub tokens, private keys, Slack tokens, high-entropy strings, and more)
- Outputs: pretty console, JSON, SARIF (for CI/Code Scanning)
- Pre-commit integration
- Baseline suppressions and inline/file-level ignores
- Custom detectors via YAML (no code changes)
- Desktop GUI (Tkinter):
  - Pick a folder to scan
  - “Add YAML…” to load custom rules (`.yml`/`.yaml`)
  - “GitHub repo” clone (https, ssh, `owner/repo`, `gh repo clone`, or `git clone`)
  - Scan staged files (Git) or the whole tree
  - Export JSON/SARIF, open selected file, view context

---

## Requirements

- Python 3.8+
- CLI:  
  ```bash
  pip install typer[all] rich pyyaml
  ```
- GUI: Tkinter (ships with most Python installs)
  - Optional: `pyyaml` for YAML rules
  - Git installed and on PATH for the Clone Repo button

On Debian/Ubuntu if Tk is missing:
```bash
sudo apt-get install python3-tk
```

---

## Files

- `secretscan.py` or `SecretScanner.py` — CLI scanner  
- `SecretScannerGui.py` — Tkinter desktop GUI for the scanner  
- `.secretscan.yml` — optional YAML rules (custom detectors)  
- `.secrets.baseline.json` — optional baseline suppressions file  

> Note: The GUI tries to import `secretscan` first, then `SecretScanner`. Keep one of those filenames.

---

## CLI Usage

Help:
```bash
python secretscan.py --help
python secretscan.py scan --help
```

Scan current directory (pretty output):
```bash
python secretscan.py scan .
```

JSON or SARIF output:
```bash
python secretscan.py scan . --format json > secrets.json
python secretscan.py scan . --format sarif --output secrets.sarif
```

Scan only staged files (Git):
```bash
python secretscan.py scan . --staged
```

Use a YAML rules file:
```bash
python secretscan.py scan . --rules .secretscan.yml
```

Baseline workflow:
```bash
# Create/refresh baseline file of current findings
python secretscan.py baseline .                 # writes .secrets.baseline.json

# Use baseline to suppress known findings
python secretscan.py scan . --baseline .secrets.baseline.json

# Update baseline after a scan
python secretscan.py scan . --update-baseline
```

Failing or not failing the build:  
By default, the CLI exits non-zero if findings are present.  
To allow success even with findings: add `--no-fail`.

Other useful flags:
- `--include-binaries` to scan binaries (off by default)  
- `--file/-f` to target specific files  
- `--output/-o` to write reports to a file  

Commands:
- `scan`: run the scanner  
- `rules`: list detectors (built-in + YAML)  
- `baseline`: create/refresh baseline file  

Windows examples:
```powershell
py secretscan.py scan .
py secretscan.py scan . --format sarif --output secrets.sarif
```

---

## Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: secretscan
        name: secretscan
        entry: python secretscan.py scan --staged --format json --output secrets.json
        language: system
        pass_filenames: true
        files: ".*"
        stages: [commit]
```

To fail commits on findings, keep default behavior.  
To allow commits but record current findings:

```yaml
entry: python secretscan.py scan --staged --update-baseline
```

---

## YAML Custom Detectors

Create `.secretscan.yml`:

```yaml
detectors:
  - id: stripe_live_key
    message: "Stripe live secret key"
    pattern: "sk_live_[A-Za-z0-9]{24}"
    severity: high
    confidence: high
    ignore_case: false

  - id: jwt_bearer
    message: "JWT-like token"
    pattern: "eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"
    severity: medium
    confidence: low
    ignore_case: false

  - id: generic_api_key
    message: "API key after api_key or api-key"
    pattern: "(?i)\bapi[_-]?key\b\s*[:=]\s*([A-Za-z0-9/\+=._-]{16,})"
    group: 1
    severity: high
    confidence: medium
    min_entropy: 3.5
    ignore_case: true
```

Notes:
- `id`: unique rule ID  
- `pattern`: Python-style regex  
- `group`: which capture group is the secret (default 0)  
- `min_entropy`: optional filter for high-entropy values  
- `ignore_case`: add re.IGNORECASE (default true)  

Use with CLI:
```bash
python secretscan.py scan . --rules .secretscan.yml
python secretscan.py rules --rules .secretscan.yml
```

> Tip: Use single quotes in YAML to avoid excessive escaping.

---

## Suppressions

- **Inline ignore**: add a comment on the same line:  
  ```python
  secret = "hardcoded"  # secret-scan: ignore
  ```

- **File-level ignore**: put `secrets:ignore-file` in the first few lines of a file  

- **Baseline**: `.secrets.baseline.json` stores hashed fingerprints of accepted findings  

---

## Desktop GUI (Tkinter)

Launch:
```bash
python SecretScannerGui.py
```

Main controls:
- **Path to scan**: pick a local folder  
- **GitHub repo + Clone Repo**:  
  Accepts https URL, ssh URL, `owner/repo`, `gh repo clone owner/repo`, or `git clone …`  
  “Clone to”: choose destination (shallow clone, depth 1)  
  After cloning, “Path to scan” auto-fills  
- **YAML config**:  
  “Add YAML…” to browse for `.yml/.yaml` (shows detector count if PyYAML is installed)  
- **Baseline file**:  
  Browse to pick an existing baseline, or leave empty to auto-use `<scan path>/.secrets.baseline.json`  
- **Options**:  
  - Scan staged (Git): only staged changes  
  - Include binaries: include binary files  
- **Actions**:  
  - Scan  
  - Update Baseline  
  - Export JSON / Export SARIF  
  - Open Selected (open file in OS)  
  - Clear results  

Results:
- Table lists Detector, Severity, File, Line, Snippet (redacted)  
- Details pane shows message, location, entropy, fingerprint, and context  

Requirements for GUI:
- Tkinter available  
- PyYAML (optional) for YAML rules  
- Git on PATH for Clone Repo (private repos require credentials)  

---

## Outputs

### JSON
Contains metadata and redacted values (actual matches not written).

```json
{
  "tool": "secretscan",
  "version": "0.1.0",
  "count": 2,
  "findings": [
    {
      "detector_id": "aws_access_key_id",
      "message": "Potential AWS Access Key ID",
      "path": "src/app.py",
      "line": 42,
      "start": 15,
      "end": 35,
      "severity": "high",
      "confidence": "high",
      "entropy": null,
      "fingerprint": "…",
      "redacted": "AKI...123"
    }
  ]
}
```

### SARIF
- Suitable for GitHub Code Scanning and similar platforms  
- Severities mapped to SARIF levels:  
  - critical/high → error  
  - medium → warning  
  - low → note  

---

## Tips and Troubleshooting

- CLI exits with `SystemExit` codes (normal for CLIs).  
- “Scan staged (Git)” only works inside a Git repo.  
- YAML not loading? Install `pyyaml` and verify the path:  
  ```bash
  pip install pyyaml
  ```
- Git clone fails? Ensure Git is installed and credentials are configured.  
- Tkinter missing on Linux? Install via package manager:  
  ```bash
  sudo apt-get install python3-tk
  ```

---

## Security Notes

- Matches are redacted in JSON/SARIF outputs  
- Baseline stores hashed fingerprints, not raw secrets  
- Review and rotate any real secrets found  
- Be mindful of scanning and storing reports for sensitive repositories  

---

## License

Add a license file if you plan to distribute (e.g., MIT).

---

## Credits

Built with **Typer**, **Rich**, **Tkinter**, and optional **PyYAML**.
