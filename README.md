# Secret Scanner --- CLI + Desktop GUI

Scan Git repositories and folders for secrets using regex + entropy
detectors. Output pretty console, JSON, or SARIF; manage suppressions
via a baseline; extend detection with a YAML rules file; and use a
desktop GUI (Tkinter) with one-click GitHub repo cloning.

This project includes two entry points: - CLI scanner: `secretscan.py`
(or `SecretScanner.py`) - Desktop GUI: `SecretScannerGui.py` (Tkinter)

------------------------------------------------------------------------

## Features

-   Regex + entropy-based detectors (AWS keys, GitHub tokens, private
    keys, Slack tokens, high-entropy strings, and more)
-   Outputs: pretty console, JSON, SARIF (for CI/Code Scanning)
-   Pre-commit integration
-   Baseline suppressions and inline/file-level ignores
-   Custom detectors via YAML (no code changes)
-   Desktop GUI (Tkinter):
    -   Pick a folder to scan
    -   "Add YAML..." to load custom rules (`.yml`/`.yaml`)
    -   "GitHub repo" clone (https, ssh, `owner/repo`, `gh repo clone`,
        or `git clone`)
    -   Scan staged files (Git) or the whole tree
    -   Export JSON/SARIF, open selected file, view context

------------------------------------------------------------------------

## Requirements

-   Python 3.8+
-   CLI: `pip install typer[all] rich pyyaml`
-   GUI: Tkinter (ships with most Python installs)
    -   Optional: `pyyaml` for YAML rules
    -   Git installed and on PATH for the Clone Repo button

Install: \`\`\`bash pip install typer\[all\] rich pyyaml \# GUI-only
optional dependency for YAML: pip install pyyaml On Debian/Ubuntu if Tk
is missing:

Bash

sudo apt-get install python3-tk Files secretscan.py or SecretScanner.py
--- CLI scanner SecretScannerGui.py --- Tkinter desktop GUI for the
scanner .secretscan.yml --- optional YAML rules (custom detectors)
.secrets.baseline.json --- optional baseline suppressions file Note: The
GUI tries to import secretscan first, then SecretScanner. Keep one of
those filenames.

CLI Usage Help:

Bash

python secretscan.py --help python secretscan.py scan --help Scan
current directory (pretty output):

Bash

python secretscan.py scan . JSON or SARIF output:

Bash

python secretscan.py scan . --format json \> secrets.json python
secretscan.py scan . --format sarif --output secrets.sarif Scan only
staged files (Git):

Bash

python secretscan.py scan . --staged Use a YAML rules file:

Bash

python secretscan.py scan . --rules .secretscan.yml Baseline workflow:

Bash

# Create/refresh baseline file of current findings

python secretscan.py baseline . \# writes .secrets.baseline.json

# Use baseline to suppress known findings

python secretscan.py scan . --baseline .secrets.baseline.json

# Update baseline after a scan

python secretscan.py scan . --update-baseline Failing or not failing the
build:

By default, the CLI exits non-zero if findings are present. To allow
success even with findings: add --no-fail. Other useful flags:

--include-binaries to scan binaries (off by default) --file/-f to target
specific files --output/-o to write reports to a file Commands:

scan: run the scanner rules: list detectors (built-in + YAML) baseline:
create/refresh baseline file Windows examples:

PowerShell

py secretscan.py scan . py secretscan.py scan . --format sarif --output
secrets.sarif Pre-commit Hook Add to .pre-commit-config.yaml:

YAML

repos: - repo: local hooks: - id: secretscan name: secretscan entry:
python secretscan.py scan --staged --format json --output secrets.json
language: system pass_filenames: true files: ".\*" stages: \[commit\] To
fail commits on findings, keep default behavior. To allow commits but
record current findings:

YAML

entry: python secretscan.py scan --staged --update-baseline YAML Custom
Detectors Create .secretscan.yml:

YAML

detectors: - id: stripe_live_key message: "Stripe live secret key"
pattern: "sk_live\_\[A-Za-z0-9\]{24}" severity: high confidence: high
ignore_case: false

-   id: jwt_bearer message: "JWT-like token" pattern:
    "eyJ\[a-zA-Z0-9\_-\]{10,}.\[a-zA-Z0-9\_-\]{10,}.\[a-zA-Z0-9\_-\]{10,}"
    severity: medium confidence: low ignore_case: false

-   id: generic_api_key message: "API key after api_key or api-key"
    pattern:
    "(?i)`\bapi[_-]`{=tex}?key`\b\s*[:=]`{=tex}`\s*`{=tex}(\[A-Za-z0-9/+=.\_-\]{16,})"
    group: 1 severity: high confidence: medium min_entropy: 3.5
    ignore_case: true Notes:

id: unique rule ID pattern: Python-style regex group: which capture
group is the secret (default 0) min_entropy: optional filter for
high-entropy values ignore_case: add re.IGNORECASE (default true) Use
with CLI:

Bash

python secretscan.py scan . --rules .secretscan.yml python secretscan.py
rules --rules .secretscan.yml Tip: Use single quotes in YAML to avoid
excessive escaping.

Suppressions Inline ignore: add a comment on the same line: Example: \#
secret-scan: ignore File-level ignore: put secrets:ignore-file in the
first few lines of a file Baseline: .secrets.baseline.json stores hashed
fingerprints of accepted findings Desktop GUI (Tkinter) Launch:

Bash

python SecretScannerGui.py Main controls:

Path to scan: pick a local folder GitHub repo + Clone Repo: Accepts:
https URL, ssh URL, owner/repo, gh repo clone owner/repo, or git clone
... "Clone to": choose destination; shallow clone (depth 1) After
cloning, "Path to scan" auto-fills YAML config: "Add YAML...": browse
for .yml/.yaml; shows detector count if pyyaml is installed Baseline
file: Browse to pick an existing baseline, or leave empty to auto-use
`<scan path>`{=html}/.secrets.baseline.json when updating Options: Scan
staged (Git): only staged changes Include binaries: include binary files
Actions: Scan: run the scan Update Baseline: append current findings'
fingerprints Export JSON / Export SARIF Open Selected: open the selected
file in your OS Clear: clear results Results:

Table lists Detector, Severity, File, Line, Snippet (redacted) Details
pane shows message, location, entropy, fingerprint, and a few lines of
context Requirements for GUI:

Tkinter available pyyaml (optional) for YAML rules Git on PATH for Clone
Repo (private repos require your git credentials) Outputs JSON:

Contains metadata and redacted values (actual matches are not written)
Example: JSON

{ "tool": "secretscan", "version": "0.1.0", "count": 2, "findings": \[ {
"detector_id": "aws_access_key_id", "message": "Potential AWS Access Key
ID", "path": "src/app.py", "line": 42, "start": 15, "end": 35,
"severity": "high", "confidence": "high", "entropy": null,
"fingerprint": "...", "redacted": "AKI...123" } \] } SARIF:

Suitable for GitHub Code Scanning and similar platforms Severities
mapped to SARIF levels: critical/high → error, medium → warning, low →
note Tips and Troubleshooting CLI exits with SystemExit codes; debuggers
may show it as an exception. That's normal for CLIs. "Scan staged (Git)"
only works inside a Git repo; otherwise the scanner walks the
filesystem. YAML not loading? Install pyyaml and verify the path: pip
install pyyaml Git clone fails? Ensure git is installed and credentials
are configured for private repos. Tkinter missing on Linux? Install
python3-tk via your package manager. Security Notes Matches are redacted
in JSON/SARIF outputs Baseline stores hashed fingerprints, not raw
secrets Review and rotate any real secrets found Be mindful of scanning
and storing reports for sensitive repositories License Add a license
file if you plan to distribute (e.g., MIT).

Credits Built with Typer, Rich, Tkinter, and optional PyYAML.

text

If your UI doesn't have a download button: - Save manually: copy the
block above into a file named README.md in your project's root. - Or on
Windows PowerShell: - Create README.md, paste, and save in your editor
(Notepad/VS Code). - Or on macOS/Linux: - Use your editor or redirect
output: cat \> README.md and paste, then Ctrl+D.
