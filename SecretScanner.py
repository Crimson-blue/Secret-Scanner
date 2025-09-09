
from __future__ import annotations
import re, os, sys, json, math, hashlib, subprocess, textwrap
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Iterable, Tuple
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich import box

try:
    import yaml  
except Exception:
    yaml = None

app = typer.Typer(add_completion=False)
console = Console()




@dataclass
class Finding:
    detector_id: str
    message: str
    path: str
    line: int
    start: int
    end: int
    match: str
    severity: str = "medium"     
    confidence: str = "medium"   
    entropy: Optional[float] = None
    fingerprint: Optional[str] = None

    def to_dict(self):
        data = asdict(self)
        
        data["redacted"] = _redact(self.match)
        data.pop("match", None)
        return data


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    probs = [c / len(s) for c in freq.values()]
    return -sum(p * math.log2(p) for p in probs)


def _context_line(text: str, pos: int) -> Tuple[int, int, int]:
    
    
    line_no = text.count("\n", 0, pos) + 1
    line_start = text.rfind("\n", 0, pos)
    if line_start == -1:
        line_start = -1
    start_col = pos - line_start
    return line_no, start_col, start_col


def _get_line(text: str, line_no: int) -> str:
    lines = text.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1]
    return ""


def _is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            chunk = f.read(4096)
        if b"\0" in chunk:
            return True
        return False
    except Exception:
        return False


def _redact(s: str) -> str:
    if len(s) <= 6:
        return "***"
    return s[:3] + "..." + s[-3:]


def _fingerprint(detector_id: str, path: str, secret_value: str, line: int) -> str:
    
    secret_hash = hashlib.sha256(secret_value.encode("utf-8", "ignore")).hexdigest()
    base = f"{detector_id}|{Path(path).as_posix()}|{line}|{secret_hash}"
    return hashlib.sha1(base.encode()).hexdigest()


def _git_repo_root(start: Path) -> Optional[Path]:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return Path(out.strip())
    except Exception:
        return None


def _git_ls_files(repo_root: Path) -> List[Path]:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo_root), "ls-files"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return [repo_root / p for p in out.splitlines() if p]
    except Exception:
        return []


def _git_staged_files(repo_root: Path) -> List[Path]:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo_root), "diff", "--name-only", "--cached"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return [repo_root / p for p in out.splitlines() if p]
    except Exception:
        return []


def _iter_files(
    base_path: Path,
    explicit_files: List[Path] | None = None,
    staged: bool = False,
    respect_git: bool = True,
) -> Iterable[Path]:
    SKIP_DIRS = {".git", "node_modules", "dist", "build", ".venv", "venv", ".idea", ".tox", ".mypy_cache", "__pycache__"}
    if explicit_files:
        for f in explicit_files:
            p = f if f.is_absolute() else (base_path / f)
            if p.is_file():
                yield p
        return

    repo_root = _git_repo_root(base_path) if respect_git else None
    if respect_git and repo_root:
        files = _git_staged_files(repo_root) if staged else _git_ls_files(repo_root)
        for f in files:
            if f.is_file():
                yield f
        return

    
    for root, dirs, files in os.walk(base_path):
        
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in files:
            p = Path(root) / fn
            yield p


def _line_has_inline_ignore(line: str) -> bool:
    
    
    return bool(re.search(r"(secret[-_\s]?scan|secrets)\s*:\s*ignore", line, re.IGNORECASE))





class BaseDetector:
    id: str
    message: str
    severity: str
    confidence: str

    def find(self, text: str, path: str) -> List[Finding]:
        raise NotImplementedError


class RegexDetector(BaseDetector):
    def __init__(
        self,
        id: str,
        pattern: str,
        message: str,
        severity: str = "medium",
        confidence: str = "medium",
        flags: int = re.MULTILINE,
        group: int = 0,
        min_entropy: Optional[float] = None,
    ):
        self.id = id
        self.pattern = re.compile(pattern, flags)
        self.message = message
        self.severity = severity
        self.confidence = confidence
        self.group = group
        self.min_entropy = min_entropy

    def find(self, text: str, path: str) -> List[Finding]:
        findings: List[Finding] = []
        for m in self.pattern.finditer(text):
            start = m.start(self.group)
            end = m.end(self.group)
            value = m.group(self.group)
            line_no, start_col, _ = _context_line(text, start)
            line_text = _get_line(text, line_no)
            if _line_has_inline_ignore(line_text):
                continue
            ent = shannon_entropy(value) if self.min_entropy is not None else None
            if self.min_entropy is not None and (ent or 0.0) < self.min_entropy:
                continue
            f = Finding(
                detector_id=self.id,
                message=self.message,
                path=path,
                line=line_no,
                start=start_col,
                end=start_col + (end - start),
                match=value,
                severity=self.severity,
                confidence=self.confidence,
                entropy=ent,
            )
            f.fingerprint = _fingerprint(self.id, path, value, line_no)
            findings.append(f)
        return findings


class EntropyDetector(BaseDetector):
    def __init__(
        self,
        id: str,
        message: str,
        token_pattern: str,
        min_length: int = 20,
        min_entropy: float = 4.0,
        severity: str = "medium",
        confidence: str = "low",
        flags: int = re.MULTILINE,
    ):
        self.id = id
        self.message = message
        self.token_re = re.compile(token_pattern, flags)
        self.min_len = min_length
        self.min_entropy = min_entropy
        self.severity = severity
        self.confidence = confidence

    def find(self, text: str, path: str) -> List[Finding]:
        findings: List[Finding] = []
        for m in self.token_re.finditer(text):
            value = m.group(0)
            if len(value) < self.min_len:
                continue
            ent = shannon_entropy(value)
            if ent < self.min_entropy:
                continue
            start = m.start()
            end = m.end()
            line_no, start_col, _ = _context_line(text, start)
            line_text = _get_line(text, line_no)
            if _line_has_inline_ignore(line_text):
                continue
            f = Finding(
                detector_id=self.id,
                message=self.message,
                path=path,
                line=line_no,
                start=start_col,
                end=start_col + (end - start),
                match=value,
                severity=self.severity,
                confidence=self.confidence,
                entropy=ent,
            )
            f.fingerprint = _fingerprint(self.id, path, value, line_no)
            findings.append(f)
        return findings


def builtin_detectors() -> List[BaseDetector]:
    detectors: List[BaseDetector] = [
        
        RegexDetector(
            id="aws_access_key_id",
            pattern=r"\bAKIA[0-9A-Z]{16}\b",
            message="Potential AWS Access Key ID",
            severity="high",
            confidence="high",
        ),
        RegexDetector(
            id="aws_secret_access_key",
            pattern=r"(?i)aws(.{0,20})?(secret|access)?.{0,5}['\"]?([A-Za-z0-9/+=]{40})['\"]?",
            message="Potential AWS Secret Access Key",
            severity="critical",
            confidence="medium",
            group=3,
            min_entropy=3.5,
        ),
        RegexDetector(
            id="github_token",
            pattern=r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
            message="Potential GitHub personal access token",
            severity="high",
            confidence="high",
        ),
        RegexDetector(
            id="slack_token",
            pattern=r"\bxox[baprs]-[A-Za-z0-9-]{10,48}\b",
            message="Potential Slack token",
            severity="high",
            confidence="medium",
        ),
        RegexDetector(
            id="private_key_block",
            pattern=r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
            message="Private key block",
            severity="critical",
            confidence="high",
        ),
        RegexDetector(
            id="generic_credential",
            pattern=r"(?i)\b(api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*['\"]?([A-Za-z0-9/\+=._-]{8,})['\"]?",
            message="Generic credential in config",
            severity="medium",
            confidence="low",
            group=2,
            min_entropy=3.0,
        ),
        
        EntropyDetector(
            id="high_entropy_base64",
            message="High-entropy base64-like string",
            token_pattern=r"[A-Za-z0-9+/]{20,}={0,2}",
            min_length=24,
            min_entropy=4.5,
            severity="medium",
            confidence="low",
        ),
        EntropyDetector(
            id="high_entropy_hex",
            message="High-entropy hex string",
            token_pattern=r"\b[0-9a-fA-F]{32,}\b",
            min_length=32,
            min_entropy=3.5,
            severity="medium",
            confidence="low",
        ),
    ]
    return detectors


def load_custom_detectors(rules_path: Optional[Path]) -> List[BaseDetector]:
    if not rules_path:
        return []
    if not rules_path.exists():
        console.print(f"[yellow]Custom rules file not found: {rules_path}[/yellow]")
        return []
    if yaml is None:
        console.print("[yellow]pyyaml not installed. Run: pip install pyyaml[/yellow]")
        return []
    with rules_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    dets: List[BaseDetector] = []
    for r in data.get("detectors", []):
        det_id = r["id"]
        pat = r["pattern"]
        msg = r.get("message", det_id)
        sev = r.get("severity", "medium")
        conf = r.get("confidence", "medium")
        min_ent = r.get("min_entropy")
        group = r.get("group", 0)
        flags = re.MULTILINE
        if r.get("ignore_case", True):
            flags |= re.IGNORECASE
        dets.append(
            RegexDetector(
                id=det_id,
                pattern=pat,
                message=msg,
                severity=sev,
                confidence=conf,
                flags=flags,
                group=group,
                min_entropy=min_ent,
            )
        )
    return dets





def scan_paths(
    base_path: Path,
    files: List[Path] | None = None,
    staged: bool = False,
    include_binaries: bool = False,
    custom_rules: Optional[Path] = None,
    baseline_path: Optional[Path] = None,
) -> List[Finding]:
    detectors = builtin_detectors() + load_custom_detectors(custom_rules)
    baseline = set()
    if baseline_path and baseline_path.exists():
        try:
            with baseline_path.open("r", encoding="utf-8") as f:
                b = json.load(f)
            baseline = set(b.get("fingerprints", []))
        except Exception:
            pass

    findings: List[Finding] = []
    seen = set()  
    to_scan = list(_iter_files(base_path, files, staged=staged, respect_git=True))
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning...", total=len(to_scan))
        for p in to_scan:
            progress.update(task, advance=1)
            if not p.is_file():
                continue
            if not include_binaries and _is_binary(p):
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            
            header = "\n".join(text.splitlines()[:5])
            if re.search(r"(secret[-_\s]?scan|secrets)\s*:\s*ignore-file", header, re.IGNORECASE):
                continue

            for det in detectors:
                for f in det.find(text, p.as_posix()):
                    if f.fingerprint and f.fingerprint in baseline:
                        continue
                    if f.fingerprint and f.fingerprint in seen:
                        continue
                    seen.add(f.fingerprint)
                    findings.append(f)

    return findings





def to_json(findings: List[Finding]) -> Dict:
    return {
        "tool": "secretscan",
        "version": "0.1.0",
        "count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }


def to_sarif(findings: List[Finding], repo_root: Optional[Path] = None) -> Dict:
    
    def level(sev: str) -> str:
        sev = sev.lower()
        if sev in ("critical", "high"):
            return "error"
        if sev == "medium":
            return "warning"
        return "note"

    
    rules = {}
    for f in findings:
        if f.detector_id not in rules:
            rules[f.detector_id] = {
                "id": f.detector_id,
                "name": f.detector_id,
                "shortDescription": {"text": f.message},
                "fullDescription": {"text": f.message},
                "helpUri": "https://example.com/secretscan/rules/" + f.detector_id,
                "defaultConfiguration": {"level": level(f.severity)},
            }

    results = []
    for f in findings:
        uri = f.path
        if repo_root:
            try:
                uri = Path(f.path).resolve().relative_to(repo_root.resolve()).as_posix()
            except Exception:
                uri = Path(f.path).as_posix()
        results.append({
            "ruleId": f.detector_id,
            "level": level(f.severity),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": f.line,
                        "startColumn": f.start,
                        "endColumn": f.end,
                    },
                }
            }],
            "fingerprints": {"secretFingerprint": f.fingerprint or ""},
            "properties": {
                "confidence": f.confidence,
                "entropy": f.entropy,
                "redacted": _redact(f.match),
            },
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "secretscan",
                    "informationUri": "https://example.com/secretscan",
                    "version": "0.1.0",
                    "rules": list(rules.values()),
                }
            },
            "results": results
        }]
    }
    return sarif


def print_pretty(findings: List[Finding]):
    if not findings:
        console.print("[green]No secrets found.[/green]")
        return
    tbl = Table(title=f"Potential secrets: {len(findings)}", box=box.SIMPLE_HEAVY)
    tbl.add_column("Detector", style="cyan", no_wrap=True)
    tbl.add_column("Severity", style="magenta")
    tbl.add_column("File:Line", style="yellow")
    tbl.add_column("Snippet", style="white")

    for f in findings:
        loc = f"{f.path}:{f.line}"
        snippet = _redact(f.match)
        tbl.add_row(f.detector_id, f.severity, loc, snippet)
    console.print(tbl)





def load_baseline(path: Path) -> Dict:
    if path.exists():
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    return {"fingerprints": []}


def save_baseline(path: Path, fingerprints: Iterable[str]):
    path.write_text(json.dumps({"fingerprints": list(sorted(set(fingerprints)))}, indent=2) + "\n", encoding="utf-8")





@app.command()
def scan(
    path: str = typer.Argument(".", help="Path to scan"),
    files: List[str] = typer.Option(None, "--file", "-f", help="Specific file(s) to scan", rich_help_panel="Scope"),
    staged: bool = typer.Option(False, "--staged", help="Scan staged files only"),
    include_binaries: bool = typer.Option(False, "--include-binaries", help="Scan binaries (off by default)"),
    format: str = typer.Option("pretty", "--format", "-F", help="Output format: pretty|json|sarif"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write report to file"),
    custom_rules: Optional[str] = typer.Option(None, "--rules", help="YAML file with custom detectors"),
    baseline: Optional[str] = typer.Option(".secrets.baseline.json", "--baseline", help="Baseline file (for suppression)"),
    update_baseline: bool = typer.Option(False, "--update-baseline", help="Append new findings to baseline and exit 0"),
    fail_on_findings: bool = typer.Option(True, "--fail/--no-fail", help="Exit non-zero if findings present"),
):
    """
    Scan a Git repo or folder for secrets using regex + entropy detectors.
    """
    base_path = Path(path).resolve()
    file_paths = [Path(p) for p in files] if files else None
    baseline_path = Path(baseline) if baseline else None
    rules_path = Path(custom_rules).resolve() if custom_rules else None

    findings = scan_paths(
        base_path=base_path,
        files=file_paths,
        staged=staged,
        include_binaries=include_binaries,
        custom_rules=rules_path,
        baseline_path=baseline_path,
    )

    if format == "pretty":
        print_pretty(findings)
    elif format == "json":
        data = to_json(findings)
        out = json.dumps(data, indent=2)
        if output:
            Path(output).write_text(out + "\n", encoding="utf-8")
        else:
            print(out)
    elif format == "sarif":
        repo_root = _git_repo_root(base_path)
        sarif = to_sarif(findings, repo_root=repo_root)
        out = json.dumps(sarif, indent=2)
        if output:
            Path(output).write_text(out + "\n", encoding="utf-8")
        else:
            print(out)
    else:
        console.print(f"[red]Unknown format: {format}[/red]")
        raise typer.Exit(2)

    if update_baseline and baseline_path:
        fps = [f.fingerprint for f in findings if f.fingerprint]
        if baseline_path.exists():
            current = load_baseline(baseline_path).get("fingerprints", [])
            fps.extend(current)
        save_baseline(baseline_path, fps)
        console.print(f"[green]Baseline updated:[/green] {baseline_path}")

    if fail_on_findings and findings and not update_baseline:
        raise typer.Exit(1)


@app.command("rules")
def rules_cmd(
    custom_rules: Optional[str] = typer.Option(None, "--rules", help="YAML file with custom detectors"),
):
    """
    List available detectors (built-in + custom).
    """
    dets = builtin_detectors() + load_custom_detectors(Path(custom_rules)) if custom_rules else builtin_detectors()
    tbl = Table(title=f"Detectors: {len(dets)}", box=box.SIMPLE_HEAVY)
    tbl.add_column("ID", style="cyan")
    tbl.add_column("Type", style="white")
    tbl.add_column("Severity", style="magenta")
    tbl.add_column("Confidence", style="green")
    for d in dets:
        typ = d.__class__.__name__
        sev = getattr(d, "severity", "medium")
        conf = getattr(d, "confidence", "medium")
        tbl.add_row(getattr(d, "id", "?"), typ, sev, conf)
    console.print(tbl)


@app.command("baseline")
def baseline_cmd(
    path: str = typer.Argument(".", help="Path to scan when creating baseline"),
    baseline: str = typer.Option(".secrets.baseline.json", "--baseline", help="Baseline file"),
    custom_rules: Optional[str] = typer.Option(None, "--rules", help="YAML file with custom detectors"),
):
    """
    Create or refresh a baseline file of current findings to suppress them.
    """
    base_path = Path(path).resolve()
    rules_path = Path(custom_rules) if custom_rules else None
    findings = scan_paths(base_path=base_path, custom_rules=rules_path, baseline_path=None)
    fps = [f.fingerprint for f in findings if f.fingerprint]
    save_baseline(Path(baseline), fps)
    console.print(f"[green]Baseline written:[/green] {baseline} (suppresses {len(fps)} findings)")


if __name__ == "__main__":
    app()