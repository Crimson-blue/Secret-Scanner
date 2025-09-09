import os, sys, json, io, contextlib, subprocess, threading, queue, re
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    import secretscan as sc
except Exception:
    try:
        import SecretScanner as sc
    except Exception as e:
        tk.Tk().withdraw()
        messagebox.showerror("Error", f"Could not import scanner module.\nPlace this file next to secretscan.py or SecretScanner.py.\n\n{e}")
        sys.exit(1)

try:
    import yaml
except Exception:
    yaml = None

def relpath_safe(p, base):
    try:
        return Path(p).resolve().relative_to(Path(base).resolve()).as_posix()
    except Exception:
        return str(Path(p).resolve())

def open_path(path):
    path = str(path)
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.run(["open", path], check=False)
        else:
            subprocess.run(["xdg-open", path], check=False)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open:\n{path}\n\n{e}")

def read_context_lines(path, line_no, radius=2):
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
        start = max(1, line_no - radius)
        end = min(len(lines), line_no + radius)
        out = []
        for i in range(start, end + 1):
            prefix = ">> " if i == line_no else "   "
            out.append(f"{prefix}{i:5d}: {lines[i-1]}")
        return "\n".join(out)
    except Exception as e:
        return f"(Could not read file for context: {e})"

def redact(val):
    try:
        return sc._redact(val)
    except Exception:
        if not val:
            return "***"
        return (val[:3] + "..." + val[-3:]) if len(val) > 6 else "***"

def do_scan(cfg):
    base = Path(cfg["path"]).resolve()
    rules = Path(cfg["rules"]).resolve() if cfg.get("rules") else None
    baseline = Path(cfg["baseline"]).resolve() if cfg.get("baseline") else None
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        findings = sc.scan_paths(
            base_path=base,
            files=None,
            staged=cfg.get("staged", False),
            include_binaries=cfg.get("include_binaries", False),
            custom_rules=rules if rules and rules.exists() else None,
            baseline_path=baseline if baseline and baseline.exists() else None,
        )
    repo_root = sc._git_repo_root(base) or base
    rows = []
    for f in findings:
        rel = relpath_safe(f.path, repo_root)
        snippet = redact(getattr(f, "match", ""))
        rows.append([f.detector_id, getattr(f, "severity", "medium"), rel, f.line, snippet])
    return {"findings": findings, "rows": rows, "repo_root": str(repo_root)}

def update_baseline(baseline_path, findings):
    fps = [getattr(f, "fingerprint", None) for f in findings if getattr(f, "fingerprint", None)]
    if Path(baseline_path).exists():
        try:
            existing = sc.load_baseline(Path(baseline_path)).get("fingerprints", [])
            fps.extend(existing)
        except Exception:
            pass
    sc.save_baseline(Path(baseline_path), fps)

def ensure_git():
    try:
        subprocess.run(["git", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
        return True
    except Exception:
        return False

def parse_repo_input(s):
    s = (s or "").strip().strip('"').strip("'")
    if not s:
        raise ValueError("Empty repo input")
    m = re.search(r"gh\s+repo\s+clone\s+([^\s]+)", s, flags=re.IGNORECASE)
    if m:
        s = m.group(1)
    m = re.search(r"git\s+clone\s+([^\s]+)", s, flags=re.IGNORECASE)
    if m:
        s = m.group(1)
    if s.startswith(("http://", "https://", "git@")) or "github.com" in s:
        spec = s
    elif re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", s):
        spec = f"https://github.com/{s}.git"
    else:
        raise ValueError("Unrecognized repo format")
    name = spec.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    name = name or "repo"
    return spec, name

def unique_dir(path: Path) -> Path:
    if not path.exists():
        return path
    base = path.name
    parent = path.parent
    i = 1
    while True:
        cand = parent / f"{base}-{i}"
        if not cand.exists():
            return cand
        i += 1

def clone_repo(spec, dest_base: Path, shallow=True):
    if not ensure_git():
        raise RuntimeError("git is not installed or not on PATH")
    dest_base.mkdir(parents=True, exist_ok=True)
    clone_url, repo_name = parse_repo_input(spec)
    target = unique_dir(dest_base / repo_name)
    args = ["git", "clone"]
    if shallow:
        args += ["--depth", "1"]
    args += [clone_url, str(target)]
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"Clone failed:\n{proc.stderr.strip() or proc.stdout.strip()}")
    return target

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secret Scanner (Tk GUI)")
        self.geometry("1180x760")
        self.minsize(900, 600)
        self.findings = []
        self.repo_root = str(Path.cwd())
        self.q = queue.Queue()
        self.var_path = tk.StringVar(value=str(Path.cwd()))
        self.var_rules = tk.StringVar(value="")
        self.var_rules_info = tk.StringVar(value="No YAML config loaded")
        self.var_baseline = tk.StringVar(value="")
        self.var_staged = tk.BooleanVar(value=False)
        self.var_bin = tk.BooleanVar(value=False)
        self.var_repo = tk.StringVar(value="")
        self.var_repo_dest = tk.StringVar(value=str(Path.cwd()))
        self.status_var = tk.StringVar(value="Idle")
        self.build_ui()

    def build_ui(self):
        frm_top = ttk.Frame(self, padding=8)
        frm_top.grid(row=0, column=0, sticky="nsew")
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)
        self.grid_rowconfigure(3, weight=0)
        self.grid_columnconfigure(0, weight=1)

        ttk.Label(frm_top, text="Path to scan", width=16).grid(row=0, column=0, sticky="w")
        ent_path = ttk.Entry(frm_top, textvariable=self.var_path)
        ent_path.grid(row=0, column=1, sticky="ew")
        ttk.Button(frm_top, text="Browse...", command=self.browse_path).grid(row=0, column=2, padx=(6,0))
        frm_top.grid_columnconfigure(1, weight=1)

        ttk.Label(frm_top, text="GitHub repo", width=16).grid(row=1, column=0, sticky="w", pady=(6,0))
        ent_repo = ttk.Entry(frm_top, textvariable=self.var_repo)
        ent_repo.grid(row=1, column=1, sticky="ew", pady=(6,0))
        self.btn_clone = ttk.Button(frm_top, text="Clone Repo", command=self.on_clone)
        self.btn_clone.grid(row=1, column=2, padx=(6,0), pady=(6,0))

        ttk.Label(frm_top, text="Clone to", width=16).grid(row=2, column=0, sticky="w")
        ent_dest = ttk.Entry(frm_top, textvariable=self.var_repo_dest)
        ent_dest.grid(row=2, column=1, sticky="ew")
        ttk.Button(frm_top, text="Browse...", command=self.browse_clone_dest).grid(row=2, column=2, padx=(6,0))

        ttk.Label(frm_top, text="YAML config", width=16).grid(row=3, column=0, sticky="w", pady=(6,0))
        ent_rules = ttk.Entry(frm_top, textvariable=self.var_rules)
        ent_rules.grid(row=3, column=1, sticky="ew", pady=(6,0))
        ttk.Button(frm_top, text="Add YAML...", command=self.add_yaml).grid(row=3, column=2, padx=(6,0), pady=(6,0))
        ttk.Label(frm_top, textvariable=self.var_rules_info, foreground="#555").grid(row=4, column=1, columnspan=2, sticky="w")

        ttk.Label(frm_top, text="Baseline file", width=16).grid(row=5, column=0, sticky="w", pady=(6,0))
        ent_base = ttk.Entry(frm_top, textvariable=self.var_baseline)
        ent_base.grid(row=5, column=1, sticky="ew", pady=(6,0))
        ttk.Button(frm_top, text="Browse...", command=self.browse_baseline).grid(row=5, column=2, padx=(6,0), pady=(6,0))

        frm_opts = ttk.Frame(frm_top)
        frm_opts.grid(row=6, column=0, columnspan=3, sticky="w", pady=(8,0))
        ttk.Checkbutton(frm_opts, text="Scan staged (Git)", variable=self.var_staged).grid(row=0, column=0, padx=(0,12))
        ttk.Checkbutton(frm_opts, text="Include binaries", variable=self.var_bin).grid(row=0, column=1)

        frm_btns = ttk.Frame(frm_top)
        frm_btns.grid(row=7, column=0, columnspan=3, sticky="w", pady=(8,0))
        self.btn_scan = ttk.Button(frm_btns, text="Scan", command=self.on_scan)
        self.btn_scan.grid(row=0, column=0, padx=(0,6))
        ttk.Button(frm_btns, text="Update Baseline", command=self.on_update_baseline).grid(row=0, column=1, padx=6)
        ttk.Button(frm_btns, text="Export JSON", command=self.on_export_json).grid(row=0, column=2, padx=6)
        ttk.Button(frm_btns, text="Export SARIF", command=self.on_export_sarif).grid(row=0, column=3, padx=6)
        ttk.Button(frm_btns, text="Open Selected", command=self.on_open_selected).grid(row=0, column=4, padx=6)
        ttk.Button(frm_btns, text="Clear", command=self.on_clear).grid(row=0, column=5, padx=6)
        ttk.Button(frm_btns, text="Exit", command=self.on_exit).grid(row=0, column=6, padx=6)

        ttk.Label(self, text="Results", padding=(8,0)).grid(row=1, column=0, sticky="w")
        frm_table = ttk.Frame(self, padding=8)
        frm_table.grid(row=2, column=0, sticky="nsew")
        self.tree = ttk.Treeview(frm_table, columns=("detector","severity","file","line","snippet"), show="headings", selectmode="browse")
        self.tree.heading("detector", text="Detector")
        self.tree.heading("severity", text="Severity")
        self.tree.heading("file", text="File")
        self.tree.heading("line", text="Line")
        self.tree.heading("snippet", text="Snippet")
        self.tree.column("detector", width=220, anchor="w")
        self.tree.column("severity", width=90, anchor="w")
        self.tree.column("file", width=600, anchor="w")
        self.tree.column("line", width=70, anchor="w")
        self.tree.column("snippet", width=400, anchor="w")
        vsb = ttk.Scrollbar(frm_table, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(frm_table, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frm_table.grid_rowconfigure(0, weight=1)
        frm_table.grid_columnconfigure(0, weight=1)
        self.tree.bind("<<TreeviewSelect>>", self.on_select_row)

        ttk.Label(self, text="Details", padding=(8,0)).grid(row=3, column=0, sticky="w")
        frm_details = ttk.Frame(self, padding=(8,0,8,8))
        frm_details.grid(row=4, column=0, sticky="nsew")
        self.text = tk.Text(frm_details, wrap="none", height=12, font=("Consolas", 10))
        det_vsb = ttk.Scrollbar(frm_details, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=det_vsb.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        det_vsb.grid(row=0, column=1, sticky="ns")
        frm_details.grid_rowconfigure(0, weight=1)
        frm_details.grid_columnconfigure(0, weight=1)

        status_bar = ttk.Frame(self, padding=(8,0,8,8))
        status_bar.grid(row=5, column=0, sticky="ew")
        ttk.Label(status_bar, textvariable=self.status_var).grid(row=0, column=0, sticky="w")

        self.grid_rowconfigure(4, weight=1)

    def browse_path(self):
        d = filedialog.askdirectory(initialdir=self.var_path.get() or str(Path.cwd()))
        if d:
            self.var_path.set(d)

    def browse_clone_dest(self):
        d = filedialog.askdirectory(initialdir=self.var_repo_dest.get() or str(Path.cwd()))
        if d:
            self.var_repo_dest.set(d)

    def add_yaml(self):
        f = filedialog.askopenfilename(filetypes=[("YAML","*.yml *.yaml")], initialdir=self.var_path.get() or str(Path.cwd()))
        if not f:
            return
        ext = Path(f).suffix.lower()
        if ext not in [".yml", ".yaml"]:
            messagebox.showerror("Invalid file", "Please select a .yml or .yaml file.")
            return
        self.var_rules.set(f)
        self.refresh_rules_info()

    def refresh_rules_info(self):
        path = self.var_rules.get().strip()
        if not path:
            self.var_rules_info.set("No YAML config loaded")
            return
        p = Path(path)
        if not p.exists():
            self.var_rules_info.set("YAML path not found")
            return
        if yaml is None:
            self.var_rules_info.set("pyyaml not installed; YAML will be ignored")
            return
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            dets = data.get("detectors", [])
            n = len(dets) if isinstance(dets, list) else 0
            self.var_rules_info.set(f"Loaded YAML: {n} detector(s)")
        except Exception as e:
            self.var_rules_info.set(f"Failed to read YAML: {e}")

    def browse_baseline(self):
        f = filedialog.askopenfilename(filetypes=[("JSON","*.json")], initialdir=self.var_path.get() or str(Path.cwd()))
        if f:
            self.var_baseline.set(f)

    def on_clone(self):
        spec = self.var_repo.get().strip()
        dest = self.var_repo_dest.get().strip() or str(Path.cwd())
        if not spec:
            messagebox.showinfo("Info", "Enter a GitHub repo (URL, SSH, owner/repo, or gh repo clone).")
            return
        if not Path(dest).exists():
            try:
                Path(dest).mkdir(parents=True, exist_ok=True)
            except Exception as e:
                messagebox.showerror("Error", f"Could not create destination:\n{dest}\n\n{e}")
                return
        self.status_var.set("Cloning repo...")
        self.btn_clone.config(state="disabled")
        t = threading.Thread(target=self.thread_clone, args=(spec, dest), daemon=True)
        t.start()
        self.after(150, self.check_queue)

    def thread_clone(self, spec, dest):
        try:
            target = clone_repo(spec, Path(dest))
            self.q.put(("clone_ok", str(target)))
        except Exception as e:
            self.q.put(("clone_err", str(e)))

    def on_scan(self):
        cfg = {
            "path": self.var_path.get() or ".",
            "rules": self.var_rules.get(),
            "baseline": self.var_baseline.get(),
            "staged": bool(self.var_staged.get()),
            "include_binaries": bool(self.var_bin.get()),
        }
        self.status_var.set("Scanning...")
        self.btn_scan.config(state="disabled")
        t = threading.Thread(target=self.thread_scan, args=(cfg,), daemon=True)
        t.start()
        self.after(150, self.check_queue)

    def thread_scan(self, cfg):
        try:
            result = do_scan(cfg)
            self.q.put(("scan_ok", result))
        except Exception as e:
            self.q.put(("scan_err", str(e)))

    def check_queue(self):
        try:
            kind, payload = self.q.get_nowait()
        except queue.Empty:
            self.after(150, self.check_queue)
            return
        if kind == "scan_ok" and isinstance(payload, dict):
            self.findings = payload["findings"]
            self.repo_root = payload["repo_root"]
            self.fill_table(payload["rows"])
            self.text.delete("1.0", "end")
            self.status_var.set(f"Scan complete. Findings: {len(payload['rows'])}")
            self.btn_scan.config(state="normal")
        elif kind == "scan_err":
            messagebox.showerror("Scan failed", str(payload))
            self.status_var.set("Scan failed")
            self.btn_scan.config(state="normal")
        elif kind == "clone_ok":
            self.var_path.set(payload)
            default_baseline = Path(payload) / ".secrets.baseline.json"
            if default_baseline.exists():
                self.var_baseline.set(str(default_baseline))
            self.status_var.set(f"Cloned: {payload}")
            self.btn_clone.config(state="normal")
        elif kind == "clone_err":
            messagebox.showerror("Clone failed", str(payload))
            self.status_var.set("Clone failed")
            self.btn_clone.config(state="normal")
        self.after(150, self.check_queue)

    def fill_table(self, rows):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for idx, row in enumerate(rows):
            self.tree.insert("", "end", iid=str(idx), values=row)

    def on_select_row(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        if idx < 0 or idx >= len(self.findings):
            return
        f = self.findings[idx]
        details = []
        details.append(f"Detector: {f.detector_id}")
        details.append(f"Message : {getattr(f,'message','')}")
        details.append(f"Severity: {getattr(f,'severity','')}    Confidence: {getattr(f,'confidence','')}")
        details.append(f"File    : {f.path}")
        details.append(f"Line    : {f.line}    Col: {getattr(f,'start','')}-{getattr(f,'end','')}")
        details.append(f"Entropy : {getattr(f,'entropy', None)}")
        details.append(f"FP      : {getattr(f,'fingerprint','')}")
        details.append("")
        details.append("Context:")
        details.append(read_context_lines(f.path, f.line))
        self.text.delete("1.0", "end")
        self.text.insert("1.0", "\n".join(details))

    def on_open_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Info", "Select a row first.")
            return
        idx = int(sel[0])
        if 0 <= idx < len(self.findings):
            f = self.findings[idx]
            open_path(f.path)

    def on_export_json(self):
        if not self.findings:
            messagebox.showinfo("Info", "No results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")], initialfile="secrets.json")
        if not path:
            return
        data = sc.to_json(self.findings)
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        self.status_var.set(f"Saved JSON: {path}")

    def on_export_sarif(self):
        if not self.findings:
            messagebox.showinfo("Info", "No results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".sarif", filetypes=[("SARIF","*.sarif *.json")], initialfile="secrets.sarif")
        if not path:
            return
        sarif = sc.to_sarif(self.findings, repo_root=Path(self.repo_root))
        Path(path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        self.status_var.set(f"Saved SARIF: {path}")

    def on_update_baseline(self):
        if not self.findings:
            messagebox.showinfo("Info", "No findings to baseline.")
            return
        path = self.var_baseline.get()
        if not path:
            path = str(Path(self.var_path.get() or ".") / ".secrets.baseline.json")
            self.var_baseline.set(path)
        try:
            update_baseline(Path(path), self.findings)
            self.status_var.set(f"Baseline updated: {path}")
            messagebox.showinfo("Baseline", f"Baseline updated:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update baseline:\n{e}")

    def on_clear(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.text.delete("1.0", "end")
        self.findings = []
        self.status_var.set("Cleared")

    def on_exit(self):
        self.destroy()

if __name__ == "__main__":
    App().mainloop()