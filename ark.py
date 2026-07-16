#!/usr/bin/env python3
"""ark -- walk into a large codebase and save everything that matters
before you delete it.

A 200 GB project is usually three very different things wearing one folder:
  1. CODE           -> git has it; a .bundle file (or the remote) restores it
  2. RE-FETCHABLE   -> venvs, caches, model weights: the internet restores it
  3. IRREPLACEABLE  -> secrets, outputs, data, locally-trained weights:
                       NOTHING restores it. This is what ark saves.

ark scans the tree with git-awareness, classifies every file, and builds an
"ark" folder: git bundle(s) + uncommitted patch + every irreplaceable file
(structure preserved, so restore is a straight copy back) + a restore-hints
sheet + SHA-256 manifests to prove both the backup and any future rebuild.

    python ark.py scan   C:/BigProject                 # read-only report
    python ark.py plan   C:/BigProject                 # writes ark-plan.json
    python ark.py build  C:/BigProject --out D:/ark    # the actual salvage
    python ark.py verify D:/ark                        # backup still intact?
    python ark.py status C:/BigProject --ark D:/ark    # safe to delete yet?

Zero dependencies (stdlib only). Windows/macOS/Linux. Heuristics are honest:
anything ambiguous is SAVED and flagged for review, never silently skipped.
"""
import argparse, fnmatch, json, os, shutil, subprocess, sys, threading, time, uuid
from collections import deque
from pathlib import Path, PurePosixPath

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

GiB = 2 ** 30
ARK_VERSION = "1.0"

# ---------------------------------------------------------------- patterns ----
REFETCH_DIRS = {".venv", "venv", "env", "node_modules", "__pycache__",
                "site-packages", ".cache", ".mypy_cache", ".pytest_cache",
                ".ruff_cache", ".tox", ".eggs", "python_embeded", ".gradle",
                "target", ".next", ".nuxt", "dist-newstyle", ".terraform",
                "bower_components", ".parcel-cache", ".turbo"}
WEIGHT_EXTS = (".safetensors", ".ckpt", ".gguf", ".onnx", ".pt", ".pth", ".tflite")
WEIGHT_HOME = {"models", "weights", "checkpoints", "hub", "huggingface",
               "torch", "whisper", "diffusers"}          # dirs where weights = downloaded
MEDIA_EXTS = (".mp4", ".webm", ".mov", ".mkv", ".avi", ".wav", ".mp3", ".flac",
              ".ogg", ".m4a", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".tiff",
              ".psd", ".svg")
ARCHIVE_EXTS = (".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".iso")
MANIFEST_NAMES = ("requirements.txt", "pyproject.toml", "package.json", "setup.py",
                  "environment.yml", "Pipfile", "poetry.lock", "Cargo.toml",
                  "go.mod", "Gemfile", "Dockerfile", "docker-compose.yml")
SECRET_HINTS = ("secret", "credential", "oauth", "apikey", "api_key", "id_rsa",
                ".pem", ".env")

CAT_LABEL = {
    "tracked":        "git-tracked (the bundle carries it)",
    "vcs":            ".git internals (the bundle carries it)",
    "refetch":        "re-fetchable (venvs, caches, build junk)",
    "weights_refetch":"model weights in cache/models dirs (re-download)",
    "weights_local":  "weight files OUTSIDE model dirs -- likely trained HERE (saved)",
    "secrets":        "secrets & credentials (saved, never re-downloadable)",
    "outputs":        "media outputs -- renders, audio, images (saved)",
    "archives":       "archives (saved -- review)",
    "data":           "everything else git doesn't hold (saved)",
}
SAVE_CATS = ("secrets", "weights_local", "outputs", "archives", "data")


def human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024


# ---------------------------------------------------------------- git ---------
def _git(root, *args, check=False):
    r = subprocess.run(["git", "-C", str(root), *args],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()}")
    return r


def _git_z(root, *args):
    r = subprocess.run(["git", "-C", str(root), *args], capture_output=True)
    if r.returncode != 0:
        return []
    return [p for p in r.stdout.decode("utf-8", "replace").split("\0") if p]


def git_facts(root, log=print):
    """Everything ark needs to know about the repo's git state."""
    g = {"is_repo": False, "remotes": [], "branch": None, "ahead": None,
         "uncommitted": 0, "untracked_loose": [], "gitlinks": [], "nested_repos": []}
    if _git(root, "rev-parse", "--is-inside-work-tree").returncode != 0:
        return g, set(), set()
    g["is_repo"] = True
    g["branch"] = _git(root, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    g["remotes"] = sorted({ln.split()[1] for ln in
                           _git(root, "remote", "-v").stdout.splitlines() if len(ln.split()) > 1})
    up = _git(root, "rev-list", "--left-right", "--count", "@{upstream}...HEAD")
    if up.returncode == 0:
        behind, ahead = up.stdout.split()
        g["ahead"] = int(ahead)
    log("  git: reading index (ls-files) ...")
    tracked = set(_git_z(root, "ls-files", "-z"))
    loose = _git_z(root, "ls-files", "-z", "-o", "--exclude-standard")
    g["untracked_loose"] = loose                      # not ignored, not tracked: git clean kills these
    g["uncommitted"] = sum(1 for ln in _git(root, "status", "--porcelain").stdout.splitlines() if ln)
    # gitlinks (mode 160000) missing from .gitmodules = the clone-won't-restore-it landmine
    gitmodules = ""
    gm = Path(root) / ".gitmodules"
    if gm.exists():
        gitmodules = gm.read_text(encoding="utf-8", errors="replace")
    for ln in _git(root, "ls-files", "-s").stdout.splitlines():
        if ln.startswith("160000"):
            p = ln.split("\t", 1)[1]
            entry = {"path": p, "in_gitmodules": p in gitmodules}
            sub = _git(Path(root) / p, "remote", "-v")
            entry["origin"] = sub.stdout.split()[1] if sub.returncode == 0 and sub.stdout.split() else None
            g["gitlinks"].append(entry)
    return g, tracked, set(loose)


# ---------------------------------------------------------------- classify ----
def classify(rel_posix, name, size, tracked):
    p = rel_posix.lower()
    segs = set(p.split("/"))
    if ".git" in segs:
        return "vcs"
    if segs & REFETCH_DIRS:
        return "refetch"
    is_weight = name.endswith(WEIGHT_EXTS) or (name.endswith(".bin") and size >= 10 * 2**20)
    if is_weight:
        return "weights_refetch" if (segs & WEIGHT_HOME or "models--" in p) else "weights_local"
    low = name.lower()
    if any(h in low for h in SECRET_HINTS) and "tokeniz" not in low:
        if rel_posix not in tracked:                  # a tracked "secrets.example" is code
            return "secrets"
    if rel_posix in tracked:
        return "tracked"
    if low.endswith(MEDIA_EXTS):
        return "outputs"
    if low.endswith(ARCHIVE_EXTS):
        return "archives"
    return "data"


def scan(root, log=print):
    """Walk + classify the whole tree. Read-only. Returns the scan dict."""
    root = Path(root).resolve()
    t0 = time.time()
    log(f"ark scan: {root}")
    git, tracked, loose = git_facts(root, log)
    cats = {}                                          # cat -> [files, bytes]
    save_list, manifests, nested, big = [], [], [], []
    n = 0
    for dp, dns, fns in os.walk(root):
        d = Path(dp)
        if d != root and (d / ".git").exists():        # nested independent repo
            sub = _git(d, "remote", "-v")
            nested.append({"path": str(d.relative_to(root)).replace("\\", "/"),
                           "origin": sub.stdout.split()[1] if sub.stdout.split() else None})
        for fn in fns:
            fp = d / fn
            try:
                size = fp.stat().st_size
            except OSError:
                continue
            rel = str(fp.relative_to(root)).replace("\\", "/")
            cat = classify(rel, fn, size, tracked)
            c = cats.setdefault(cat, [0, 0]); c[0] += 1; c[1] += size
            if cat in SAVE_CATS:
                save_list.append({"p": rel, "s": size, "cat": cat,
                                  **({"loose": True} if rel in loose else {})})
            if fn in MANIFEST_NAMES and cat == "tracked":
                manifests.append(rel)
            if size >= 200 * 2**20:
                big.append({"p": rel, "s": size, "cat": cat})
            n += 1
            if n % 25000 == 0:
                log(f"  {n} files walked ({time.time()-t0:.0f}s)")
    save_bytes = sum(e["s"] for e in save_list)
    big.sort(key=lambda e: -e["s"])
    scan_d = {
        "ark_version": ARK_VERSION, "root": str(root), "files": n,
        "seconds": round(time.time() - t0, 1),
        "git": git, "nested_repos": nested,
        "categories": {k: {"files": v[0], "bytes": v[1], "label": CAT_LABEL.get(k, k)}
                       for k, v in sorted(cats.items(), key=lambda kv: -kv[1][1])},
        "save": {"files": len(save_list), "bytes": save_bytes},
        "save_list": save_list, "manifests": manifests, "biggest": big[:60],
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    log(f"  done: {n} files in {scan_d['seconds']}s -> save {len(save_list)} files / {human(save_bytes)}")
    return scan_d


# ---------------------------------------------------------------- plan --------
def plan(root, scan_d=None, exclude=(), log=print):
    """Turn a scan into an editable salvage plan (ark-plan.json beside the tool caller)."""
    scan_d = scan_d or scan(root, log)
    save = [e for e in scan_d["save_list"]
            if not any(fnmatch.fnmatch(e["p"], pat) for pat in exclude)]
    plan_d = {
        "ark_version": ARK_VERSION, "root": scan_d["root"], "created": scan_d["created"],
        "git": scan_d["git"], "nested_repos": scan_d["nested_repos"],
        "manifests": scan_d["manifests"],
        "skip_summary": {k: v for k, v in scan_d["categories"].items()
                         if k not in SAVE_CATS},
        "save": save,
        "save_bytes": sum(e["s"] for e in save),
        "exclude": list(exclude),
    }
    log(f"plan: {len(save)} files / {human(plan_d['save_bytes'])} to save"
        + (f" (excluded {len(scan_d['save_list']) - len(save)})" if exclude else ""))
    return plan_d


# ---------------------------------------------------------------- build -------
def _copy(src: Path, dst: Path):
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def build(root, out, plan_d=None, hash_source=False, log=print):
    """Execute the salvage: bundle + patch + irreplaceable copies + hints + manifests."""
    import capsule                                     # sibling module (sha-256 manifests)
    root, out = Path(root).resolve(), Path(out).resolve()
    if out == root or str(out).startswith(str(root) + os.sep):
        raise SystemExit("refusing: --out must be OUTSIDE the tree being salvaged")
    plan_d = plan_d or plan(root, log=log)
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    report = {"root": str(root), "out": str(out), "steps": {}}

    # 1. code: full git history as a single clonable file + uncommitted work as a patch
    if plan_d["git"]["is_repo"]:
        log("build 1/5: git bundle (all branches + tags)")
        bpath = out / "code" / (root.name + ".bundle")
        bpath.parent.mkdir(parents=True, exist_ok=True)
        _git(root, "bundle", "create", str(bpath), "--all", check=True)
        ok = _git(root, "bundle", "verify", str(bpath)).returncode == 0
        diff = _git(root, "diff", "HEAD").stdout
        if diff.strip():
            (out / "code" / "uncommitted.patch").write_text(diff, encoding="utf-8")
        report["steps"]["bundle"] = {"path": str(bpath), "verified": ok,
                                     "uncommitted_patch": bool(diff.strip())}
    else:
        log("build 1/5: no git repo here -- the irreplaceable copy IS the only copy")
        report["steps"]["bundle"] = None

    # 2. irreplaceables, structure preserved (restore = copy the folder back over the clone)
    save = plan_d["save"]
    total = sum(e["s"] for e in save)
    log(f"build 2/5: copying {len(save)} irreplaceable files ({human(total)})")
    done_b, errors = 0, []
    for i, e in enumerate(save):
        try:
            _copy(root / e["p"], out / "irreplaceable" / e["p"])
            done_b += e["s"]
        except OSError as ex:
            errors.append({"p": e["p"], "err": str(ex)})
        if (i + 1) % 500 == 0:
            log(f"  {i+1}/{len(save)} files, {human(done_b)}")
    report["steps"]["copy"] = {"files": len(save) - len(errors), "bytes": done_b,
                               "errors": errors[:50], "error_count": len(errors)}
    log(f"  copied {human(done_b)}, {len(errors)} errors")

    # 3. restore hints -- how the OTHER 90% comes back
    log("build 3/5: restore-hints.md")
    (out / "restore-hints.md").write_text(_hints_md(plan_d), encoding="utf-8")

    # 4. manifests: fingerprint of the SOURCE tree (prove any future rebuild), of the ark (prove transport)
    log(f"build 4/5: source-tree manifest (hash={'sha256' if hash_source else 'sizes only'})")
    capsule.build(root, out / "capsule", do_hash=hash_source, workers=6, log=log)
    log("build 5/5: ark self-check manifest (sha256 of the backup itself)")
    capsule.build(out, out / "selfcheck", do_hash=True, workers=6, log=log,
                  skip_dirs={str(out / "selfcheck")})
    (out / "ark-plan.json").write_text(json.dumps(plan_d, indent=1), encoding="utf-8")
    (out / "README.md").write_text(_readme_md(plan_d, report), encoding="utf-8")
    report["seconds"] = round(time.time() - t0, 1)
    (out / "ark-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    log(f"ARK BUILT -> {out}  ({report['seconds']}s)")
    return report


def _hints_md(p):
    L = ["# Restore hints -- the parts ark did NOT copy (because the internet has them)\n"]
    g = p["git"]
    if g["is_repo"]:
        L.append(f"## Code\n- Remote(s): {', '.join(g['remotes']) or 'NONE -- the .bundle in code/ is the ONLY copy'}")
        L.append(f"- Restore: `git clone <remote-or-code/{Path(p['root']).name}.bundle> restored/`")
        if g["ahead"]:
            L.append(f"- WARNING: {g['ahead']} commit(s) were never pushed -- the bundle has them, the remote does NOT.")
        if g["uncommitted"]:
            L.append(f"- {g['uncommitted']} uncommitted change(s) -> apply `code/uncommitted.patch` after cloning.")
    for gl in g.get("gitlinks", []):
        if not gl["in_gitmodules"]:
            L.append(f"\n## LANDMINE: `{gl['path']}` is a gitlink with NO .gitmodules entry")
            L.append(f"- A clone restores an EMPTY dir. Re-clone by hand: `git clone {gl['origin'] or '<find its origin>'} {gl['path']}`")
    if p["nested_repos"]:
        L.append("\n## Nested git repos inside the tree (not covered by the main bundle)")
        for nr in p["nested_repos"]:
            L.append(f"- `{nr['path']}` -> origin: {nr['origin'] or 'NO REMOTE (consider bundling it separately!)'}")
    if p["manifests"]:
        L.append("\n## Dependency manifests found (rebuild the environments)")
        for m in p["manifests"]:
            L.append(f"- `{m}`" + ("  -> `pip install -r`" if m.endswith("requirements.txt")
                     else "  -> `npm install`" if m.endswith("package.json") else ""))
    sk = p["skip_summary"]
    if "weights_refetch" in sk:
        w = sk["weights_refetch"]
        L.append(f"\n## Model weights skipped ({w['files']} files, {human(w['bytes'])})")
        L.append("- These sat in models/cache dirs, so they are re-downloadable in principle.")
        L.append("- VERIFY sources before deleting: the file NAMES are all in capsule/manifest.jsonl.gz.")
    L.append("\n## Verify a rebuild is byte-exact\n"
             "`python capsule.py <restored-tree> --verify capsule/manifest.jsonl.gz`\n"
             "(needs the manifest built with hashes: `ark build --hash-source`)")
    return "\n".join(L) + "\n"


def _readme_md(p, report):
    name = Path(p["root"]).name
    c = report["steps"].get("copy", {})
    return f"""# ark of {name}
Built {time.strftime('%Y-%m-%d %H:%M')} from `{p['root']}` by ark v{ARK_VERSION}.

| Piece | What it is |
|---|---|
| `code/{name}.bundle` | full git history -- `git clone` it like a remote |
| `code/uncommitted.patch` | work that was never committed (if present) |
| `irreplaceable/` | {c.get('files', 0)} files / {human(c.get('bytes', 0))} nothing can re-download -- structure preserved |
| `restore-hints.md` | how the re-fetchable rest (venvs, weights) comes back |
| `capsule/` | fingerprint of the ORIGINAL tree (verify a rebuild) |
| `selfcheck/` | fingerprint of THIS ark (verify the backup survived transport) |
| `ark-plan.json` | exactly what was saved and skipped, with reasons |

## Restore
1. `git clone code/{name}.bundle {name}` (or from the remote)
2. apply `code/uncommitted.patch` if present
3. copy `irreplaceable/*` over the clone root (structure matches)
4. follow `restore-hints.md` for envs + model weights
5. prove it: `python capsule.py <tree> --verify capsule/manifest.jsonl.gz`

## Is this ark itself intact?
`python ark.py verify {report['out']}`
"""


# ---------------------------------------------------------------- verify ------
def verify(ark_dir, log=print):
    """Check the ark's own selfcheck manifest -- did the backup survive transport?"""
    import capsule
    ark_dir = Path(ark_dir).resolve()
    m = ark_dir / "selfcheck" / "manifest.jsonl.gz"
    if not m.exists():
        raise SystemExit(f"no selfcheck manifest at {m}")
    return capsule.verify(ark_dir, m, log=log)


def status(root, ark_dir=None, log=print):
    """The safe-to-delete checklist."""
    root = Path(root).resolve()
    checks = []
    g, _, loose = git_facts(root, log=lambda *_: None)
    if g["is_repo"]:
        checks.append(("code pushed to a remote", bool(g["remotes"]) and g["ahead"] == 0,
                       f"remotes={g['remotes']} ahead={g['ahead']}"))
        checks.append(("no uncommitted changes", g["uncommitted"] == 0,
                       f"{g['uncommitted']} uncommitted"))
        checks.append(("no loose untracked files", not loose, f"{len(loose)} loose"))
        lm = [x for x in g["gitlinks"] if not x["in_gitmodules"]]
        checks.append(("no gitlink landmines", not lm, ", ".join(x["path"] for x in lm) or "clean"))
    else:
        checks.append(("git repo", False, "NOT a git repo -- the ark is the only copy"))
    if ark_dir:
        a = Path(ark_dir)
        checks.append(("ark exists", a.exists(), str(a)))
        checks.append(("ark has irreplaceable/", (a / "irreplaceable").exists(), ""))
        checks.append(("ark selfcheck manifest present", (a / "selfcheck" / "manifest.jsonl.gz").exists(),
                       "run `ark.py verify` for the full hash check"))
    else:
        checks.append(("ark built", False, "no --ark given"))
    ok = all(c[1] for c in checks)
    log(("SAFE TO DELETE: YES" if ok else "NOT SAFE TO DELETE YET") + f"  ({root})")
    for name, passed, detail in checks:
        log(f"  [{'ok' if passed else 'XX'}] {name}" + (f"  ({detail})" if detail else ""))
    return {"safe": ok, "checks": [{"name": n, "ok": o, "detail": d} for n, o, d in checks]}


# ---------------------------------------------------------------- jobs --------
class Job:
    def __init__(self, kind):
        self.id = uuid.uuid4().hex[:8]
        self.kind, self.state = kind, "running"
        self.log = deque(maxlen=4000)
        self.result, self.error = None, None
        self.started, self.ended = time.time(), None

    def snapshot(self, tail=40):
        return {"id": self.id, "kind": self.kind, "state": self.state,
                "log": list(self.log)[-tail:], "result": self.result,
                "error": self.error, "seconds": round((self.ended or time.time()) - self.started, 1)}


JOBS, _CURRENT = {}, {"job": None}


def run_job(kind, fn):
    cur = _CURRENT["job"]
    if cur and cur.state == "running":
        raise RuntimeError(f"job {cur.id} ({cur.kind}) still running")
    job = Job(kind)
    JOBS[job.id] = job
    _CURRENT["job"] = job

    def _run():
        try:
            job.result = fn(lambda m: job.log.append(str(m)))
            job.state = "done"
        except BaseException as ex:                    # noqa: BLE001
            job.error, job.state = str(ex), "error"
        job.ended = time.time()

    threading.Thread(target=_run, daemon=True).start()
    return job


# ---------------------------------------------------------------- cli ---------
def main():
    ap = argparse.ArgumentParser(description="Save everything that matters before deleting a codebase.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for c in ("scan", "plan", "build", "status"):
        s = sub.add_parser(c)
        s.add_argument("path")
        if c == "plan":
            s.add_argument("--exclude", nargs="*", default=[])
        if c == "build":
            s.add_argument("--out", default=None)
            s.add_argument("--hash-source", action="store_true",
                           help="sha-256 the WHOLE source tree (slow on huge trees; enables byte-exact rebuild proof)")
            s.add_argument("--exclude", nargs="*", default=[])
        if c == "status":
            s.add_argument("--ark", default=None)
        s.add_argument("--json", action="store_true")
    v = sub.add_parser("verify")
    v.add_argument("ark_dir")
    a = ap.parse_args()

    if a.cmd == "scan":
        d = scan(a.path)
        if a.json:
            d.pop("save_list")
            print(json.dumps(d, indent=1))
        else:
            _print_scan(d)
    elif a.cmd == "plan":
        d = plan(a.path, exclude=a.exclude)
        out = Path(a.path).resolve().name + ".ark-plan.json"
        Path(out).write_text(json.dumps(d, indent=1), encoding="utf-8")
        print(f"plan -> {out}  ({len(d['save'])} files / {human(d['save_bytes'])})")
    elif a.cmd == "build":
        out = a.out or str(Path(a.path).resolve().parent / (Path(a.path).resolve().name + "-ark"))
        build(a.path, out, plan(a.path, exclude=a.exclude), hash_source=a.hash_source)
    elif a.cmd == "verify":
        verify(a.ark_dir)
    elif a.cmd == "status":
        d = status(a.path, a.ark)
        if a.json:
            print(json.dumps(d, indent=1))


def _print_scan(d):
    print(f"\n{d['root']} -- {d['files']} files, scanned in {d['seconds']}s")
    print(f"{'category':18s} {'files':>9s} {'size':>10s}  meaning")
    for k, v in d["categories"].items():
        print(f"{k:18s} {v['files']:>9d} {human(v['bytes']):>10s}  {v['label']}")
    print(f"\nARK WOULD SAVE: {d['save']['files']} files / {human(d['save']['bytes'])}")
    g = d["git"]
    if g["is_repo"]:
        print(f"git: branch={g['branch']} remotes={g['remotes'] or 'NONE'} "
              f"ahead={g['ahead']} uncommitted={g['uncommitted']} loose_untracked={len(g['untracked_loose'])}")
        for gl in g["gitlinks"]:
            if not gl["in_gitmodules"]:
                print(f"LANDMINE gitlink w/o .gitmodules: {gl['path']} (origin: {gl['origin']})")
    for nr in d["nested_repos"]:
        print(f"nested repo: {nr['path']} -> {nr['origin'] or 'NO REMOTE'}")
    if d["biggest"]:
        print("\nbiggest files:")
        for e in d["biggest"][:12]:
            print(f"  {human(e['s']):>10s}  [{e['cat']}] {e['p']}")


if __name__ == "__main__":
    main()
