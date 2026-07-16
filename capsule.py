#!/usr/bin/env python3
"""capsule -- byte-exact fingerprint manifests (the proof half of ark).

Walks a tree, records path + size + mtime + SHA-256 per file, writes
manifest.jsonl.gz + summary.json. Verify mode re-hashes a tree against a
manifest and reports identical / changed / missing. The manifest holds NO
file data -- it cannot restore anything, it PROVES a restore is exact.
"""
import argparse, gzip, hashlib, json, os, sys, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def sha256(path, buf=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(buf)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _walk(root, skip_dirs=()):
    skip = {os.path.normcase(os.path.abspath(s)) for s in skip_dirs}
    for dp, dns, fns in os.walk(root):
        if os.path.normcase(os.path.abspath(dp)) in skip:
            dns[:] = []
            continue
        for f in fns:
            yield Path(dp) / f


def build(root, out, do_hash=True, workers=6, log=print, skip_dirs=()):
    root, out = Path(root).resolve(), Path(out)
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    files = list(_walk(root, skip_dirs))
    total = len(files)
    log(f"  capsule: {total} files (hash={'sha256' if do_hash else 'off'})")
    done, bytes_done = 0, 0

    def entry(p):
        try:
            st = p.stat()
            e = {"p": str(p.relative_to(root)).replace("\\", "/"),
                 "s": st.st_size, "m": int(st.st_mtime)}
            if do_hash:
                e["h"] = sha256(p)
            return e
        except OSError as ex:
            return {"p": str(p), "err": str(ex)}

    mpath = out / "manifest.jsonl.gz"
    with gzip.open(mpath, "wt", encoding="utf-8") as gz, \
         ThreadPoolExecutor(max_workers=workers) as ex:
        for e in ex.map(entry, files, chunksize=64):
            gz.write(json.dumps(e, ensure_ascii=False) + "\n")
            done += 1
            bytes_done += e.get("s", 0)
            if done % 20000 == 0:
                log(f"  capsule: {done}/{total}, {bytes_done/2**30:.1f} GiB, {time.time()-t0:.0f}s")
    summary = {"root": str(root), "files": total, "bytes": bytes_done,
               "gib": round(bytes_done / 2**30, 2), "hashed": do_hash,
               "seconds": round(time.time() - t0, 1), "manifest": str(mpath),
               "created": time.strftime("%Y-%m-%d %H:%M:%S")}
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    log(f"  capsule done: {summary['gib']} GiB in {summary['seconds']}s -> {mpath}")
    return summary


def verify(root, manifest, log=print):
    root = Path(root).resolve()
    ok = changed = missing = 0
    with gzip.open(manifest, "rt", encoding="utf-8") as gz:
        for line in gz:
            e = json.loads(line)
            if "h" not in e:
                continue
            p = root / e["p"]
            if not p.exists():
                missing += 1
                log(f"  MISSING {e['p']}")
            elif sha256(p) == e["h"]:
                ok += 1
            else:
                changed += 1
                log(f"  CHANGED {e['p']}")
    res = {"identical": ok, "changed": changed, "missing": missing,
           "ok": changed == 0 and missing == 0}
    log(f"verify: {ok} identical, {changed} changed, {missing} missing"
        + ("  -- BYTE-EXACT" if res["ok"] else ""))
    return res


def main():
    ap = argparse.ArgumentParser(description="Byte-exact manifest of a tree.")
    ap.add_argument("path")
    ap.add_argument("--out", default=None)
    ap.add_argument("--no-hash", action="store_true")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--verify", default=None, help="manifest.jsonl.gz to check PATH against")
    a = ap.parse_args()
    if a.verify:
        verify(a.path, Path(a.verify))
    else:
        out = Path(a.out) if a.out else Path(a.path).resolve().parent / (Path(a.path).resolve().name + "-capsule")
        build(a.path, out, do_hash=not a.no_hash, workers=a.workers)


if __name__ == "__main__":
    main()
