# ⚓ ark

**Walk into a large codebase and save everything that matters before you delete it.**

A 200 GB project is usually three very different things wearing one folder:

| What | Who restores it | ark's move |
|---|---|---|
| **Code** | git | one `.bundle` file (full history, clonable offline) + `uncommitted.patch` |
| **Re-fetchable** — venvs, caches, downloaded model weights | the internet | *skipped*, listed in `restore-hints.md` |
| **Irreplaceable** — secrets, outputs, data, locally-trained weights | **nothing** | **copied, structure preserved** |

ark scans with git-awareness, classifies every file, salvages the irreplaceable
third, and writes SHA-256 manifests so both the backup and any future rebuild
can be **proven** byte-exact. Anything ambiguous is saved and flagged — never
silently skipped.

Stdlib only. No pip installs. Windows / macOS / Linux.

## CLI

```bash
python ark.py scan   C:/BigProject                  # read-only classification report
python ark.py plan   C:/BigProject                  # writes an editable ark-plan.json
python ark.py build  C:/BigProject --out D:/bp-ark  # the actual salvage
python ark.py verify D:/bp-ark                      # backup still intact?
python ark.py status C:/BigProject --ark D:/bp-ark  # SAFE TO DELETE: yes/no checklist
```

`build --hash-source` additionally fingerprints the *whole* source tree
(slow on huge trees) so a rebuilt tree can later be verified file-for-file:
`python capsule.py <rebuilt> --verify <ark>/capsule/manifest.jsonl.gz`.

## What a built ark looks like

```
BigProject-ark/
  README.md               generated runbook with the numbers
  code/BigProject.bundle  full git history — `git clone` it like a remote
  code/uncommitted.patch  work that was never committed (when present)
  irreplaceable/…         every irreplaceable file, original paths preserved
  restore-hints.md        how the skipped 90% comes back (manifests found,
                          weights to re-fetch, gitlink landmines, nested repos)
  capsule/                fingerprint of the ORIGINAL tree
  selfcheck/              fingerprint of THIS ark (transport/bit-rot check)
  ark-plan.json           exactly what was saved & skipped, with reasons
```

Restore = clone the bundle, apply the patch, copy `irreplaceable/*` over the
clone, follow the hints, verify with capsule.

## What the scanner actually catches

- **git truth**: remote + ahead/behind, uncommitted changes, *loose* untracked
  files (the ones `git clean` kills), and **gitlinks with no `.gitmodules`
  entry** — the submodule that a fresh clone silently restores as an empty dir.
- **nested git repos** inside the tree, each with (or alarmingly without) a remote.
- **weight files outside models/cache dirs** — a `.safetensors` in `data/…/out/`
  was probably *trained on this machine* and is irreplaceable; the same file
  under `models/` is a re-download. ark tells them apart.
- **secrets** by name heuristics (`.env`, `*secret*`, `*oauth*`, `*.pem`, …) —
  always saved, they are never re-downloadable.

## Web UI

```bash
python web.py        # http://127.0.0.1:8777
```

Scan → category table with size bars, git verdict, landmine warnings, biggest
files. Build / Verify / Safe-to-delete with a live job log.

## MCP (drive it from Claude)

`.mcp.json` ships in this repo — opening the folder in Claude Code exposes:

`ark_scan` · `ark_build` · `ark_verify` · `ark_job` (poll) · `ark_status`

Register globally instead with:
`claude mcp add ark -- python C:/Users/USER/ark/mcp_server.py`

## Honest limits

- The classifier is a **heuristic + git**. It errs toward saving, but you review
  `ark-plan.json` before trusting a delete. It cannot know a stray folder was
  precious if nothing about it says so.
- ark does not upload anywhere. It builds the folder; putting it on Drive /
  a second disk is on you (`selfcheck` lets you verify it after the trip).
- Model weights are only *listed*, never fetched — re-download tooling is
  project-specific (see the sibling `restore.py` pattern in AAAFlow).

---
Born from a real 200 GB deletion (AAAFlow, 2026-07): the first version of this
workflow was done by hand, found a broken gitlink the hard way, and recovered a
wiped project from render-cache metadata. ark is that experience, systematized.
Sibling project: [showcase-kit](https://github.com/VillAlfonso/showcase-kit)
(portfolio generator — *show* the work before you archive it).
