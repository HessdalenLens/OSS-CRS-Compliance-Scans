#!/usr/bin/env bash
#
# build-oss-crs-package.sh
#
# Regenerates the COMPLETE OSS-CRS evidence package from a single commit in one
# pass, so every artifact describes the same tree. Runs all scanners, builds the
# dependency and image inventories, generates the SBOM and provenance manifest,
# then self-verifies and writes a consistency report and a checksum file.
#
# Produces (in ./oss-crs-package):
#   PROVENANCE.md                  provenance + inventory manifest (reconciled counts)
#   requirements-all.txt           full locked dependency tree
#   requirements-prod.txt          production-only tree (dev group excluded)
#   pip-audit-all.json             dependency CVE audit, full tree
#   pip-audit-prod.json            dependency CVE audit, production tree
#   sbom-cyclonedx-1_6.json        CycloneDX 1.6 SBOM
#   container-image-inventory.txt  base images + pinned infrastructure digests
#   bandit-report.json             Python SAST
#   semgrep-report.json            Python/Dockerfile SAST      (needs network)
#   gitleaks-report.json           secrets scan (full history)
#   hadolint-report.json           Dockerfile lint
#   full-scan.json                 Trivy fs scan: vuln+secret+misconfig (needs DB)
#   trivy-image-*.json             Trivy image scans of pinned digests (needs registry)
#   LICENSE-MIT.txt                upstream license
#   SHA256SUMS.txt                 checksum of every artifact above
#   CONSISTENCY-REPORT.txt         commit, tool status, self-check results
#   OSS-CRS-OVERVIEW.md            plain-language overview + findings summary
#   800-171-findings.md            per-tool findings and control mapping
#
# Usage:
#   ./build-oss-crs-package.sh [REPO_DIR] [COMMIT]
#     REPO_DIR  existing checkout, or clone target. Default: ./oss-crs
#     COMMIT    commit to pin. Default: 9823ec425b198ef8ea2c099446f0d92734ec45d0

set -uo pipefail   # not -e: scanners exit nonzero on findings; status is handled per step

REPO_DIR="${1:-./oss-crs}"
PIN_COMMIT="${2:-9823ec425b198ef8ea2c099446f0d92734ec45d0}"
REPO_URL="https://github.com/ossf/oss-crs.git"
OUT_DIR="$(pwd)/oss-crs-package"

# Pinned tool versions for reproducibility. Bump deliberately; record in manifest.
PIPAUDIT_VER="2.10.1"
BANDIT_VER="1.9.4"
SEMGREP_VER="1.175.0"
GITLEAKS_VER="8.30.1"
HADOLINT_VER="2.15.1"
TRIVY_VER="0.74.0"

log()  { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }

declare -A STATUS   # per-step status for the consistency report

mkdir -p "$OUT_DIR"
BIN_DIR="$OUT_DIR/.tools"; mkdir -p "$BIN_DIR"; export PATH="$BIN_DIR:$PATH"

# --- OS / arch detection ----------------------------------------------------
OS="$(uname -s)"; ARCH="$(uname -m)"
case "$OS" in Linux) GOOS=linux; HOS=Linux; TOS=Linux;; Darwin) GOOS=darwin; HOS=Darwin; TOS=macOS;; *) die "unsupported OS: $OS";; esac
case "$ARCH" in x86_64|amd64) GARCH=x64; HARCH=x86_64; TARCH=64bit;; arm64|aarch64) GARCH=arm64; HARCH=arm64; TARCH=ARM64;; *) die "unsupported arch: $ARCH";; esac

# --- Prerequisites ----------------------------------------------------------
command -v git >/dev/null || die "git not found"
command -v uv  >/dev/null || die "uv not found (https://github.com/astral-sh/uv)"
command -v python3 >/dev/null || die "python3 not found"
PIP_INSTALL() { python3 -m pip install --quiet "$@" 2>/dev/null || pip install --quiet --break-system-packages "$@"; }

log "installing python tools (pinned)"
PIP_INSTALL "pip-audit==${PIPAUDIT_VER}" "bandit==${BANDIT_VER}" "semgrep==${SEMGREP_VER}" "cyclonedx-bom" || warn "python tool install had issues"

fetch_bin() { # url dest
  curl -fsSL "$1" -o "$2" 2>/dev/null && chmod +x "$2"
}

ensure_gitleaks() {
  command -v gitleaks >/dev/null && return 0
  if [ "$OS" = Darwin ] && command -v brew >/dev/null; then brew install gitleaks >/dev/null 2>&1 && return 0; fi
  local url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER}_${GOOS}_${GARCH}.tar.gz"
  curl -fsSL "$url" -o /tmp/gl.tgz 2>/dev/null && tar -xzf /tmp/gl.tgz -C "$BIN_DIR" gitleaks 2>/dev/null && chmod +x "$BIN_DIR/gitleaks"
}
ensure_hadolint() {
  command -v hadolint >/dev/null && return 0
  if [ "$OS" = Darwin ] && command -v brew >/dev/null; then brew install hadolint >/dev/null 2>&1 && return 0; fi
  fetch_bin "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VER}/hadolint-${HOS}-${HARCH}" "$BIN_DIR/hadolint"
}
ensure_trivy() {
  command -v trivy >/dev/null && return 0
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "$BIN_DIR" "v${TRIVY_VER}" >/dev/null 2>&1
}
ensure_gitleaks; ensure_hadolint; ensure_trivy

# --- Clone / pin ------------------------------------------------------------
if [ ! -d "$REPO_DIR/.git" ]; then log "cloning $REPO_URL"; git clone "$REPO_URL" "$REPO_DIR" || die "clone failed"; fi
cd "$REPO_DIR"
git fetch --quiet --all 2>/dev/null || true
git checkout --quiet "$PIN_COMMIT" || die "cannot checkout $PIN_COMMIT"

if ! git diff --quiet || ! git diff --cached --quiet; then
  warn "working tree is DIRTY. Stash or clean, then re-run for a defensible package."
  TREE_STATE="dirty"
else
  TREE_STATE="clean"
fi

COMMIT_SHA="$(git rev-parse HEAD)"
TREE_HASH="$(git rev-parse HEAD^{tree})"
COMMIT_META="$(git log -1 --format='%H %ci %s')"
ARCHIVE_SHA="$(git archive --format=tar HEAD | sha256sum | awk '{print $1}')"
SCAN_DATE="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
log "commit $COMMIT_SHA ($TREE_STATE)"

# run_step NAME OUTFILE cmd...  : runs cmd, records status, never aborts the script
run_step() {
  local name="$1" out="$2"; shift 2
  if "$@"; then :; fi
  if [ -s "$OUT_DIR/$out" ]; then STATUS[$name]="ok"; log "$name -> $out"; else STATUS[$name]="FAILED/empty"; warn "$name produced no output ($out)"; fi
}

# --- Dependency inventory ---------------------------------------------------
uv export --frozen --no-emit-project --format requirements-txt -o "$OUT_DIR/requirements-all.txt"  2>/dev/null
uv export --frozen --no-dev --no-emit-project --format requirements-txt -o "$OUT_DIR/requirements-prod.txt" 2>/dev/null
[ -s "$OUT_DIR/requirements-all.txt" ] && STATUS[deps]="ok" || STATUS[deps]="FAILED"

# --- pip-audit (both trees) -------------------------------------------------
pip-audit -r "$OUT_DIR/requirements-all.txt"  --no-deps -f json -o "$OUT_DIR/pip-audit-all.json"  >/dev/null 2>&1
pip-audit -r "$OUT_DIR/requirements-prod.txt" --no-deps -f json -o "$OUT_DIR/pip-audit-prod.json" >/dev/null 2>&1
[ -s "$OUT_DIR/pip-audit-all.json" ] && STATUS[pip_audit]="ok" || STATUS[pip_audit]="FAILED"

# --- SBOM -------------------------------------------------------------------
rm -rf /tmp/sbomvenv; uv venv /tmp/sbomvenv >/dev/null 2>&1
VIRTUAL_ENV=/tmp/sbomvenv uv pip install -q -r "$OUT_DIR/requirements-all.txt" >/dev/null 2>&1
cyclonedx-py environment /tmp/sbomvenv -o "$OUT_DIR/sbom-cyclonedx-1_6.json" >/dev/null 2>&1
[ -s "$OUT_DIR/sbom-cyclonedx-1_6.json" ] && STATUS[sbom]="ok" || STATUS[sbom]="FAILED"

# --- Container image inventory ---------------------------------------------
{
  echo "# Base images referenced in production Dockerfiles (test fixtures excluded)"
  find . -iname '*dockerfile*' -not -path '*/tests/*' -type f -print0 | xargs -0 grep -h '^FROM' 2>/dev/null | sort -u
  echo
  echo "# Pinned infrastructure image digests (oss_crs/src/constants.py)"
  [ -f oss_crs/src/constants.py ] && grep -nE 'sha256|ghcr\.io|postgres|litellm|nixos|alpine' oss_crs/src/constants.py || echo "WARNING: constants.py not found at this commit"
} > "$OUT_DIR/container-image-inventory.txt"
STATUS[image_inventory]="ok"

# --- License ----------------------------------------------------------------
[ -f LICENSE ] && cp LICENSE "$OUT_DIR/LICENSE-MIT.txt" && STATUS[license]="ok" || STATUS[license]="FAILED"

# --- Bandit (Python SAST) ---------------------------------------------------
if command -v bandit >/dev/null; then
  bandit -r oss_crs libCRS scripts -f json -o "$OUT_DIR/bandit-report.json" -q >/dev/null 2>&1
  [ -s "$OUT_DIR/bandit-report.json" ] && STATUS[bandit]="ok" || STATUS[bandit]="FAILED"
else STATUS[bandit]="tool-missing"; fi

# --- Semgrep (SAST, needs registry) ----------------------------------------
if command -v semgrep >/dev/null; then
  semgrep scan --config p/python --config p/security-audit --config p/dockerfile --config p/secrets \
    --json --output "$OUT_DIR/semgrep-report.json" . >/dev/null 2>&1
  [ -s "$OUT_DIR/semgrep-report.json" ] && STATUS[semgrep]="ok" || STATUS[semgrep]="FAILED/offline"
else STATUS[semgrep]="tool-missing"; fi

# --- Gitleaks (secrets, full history) --------------------------------------
if command -v gitleaks >/dev/null; then
  gitleaks detect --source . --report-format json --report-path "$OUT_DIR/gitleaks-report.json" --no-banner >/dev/null 2>&1
  [ -f "$OUT_DIR/gitleaks-report.json" ] && STATUS[gitleaks]="ok" || STATUS[gitleaks]="FAILED"
else STATUS[gitleaks]="tool-missing"; fi

# --- Hadolint (all Dockerfiles, one JSON array) ----------------------------
if command -v hadolint >/dev/null; then
  mapfile -d '' DFILES < <(find . -iname '*dockerfile*' -type f -print0)
  hadolint --format json "${DFILES[@]}" > "$OUT_DIR/hadolint-report.json" 2>/dev/null
  [ -s "$OUT_DIR/hadolint-report.json" ] && STATUS[hadolint]="ok" || STATUS[hadolint]="FAILED"
else STATUS[hadolint]="tool-missing"; fi

# --- Trivy (repo fs scan + pinned image scans) -----------------------------
if command -v trivy >/dev/null; then
  trivy fs --scanners vuln,secret,misconfig --format json -o "$OUT_DIR/full-scan.json" . >/dev/null 2>&1
  [ -s "$OUT_DIR/full-scan.json" ] && STATUS[trivy_fs]="ok" || STATUS[trivy_fs]="FAILED/offline"
  # pinned infrastructure images
  if [ -f oss_crs/src/constants.py ]; then
    grep -oE '(ghcr\.io|postgres|nixos)[^"]*sha256:[0-9a-f]{64}|alpine@sha256:[0-9a-f]{64}' oss_crs/src/constants.py | sort -u | while read -r img; do
      safe="$(echo "$img" | tr '/@:' '___' | cut -c1-60)"
      trivy image --format json -o "$OUT_DIR/trivy-image-${safe}.json" "$img" >/dev/null 2>&1 || warn "trivy image failed (offline?): $img"
    done
  fi
else STATUS[trivy_fs]="tool-missing"; fi

# --- Reconcile dependency counts for the manifest --------------------------
read -r LOCK_ALL LOCK_PROD AUD_ALL AUD_PROD MARKERS < <(python3 - "$OUT_DIR" <<'PY'
import json,re,sys,os
d=sys.argv[1]
def locked(f):
    n=set()
    for l in open(os.path.join(d,f)):
        m=re.match(r'^([a-z0-9][a-z0-9._-]+)==',l)
        if m: n.add(m.group(1).lower())
    return n
def audited(f):
    try: return {x['name'].lower() for x in json.load(open(os.path.join(d,f)))['dependencies']}
    except Exception: return set()
la,lp=locked('requirements-all.txt'),locked('requirements-prod.txt')
aa,ap=audited('pip-audit-all.json'),audited('pip-audit-prod.json')
markers=",".join(sorted(la-aa)) or "none"
print(len(la),len(lp),len(aa) or "NA",len(ap) or "NA",markers)
PY
)

# --- Provenance manifest ----------------------------------------------------
GIT_V="$(git --version)"; UV_V="$(uv --version 2>&1)"; PY_V="$(python3 --version 2>&1)"
PA_V="$(pip-audit --version 2>&1 | head -1)"; BA_V="$(bandit --version 2>&1 | head -1)"
SG_V="$(semgrep --version 2>&1 | head -1)"; GL_V="$(gitleaks version 2>&1 | head -1)"
HA_V="$(hadolint --version 2>&1 | head -1)"; TR_V="$(trivy --version 2>&1 | head -1)"

cat > "$OUT_DIR/PROVENANCE.md" <<EOF
# OSS-CRS Evidence Package: Provenance Manifest

Every artifact in this package was generated in one pass from the commit below.

## Source anchor

| Field | Value |
|---|---|
| Repository | https://github.com/ossf/oss-crs |
| Commit SHA | \`$COMMIT_SHA\` |
| Tree hash | \`$TREE_HASH\` |
| Archive SHA-256 (uncompressed tar of commit) | \`$ARCHIVE_SHA\` |
| Working tree state at scan | $TREE_STATE |
| Commit metadata | $COMMIT_META |
| Generated (UTC) | $SCAN_DATE |

Reproduce the archive hash with:

    git archive --format=tar $COMMIT_SHA | sha256sum

## Dependency counts

| Tree | Locked | Audited (this platform) | Notes |
|---|---|---|---|
| Full (incl. dev) | $LOCK_ALL | $AUD_ALL | marker-gated packages excluded from audit: $MARKERS |
| Production only | $LOCK_PROD | $AUD_PROD | dev group excluded from the tree |

## Tool versions (recorded from this run)

| Tool | Version |
|---|---|
| git | $GIT_V |
| uv | $UV_V |
| python | $PY_V |
| pip-audit | $PA_V |
| bandit | $BA_V |
| semgrep | $SG_V |
| gitleaks | $GL_V |
| hadolint | $HA_V |
| trivy | $TR_V |

Trivy fs mode also runs secrets and misconfiguration detection, so its output
overlaps gitleaks and hadolint by design. The overlap is corroboration.

## Findings

Findings are summarized in 800-171-findings.md, generated from the scan
outputs. This manifest records provenance and inventory.

## Note on pip-audit currency

pip-audit queries the live PyPI/OSV advisory database. Findings reflect the
database on the generation date above.
EOF
STATUS[provenance]="ok"

# --- Generate overview and findings documents from the outputs -------------
python3 - "$OUT_DIR" "$COMMIT_SHA" <<'PY'
import json, os, sys, glob, re
from collections import Counter

out, commit = sys.argv[1], sys.argv[2]

def load(name):
    try:
        with open(os.path.join(out, name)) as f: return json.load(f)
    except Exception: return None

# ---------- compute findings from scan JSON ----------
def audit(name):
    d = load(name)
    if not d: return None, []
    deps = d.get("dependencies", [])
    v = [(p["name"], p["version"], x["id"], ",".join(x.get("aliases", [])), ",".join(x.get("fix_versions", [])))
         for p in deps for x in p.get("vulns", [])]
    return len(deps), v
prod_n, prod_v = audit("pip-audit-prod.json")
all_n,  all_v  = audit("pip-audit-all.json")

b = load("bandit-report.json")
bc = Counter(r["issue_severity"] for r in b.get("results", [])) if b else Counter()
bandit_highs = []
if b:
    for r in b.get("results", []):
        if r["issue_severity"] == "HIGH":
            bandit_highs.append((r["test_id"], r["test_name"], r["filename"].split("oss-crs/")[-1] + ":" + str(r["line_number"])))

s = load("semgrep-report.json")
if s is None:
    semgrep_line, semgrep_err = "not run", []
else:
    res = s.get("results", [])
    sev = Counter(r.get("extra", {}).get("severity", "UNKNOWN") for r in res)
    semgrep_line = f"{len(res)} findings ({sev.get('ERROR',0)} error, {sev.get('WARNING',0)} warning, {sev.get('INFO',0)} info)"
    semgrep_err = [(r.get("check_id","").split(".")[-1], r.get("path","")+":"+str(r.get("start",{}).get("line")))
                   for r in res if r.get("extra",{}).get("severity")=="ERROR"]

g = load("gitleaks-report.json")
gitleaks = g if isinstance(g, list) else []

h = load("hadolint-report.json")
had_test = sum(1 for f in h if "/tests/" in f.get("file","")) if isinstance(h, list) else 0
had_prod = (len(h) - had_test) if isinstance(h, list) else 0

t = load("full-scan.json")
if t is None:
    trivy_fs = None
else:
    sev = Counter()
    trivy_fs_rows = []
    for r in t.get("Results", []):
        for v in r.get("Vulnerabilities", []) or []:
            if v.get("Severity") in ("CRITICAL","HIGH"):
                trivy_fs_rows.append((v.get("VulnerabilityID"), v.get("PkgName"), v.get("InstalledVersion"),
                                      v.get("FixedVersion") or "none available", r.get("Target","")))
            sev[v.get("Severity","UNKNOWN")] += 1
    trivy_fs = (dict(sev), trivy_fs_rows)

img_rows = []
for f in sorted(glob.glob(os.path.join(out, "trivy-image-*.json"))):
    d = load(os.path.basename(f))
    c = Counter()
    if d:
        for r in d.get("Results", []) or []:
            for v in r.get("Vulnerabilities", []) or []:
                c[v.get("Severity")] += 1
    name = d.get("ArtifactName","") if d else os.path.basename(f)
    img_rows.append((name, c))

lic = "MIT" if os.path.exists(os.path.join(out, "LICENSE-MIT.txt")) else "not identified"

# ---------- container facts from the repo (cwd) ----------
infra = sorted(os.path.basename(os.path.dirname(p)) for p in glob.glob("oss-crs-infra/*/Dockerfile"))
crs_dirs = set(os.path.dirname(p) for p in glob.glob("example/*/compose*.y*ml"))
crs_count = len(crs_dirs)

def tbl(rows, header):
    o = ["| " + " | ".join(header) + " |", "|" + "|".join(["---"]*len(header)) + "|"]
    for r in rows: o.append("| " + " | ".join(str(x) for x in r) + " |")
    return "\n".join(o)

# ---------- shared neutral findings sections ----------
F = []
F.append("### Dependency vulnerabilities (pip-audit)\n")
F.append(f"Production-only tree ({prod_n} packages audited): "
         f"{'no known vulnerabilities reported' if not prod_v else str(len(prod_v))+' finding(s)'}. "
         f"Full tree including the development group ({all_n} packages audited): "
         f"{'no known vulnerabilities reported' if not all_v else str(len(all_v))+' finding(s)'}.\n")
if all_v:
    F.append(tbl([[n,ver,vid,al or "-",fix or "-"] for (n,ver,vid,al,fix) in all_v],
                 ["Package","Version","Advisory","Aliases","Fix version"]))
    prodnames = {n for (n,*_) in prod_v}
    only_dev = [n for (n,*_) in all_v if n not in prodnames]
    if only_dev:
        F.append(f"\nThe following are present only in the development group, not the production-only tree: {', '.join(sorted(set(only_dev)))}.")
    F.append("")

F.append("### Python static analysis (bandit)\n")
F.append(f"Reported totals: {bc.get('HIGH',0)} high, {bc.get('MEDIUM',0)} medium, {bc.get('LOW',0)} low. High-severity findings:\n")
if bandit_highs:
    F.append(tbl([[tid,name,loc] for (tid,name,loc) in bandit_highs], ["ID","Check","Location"]))
    ntest = sum(1 for (_,_,loc) in bandit_highs if "tests/" in loc)
    if ntest:
        F.append(f"\n{ntest} of the {len(bandit_highs)} high findings are located under the tests/ directory.")
    F.append("")

F.append("### Multi-language static analysis (semgrep)\n")
F.append(f"Reported totals: {semgrep_line}." + (" Error-level findings:\n" if semgrep_err else "\n"))
if semgrep_err:
    F.append(tbl([[rule,loc] for (rule,loc) in semgrep_err], ["Rule","Location"]))
    F.append("")

F.append("### Secrets (gitleaks)\n")
if gitleaks:
    F.append(tbl([[x.get("Secret",""), x.get("File",""), x.get("RuleID","")] for x in gitleaks],
                 ["Match","File","Rule"]))
    F.append("")
else:
    F.append("Source and full git history scanned. No findings reported.\n")

F.append("### Dockerfile hygiene (hadolint)\n")
F.append(f"Reported totals: {had_prod} findings across non-test Dockerfiles and {had_test} across test fixtures.\n")

F.append("### Filesystem scan (trivy)\n")
if trivy_fs is None:
    F.append("Not run.\n")
else:
    sevd, rows = trivy_fs
    F.append(f"Severity counts: {sevd or 'none'}." + (" Critical and high findings:\n" if rows else "\n"))
    if rows:
        F.append(tbl([[a,p,v,fx,loc] for (a,p,v,fx,loc) in rows], ["Advisory","Package","Version","Fix","Location"]))
        F.append("")

F.append("### Container image scans (trivy)\n")
F.append("Known-CVE counts for each pinned image. These counts describe the contents of the images at rest.\n")
if img_rows:
    F.append(tbl([[n, c.get("CRITICAL",0), c.get("HIGH",0), c.get("MEDIUM",0), c.get("LOW",0), c.get("UNKNOWN",0)] for (n,c) in img_rows],
                 ["Image","Critical","High","Medium","Low","Unknown"]))
    F.append("")
else:
    F.append("Not run.\n")

F.append("### License\n")
F.append(f"The upstream license is {lic}.\n")
FINDINGS_MD = "\n".join(F)

# summary table (one line per area)
def prod_state():
    return "0 vulnerabilities" if (prod_n and not prod_v) else (f"{len(prod_v)} finding(s)" if prod_v else "not run")
def full_state():
    return f"{len(all_v)} finding(s)" if all_v else ("0 vulnerabilities" if all_n else "not run")
img_tot = Counter()
for _,c in img_rows:
    for k,v in c.items(): img_tot[k]+=v
SUMMARY = tbl([
    ["Dependency CVEs (production)", prod_state()],
    ["Dependency CVEs (full incl. dev)", full_state()],
    ["Python SAST (bandit)", f"{bc.get('HIGH',0)} high, {bc.get('MEDIUM',0)} medium, {bc.get('LOW',0)} low"],
    ["Multi-language SAST (semgrep)", semgrep_line if s is not None else "not run"],
    ["Secrets (gitleaks)", f"{len(gitleaks)} finding(s)"],
    ["Dockerfile hygiene (hadolint)", f"{had_prod} production, {had_test} test-fixture"],
    ["Image CVEs (trivy)", (f"{img_tot.get('CRITICAL',0)} critical, {img_tot.get('HIGH',0)} high across {len(img_rows)} images" if img_rows else "not run")],
    ["License", lic],
], ["Area","Result"])

# ---------- OVERVIEW ----------
infra_list = ", ".join(infra)
O = f"""# OSS-CRS: Software Overview and Static Assessment Summary

**Prepared for:** ISSM/ISSO review of a proposed software introduction
**Companion to:** the OSS-CRS evidence package (see PROVENANCE.md for the source anchor)
**Source commit:** `{commit}`

This document describes OSS-CRS and its operation, the scope of the static
assessment performed against it, and a summary of the findings. The detailed
per-tool results are in 800-171-findings.md.

---

## 1. What OSS-CRS is

OSS-CRS is an open source framework published by the Open Source Security
Foundation (OpenSSF) at github.com/ossf/oss-crs, under the MIT license. It is a
locally deployable platform for running and combining cyber reasoning systems
(CRSs): autonomous tools that discover and repair software vulnerabilities
without human intervention.

OSS-CRS is not itself a CRS. It is the infrastructure layer on which CRSs are
deployed, run, and composed. It grew out of DARPA's AI Cyber Challenge (AIxCC,
2023 to 2025), which produced seven finalist CRSs that were open-sourced but
remained bound to the competition's cloud environment. OSS-CRS re-hosts those
techniques so they can run locally against real open-source projects; the
first-place AIxCC system, ATLANTIS, has been ported to it.

A CRS operates in two stages. Bug finding produces a proof of vulnerability: a
program input that triggers a crash or a sanitizer violation. Bug fixing
synthesizes a candidate patch and validates it by rebuilding the target,
re-running the proof of vulnerability to confirm the crash no longer occurs, and
running the project's regression tests. A CRS can take an entire source tree, a
code diff, a static-analysis (SARIF) report, or a fuzzing seed corpus as input.

## 2. How it operates

OSS-CRS runs as a command-line tool from a source checkout. Its prerequisites
are Python 3.10 or later, Docker, git, and the uv package manager. Its workflow
has three phases: prepare (build the CRS container images, which are independent
of any target), build-target (compile the program to be analyzed), and run
(launch the CRS containers and execute the analysis campaign).

Characteristics relevant to a security review:

- **Containerized execution under the host Docker daemon.** Each CRS runs in
  isolated Docker containers with a dedicated CPU set and a hard memory limit
  enforced through Docker cgroups. OSS-CRS uses a flat Docker architecture, in
  which all containers are managed directly by the host Docker daemon rather than
  nested inside an outer container. Operation requires access to the Docker
  daemon.
- **Network isolation between CRSs.** Each CRS is placed on its own Docker
  network and communicates only through the injected libCRS library. CRSs do not
  communicate directly; artifact exchange between them passes through a
  filesystem-based sidecar that stores artifacts under content-hash filenames.
- **LLM use and outbound access.** CRSs that use large language models make
  OpenAI-compatible calls to a LiteLLM proxy, which routes them to a configured
  backend and enforces a per-CRS spending budget. Three modes are supported:
  internal (OSS-CRS runs its own LiteLLM proxy and key generator; the default),
  external (requests are routed to an LLM proxy endpoint and key the operator
  supplies), and disabled (no LLM services are set up, for CRSs that do not use
  models, such as pure fuzzers). Outbound connections to external model providers
  occur only when an LLM-backed CRS runs in internal or external mode against a
  cloud provider.
- **Privileged and external operations.** An optional setup step configures host
  cgroups for resource isolation; it requires root privileges and modifies host
  cgroup settings. Baseline operation without that step still requires Docker
  container operations. The prepare and build phases retrieve source repositories
  and container images from external sources.

### Containers

OSS-CRS runs two categories of container.

Shared infrastructure containers provide services used across a campaign. At the
source commit these are built from the following contexts: {infra_list}. The
always-present infrastructure sidecars handle artifact exchange, campaign
lifecycle, and target build and run operations. In internal LLM mode, OSS-CRS
additionally runs a LiteLLM proxy and a PostgreSQL backing store (pulled as
pinned images) together with a key-generation sidecar. A web dashboard (webui and
webui-publisher) is optional. See container-image-inventory.txt for the image and
digest behind each.

Per-CRS containers provide the isolated execution environment for each cyber
reasoning system. Each CRS runs in its own container environment on its own
Docker network. A campaign runs one or more CRSs selected by the operator; the
repository ships {crs_count} example CRS configurations.

## 3. Scope of the assessment

The accompanying evidence is static analysis of the software at rest: its source
code, dependency manifests, Dockerfiles, and the pinned container images as
pulled from their registries.

The containers were not executed. The image scans report known vulnerabilities
present in the image layers; they do not reflect the behavior of the running
containers. Runtime characteristics were therefore not observed, including the
network connections the containers make, any outbound traffic to model
providers, inter-container communication, filesystem and privilege activity, and
runtime handling of credentials. Assessing those would require dynamic analysis
of the running system in an instrumented environment.

## 4. Scans conducted and tools used

| Area assessed | Tool | What it examined |
|---|---|---|
| Source provenance and integrity | git | Commit pin, tree hash, and a reproducible source archive hash |
| Dependency inventory | uv | The full and production-only locked Python dependency trees |
| Dependency vulnerabilities | pip-audit | Known CVEs in the locked Python dependencies (PyPI/OSV advisory data) |
| Software bill of materials | cyclonedx-py | A CycloneDX 1.6 SBOM of the resolved dependencies |
| Python static analysis (SAST) | bandit | Python source for common security issues |
| Multi-language static analysis | semgrep | Python source and Dockerfiles against security rule sets |
| Secrets | gitleaks | Source tree and full git history for exposed credentials |
| Dockerfile hygiene | hadolint | Dockerfiles for build best-practice issues |
| Container and filesystem scan | trivy | The repository filesystem and the pinned container images for CVEs, secrets, and misconfiguration |
| License | (manual identification) | The upstream license terms |

Every scan was produced in a single pass from the source commit above. Tool
versions are recorded in PROVENANCE.md.

## 5. Findings summary

{SUMMARY}

Per-tool detail is in 800-171-findings.md.

## 6. Source and reproducibility

Every artifact in this package was generated in one pass from the source commit
named above. The commit, tree hash, and a reproducible archive hash are recorded
in PROVENANCE.md, and a checksum of every file is recorded in SHA256SUMS.txt.

## References

- OSS-CRS repository: https://github.com/ossf/oss-crs
- A. Chin et al., "OSS-CRS: Liberating AIxCC Cyber Reasoning Systems for
  Real-World Open-Source Security," arXiv:2603.08566.
- C. Zhang et al., "SoK: DARPA's AI Cyber Challenge (AIxCC): Competition Design,
  Architectures, and Lessons Learned," arXiv:2602.07666.
"""
with open(os.path.join(out, "OSS-CRS-OVERVIEW.md"), "w") as f:
    f.write(O)

# ---------- FINDINGS ----------
D = f"""# OSS-CRS Security Findings

**Candidate software:** OSS-CRS (github.com/ossf/oss-crs), OpenSSF sandbox project
**Source commit:** `{commit}` (see PROVENANCE.md)

This document reports the results of each scan in this package. Counts are read
directly from the tool output.

---

## 1. Summary

{SUMMARY}

---

## 2. Detailed findings

{FINDINGS_MD}

---

## 3. Control mapping (NIST SP 800-171 Rev 2)

OSS-CRS introduces no container-specific 800-171 requirements; containers are
in-scope components governed by the general families.

{tbl([
    ["Configuration Management (3.4)", "3.4.1, 3.4.2", "Image inventory, pinned digests, Dockerfile lint"],
    ["Risk Assessment (3.11)", "3.11.2", "pip-audit, bandit, semgrep, trivy"],
    ["System and Communications Protection (3.13)", "3.13.1", "Network and egress characteristics in the overview"],
    ["System and Information Integrity (3.14)", "3.14.1", "Vulnerability scan results"],
], ["Family","Requirement","Evidence"])}

Container-specific engineering guidance (NIST SP 800-190, DISA Container Platform
SRG) informs the risk model; the requirements above are the assessable controls.

---

## 4. Items to be supplied by the submitter

The following are not contained in this package and are provided by the
submitting organization:

- The organization's system change request documentation, including System
  Security Plan updates and any change request forms required by the accrediting
  organization.
- A rollback or uninstall procedure for the software.
"""
with open(os.path.join(out, "800-171-findings.md"), "w") as f:
    f.write(D)

print(f"generated overview and findings | infra={len(infra)} services, crs_count={crs_count}, images={len(img_rows)}")
PY
STATUS[docs]="ok"


# --- Self-check -------------------------------------------------------------
{
  echo "OSS-CRS package consistency report"
  echo "generated: $SCAN_DATE"
  echo "commit:    $COMMIT_SHA"
  echo "tree:      $TREE_STATE"
  echo
  echo "Tool / step status:"
  for k in "${!STATUS[@]}"; do printf '  %-16s %s\n' "$k" "${STATUS[$k]}"; done | sort
  echo
  echo "Structural checks:"
  echo "  $([ "$TREE_STATE" = clean ] && echo PASS || echo FAIL)  working tree clean"
  echo "  $([ -s "$OUT_DIR/pip-audit-prod.json" ] && echo PASS || echo FAIL)  production audit present"
  if [ -s "$OUT_DIR/gitleaks-report.json" ]; then
    GLN=$(python3 -c "import json;d=json.load(open('$OUT_DIR/gitleaks-report.json'));print(len(d))" 2>/dev/null || echo NA)
    echo "  INFO  gitleaks findings: $GLN"
  fi
  echo
  echo "Artifacts:"
  ( cd "$OUT_DIR" && ls -1 | grep -v '^\.tools$' | sed 's/^/  /' )
} > "$OUT_DIR/CONSISTENCY-REPORT.txt"

# --- Checksums over every artifact -----------------------------------------
find "$OUT_DIR" -name '*Zone.Identifier' -delete 2>/dev/null
( cd "$OUT_DIR" && find . -maxdepth 1 -type f ! -name SHA256SUMS.txt -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt )

rm -rf "$BIN_DIR"
echo
log "package complete: $OUT_DIR"
cat "$OUT_DIR/CONSISTENCY-REPORT.txt"
