# OSS-CRS Compliance Scans

Two scripts that generate a reproducible body of evidence for introducing
[OSS-CRS](https://github.com/ossf/oss-crs) into an environment aligned to
NIST SP 800-171.

- **`oss-crs-static.sh`** analyzes the software at rest: source, dependencies,
  Dockerfiles, and pinned container images. No deployment required.
- **`oss-crs-runtime.sh`** observes a live OSS-CRS campaign: egress, container
  posture, syscall activity, exposed services, and host configuration. It never
  launches OSS-CRS; it brackets a campaign you run yourself.

Both produce neutral findings documents with counts read directly from tool
output, a provenance record, a control mapping, and a checksum manifest. Neither
assigns dispositions or makes recommendations; those belong to the submitting
organization and the reviewing authority.

## Getting the scripts

```bash
git clone https://github.com/HessdalenLens/OSS-CRS-Compliance-Scans.git
cd OSS-CRS-Compliance-Scans
```

---

## oss-crs-static.sh

Clones OSS-CRS at a pinned commit and runs the full static battery in one pass,
so every artifact describes the same tree.

### Requirements

Linux or macOS (x86_64 or arm64). On Windows, use WSL.

Must already be installed: `git`, `uv`, `python3`, `bash`.
Install `uv` with `curl -LsSf https://astral.sh/uv/install.sh | sh`.

The script installs the rest itself at pinned versions into a temporary
directory it removes afterward: pip-audit, bandit, semgrep, cyclonedx-bom,
gitleaks, hadolint, trivy.

Network access is required for tool installation, the repository clone,
semgrep's rule registry, and trivy's vulnerability database and image pulls.
Docker is not required.

### Usage

```bash
./oss-crs-static.sh [REPO_DIR] [COMMIT]
```

`REPO_DIR` is an existing checkout or a clone target (default `./oss-crs`).
`COMMIT` is the commit to pin (defaults to the value set in the script). Output
lands in `./oss-crs-package`.

```bash
# clone and scan the default pinned commit
./oss-crs-static.sh

# scan a specific commit in an existing checkout
./oss-crs-static.sh ./oss-crs 9823ec425b198ef8ea2c099446f0d92734ec45d0
```

### What it produces

| File | Contents |
|---|---|
| `OSS-CRS-OVERVIEW.md` | What OSS-CRS is, how it operates, container architecture, assessment scope, findings summary |
| `800-171-findings.md` | Per-tool findings and control mapping |
| `PROVENANCE.md` | Commit, tree hash, archive hash, dependency counts, tool versions |
| `CONSISTENCY-REPORT.txt` | Per-step status and structural checks |
| `SHA256SUMS.txt` | Checksum of every artifact |
| `requirements-all.txt`, `requirements-prod.txt` | Locked dependency trees, full and production-only |
| `pip-audit-all.json`, `pip-audit-prod.json` | Dependency CVE audits |
| `sbom-cyclonedx-1_6.json` | CycloneDX 1.6 SBOM |
| `bandit-report.json`, `semgrep-report.json` | Static analysis |
| `gitleaks-report.json` | Secrets scan across full git history |
| `hadolint-report.json` | Dockerfile lint |
| `full-scan.json`, `trivy-image-*.json` | Trivy filesystem and pinned-image scans |
| `container-image-inventory.txt` | Base images and pinned infrastructure digests |
| `LICENSE-MIT.txt` | Upstream license |

### Reproducibility

Everything is anchored to one commit. Verify the source archive hash with:

```bash
git archive --format=tar <commit> | sha256sum
```

The script refuses to certify a dirty working tree and records the state in
`PROVENANCE.md`. Tool versions are pinned in the script header; change them
deliberately, since a re-run reproduces only against the same versions.

---

## oss-crs-runtime.sh

Observes what the containers actually do while a campaign is running. This
closes the gap the static package declares: image scans describe what images
contain, not what containers do.

### Requirements

Root, Docker with a running daemon, `python3`, and `curl`. Network access is
required to pull the tool containers and install the host tools.

Pulled automatically as containers: Falco, Zeek, Docker Bench for Security,
OWASP ZAP.

Installed automatically at `start`, each independently so one unavailable
package cannot block the others: `tcpdump`, `nmap`, `trivy`, `oscap`, and SCAP
Security Guide content. The script resolves these per distribution, which
matters because the package names differ:

| Tool | Debian / Ubuntu | RHEL family |
|---|---|---|
| nmap | `nmap` | `nmap` |
| tcpdump | `tcpdump` | `tcpdump` |
| oscap | `libopenscap8` | `openscap-scanner` |
| SSG content | not packaged; downloaded from ComplianceAsCode releases | `scap-security-guide` |
| trivy | not packaged; installed from the vendor script | not packaged; installed from the vendor script |

Do not install these with a single combined `apt install` line. On Ubuntu,
`openscap-scanner` and `scap-security-guide` do not exist, and apt aborts the
whole transaction when any named package is unknown, so nothing gets installed
including the packages that were valid.

If a tool cannot be installed, the run continues and `RUNTIME-STATUS.txt`
records it as `unavailable`, with that section of the findings marked accordingly.

### Usage

Two steps, run as root:

```bash
sudo ./oss-crs-runtime.sh start      # begin capture and Falco, start the watcher
# run the OSS-CRS campaign as you normally would
sudo ./oss-crs-runtime.sh stop       # end capture, run Zeek and OpenSCAP, report
```

`start` launches a background watcher that polls for in-scope containers and
runs the collection automatically, so there is no step to time by hand. It
snapshots container posture every time the set changes, collects once the
population settles, and collects again if the population later grows, which
covers the case where OSS-CRS starts its infrastructure containers before the
CRS containers. At `stop`, every container observed during the campaign is
merged into a single posture record, so the evidence spans the whole run rather
than one moment in it.

Two additional verbs are available. `collect` runs a collection immediately,
which is useful with `NO_WATCH=1` or to force an extra pass. `report`
regenerates the findings document from existing outputs without re-running
anything.

Output lands in `./oss-crs-runtime`, overridable with `OSS_CRS_RUNTIME_OUT`.

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `OSS_CRS_SCOPE` | `oss-crs` | Substring marking in-scope containers, images, and networks |
| `OSS_CRS_RUNTIME_OUT` | `./oss-crs-runtime` | Output directory |
| `CAPTURE_IFACE` | `any` | Capture interface |
| `DOCKER_NET_POOL` | `172.16.0.0/12` | Address space the capture filter covers |
| `CAPTURE_FILTER` | generated | Overrides the generated BPF capture filter entirely |
| `POLL_INTERVAL` | `15` | Seconds between watcher polls |
| `SETTLE_POLLS` | `2` | Consecutive unchanged polls before a collection fires |
| `MAX_COLLECTS` | `3` | Cap on automatic collections per campaign |
| `NO_WATCH` | `0` | Set to `1` to disable the watcher and collect manually |
| `FALCO_IMAGE`, `ZEEK_IMAGE`, `BENCH_IMAGE`, `ZAP_IMAGE` | `:latest` | Tool images |
| `TRIVY_COMPLIANCE` | `docker-cis-1.6.0` | Trivy compliance spec |

Tool images default to `:latest` and their resolved digests are recorded in
`RUNTIME-PROVENANCE.md`. Pin those digests for a reproducible re-run.

### What it produces

| File | Contents |
|---|---|
| `RUNTIME-FINDINGS.md` | Observed findings and control mapping |
| `RUNTIME-PROVENANCE.md` | Observation window, host, tool images and digests, step status |
| `RUNTIME-STATUS.txt` | Per-step status |
| `capture.pcap`, `zeek/*.log` | Packet capture and derived Zeek logs |
| `falco-events.json` | Runtime syscall and behavior events |
| `containers-inspect.json`, `networks-inspect.json` | Container posture and network topology |
| `docker-bench.log` | CIS Docker Benchmark results |
| `nmap.xml` | Open ports and services on in-scope containers |
| `zap-*.json` | ZAP baseline results per HTTP endpoint |
| `trivy-compliance-*.json` | CIS Docker compliance per running image |
| `openscap-results.xml`, `openscap-report.html` | Host OS scan |
| `SHA256SUMS.txt` | Checksum of every artifact |

### Notes before you run it

Falco runs privileged with host mounts. On a hardened or monitored host this may
need a security exception arranged in advance, not during your campaign window.

Docker Bench assumes a systemd host with `containerd` and `runc` under
`/usr/bin`. OpenSCAP profile availability depends on the SCAP Security Guide
content your distribution ships; the script detects what is present and records
the profile it used. Every step is guarded, so a missing tool degrades that
section rather than failing the run, and the status file records exactly what
did not execute.

The packet capture is restricted by a BPF filter to Docker network address
space, so traffic on the host's own interfaces is not written to the pcap. The
filter is built at `start` from the subnets of existing Docker networks plus
`DOCKER_NET_POOL`, which covers networks OSS-CRS creates after the capture
begins. Container egress to external destinations is still recorded, because the
source address is inside a Docker subnet. If other containers run on the same
host during the window, their traffic is in scope of that filter; a dedicated
host gives the cleanest evidence. The exact filter used is recorded in
`RUNTIME-PROVENANCE.md`.

### Campaign timing

`oss-crs run` ends with an unconditional cleanup task that executes
`docker compose down -v --rmi local --remove-orphans`, removing the containers,
their volumes, and locally built images. There is no flag that disables this.
The watcher exists because of it: everything that requires live containers is
collected automatically while the campaign is running, so teardown does not cost
you any evidence.

The packet capture and Falco run continuously from `start` to `stop`, so the
whole campaign is recorded regardless of when a collection fires, including
everything after it. Run `stop` once the campaign and its teardown have
finished.

---

## Control mapping

Findings map to NIST SP 800-171 Rev 2 families. Static evidence covers
Configuration Management (3.4), Risk Assessment (3.11), System and
Communications Protection (3.13), and System and Information Integrity (3.14).
Runtime evidence adds Access Control (3.1) and Audit and Accountability (3.3).

Docker Bench and Trivy report against the CIS Docker Benchmark, which has a
published crosswalk to NIST SP 800-53; 800-171 derives from the 800-53 moderate
baseline. OpenSCAP reports against a SCAP Security Guide profile. The remaining
tools produce evidence mapped to control families in the generated documents.

Container-specific engineering guidance (NIST SP 800-190, DISA Container
Platform SRG) informs the risk model; the families above are the assessable
controls.

## Scope

These scripts generate evidence. They do not assign dispositions, assess
residual risk, or produce a change request. The following are supplied by the
submitting organization:

- System change request documentation, including System Security Plan updates
  and any forms required by the accrediting organization.
- A rollback or uninstall procedure for the software.
- Dispositions and residual-risk determinations for the reported findings.

## References

- [OSS-CRS repository](https://github.com/ossf/oss-crs)
- Chin et al., "OSS-CRS: Liberating AIxCC Cyber Reasoning Systems for Real-World
  Open-Source Security," [arXiv:2603.08566](https://arxiv.org/abs/2603.08566)
- Zhang et al., "SoK: DARPA's AI Cyber Challenge (AIxCC): Competition Design,
  Architectures, and Lessons Learned," [arXiv:2602.07666](https://arxiv.org/abs/2602.07666)
