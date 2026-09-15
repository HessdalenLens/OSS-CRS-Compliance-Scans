#!/usr/bin/env bash
#
# oss-crs-runtime.sh
#
# Runtime analysis of a live OSS-CRS campaign. Brackets a campaign the operator
# runs themselves; this script never launches OSS-CRS. It observes what the
# containers actually do, checks their posture while they are up, runs DAST
# against the HTTP surfaces, audits the host, and writes a neutral findings
# document with control mapping, a provenance record, and checksums.
#
# Verbs (run as root; each is a separate invocation):
#   start    begin host-level captures (packet capture, Falco), snapshot baseline
#   collect  run while the campaign is live: container posture, Docker Bench,
#            nmap, ZAP, Trivy compliance. Requires running containers.
#   stop     end captures, run Zeek over the capture and OpenSCAP on the host,
#            parse everything, write RUNTIME-FINDINGS.md, checksum
#   report   regenerate RUNTIME-FINDINGS.md from existing outputs only
#
# Typical operator sequence:
#   sudo ./oss-crs-runtime.sh start
#   <run the OSS-CRS campaign as usual>
#   sudo ./oss-crs-runtime.sh stop
#
# 'start' launches a background watcher that polls for in-scope containers and
# runs the collection automatically once their population settles, so collect
# does not have to be timed by hand. Set NO_WATCH=1 to disable the watcher and
# run 'collect' manually while containers are up.
#
# Produces (in ./oss-crs-runtime):
#   capture.pcap                 packet capture across all host interfaces
#   zeek/*.log                   Zeek logs derived from the capture (JSON lines)
#   falco-events.json            Falco runtime events (JSON lines)
#   containers-inspect.json      docker inspect of in-scope running containers
#   networks-inspect.json        docker network inspect of all networks
#   docker-bench.log / .json     CIS Docker Benchmark results
#   nmap.xml                     open ports/services on in-scope containers
#   zap-<target>.json            ZAP baseline results per HTTP endpoint
#   trivy-compliance-<img>.json  CIS Docker compliance per running image
#   openscap-results.xml/.html   host OS scan against the available SSG profile
#   RUNTIME-PROVENANCE.md        window, host, tool images and resolved digests
#   RUNTIME-STATUS.txt           per-step status
#   RUNTIME-FINDINGS.md          neutral findings and control mapping
#   SHA256SUMS.txt               checksum of every artifact
#
# Tool images default to :latest and their resolved digests are recorded in
# RUNTIME-PROVENANCE.md. Pin the digests there for a reproducible re-run.

set -uo pipefail

VERB="${1:-}"
OUT_DIR="${OSS_CRS_RUNTIME_OUT:-$(pwd)/oss-crs-runtime}"
STATE="$OUT_DIR/.state"
SCOPE_MATCH="${OSS_CRS_SCOPE:-oss-crs}"   # substring that marks in-scope containers/networks/images

FALCO_IMAGE="${FALCO_IMAGE:-falcosecurity/falco:latest}"
ZEEK_IMAGE="${ZEEK_IMAGE:-zeek/zeek:latest}"
BENCH_IMAGE="${BENCH_IMAGE:-docker/docker-bench-security:latest}"
ZAP_IMAGE="${ZAP_IMAGE:-zaproxy/zap-stable:latest}"
TRIVY_COMPLIANCE="${TRIVY_COMPLIANCE:-docker-cis-1.6.0}"
CAPTURE_IFACE="${CAPTURE_IFACE:-any}"
# Capture is restricted to Docker network address space so host traffic is never
# written to the pcap. The pool covers networks OSS-CRS creates mid-campaign.
# Set CAPTURE_FILTER to override the generated filter entirely.
DOCKER_NET_POOL="${DOCKER_NET_POOL:-172.16.0.0/12}"
# Watcher: polls for in-scope containers and collects automatically, so collect
# does not have to be timed by hand. Set NO_WATCH=1 to require manual collect.
POLL_INTERVAL="${POLL_INTERVAL:-15}"   # seconds between polls
SETTLE_POLLS="${SETTLE_POLLS:-2}"      # consecutive unchanged polls before heavy collection
NO_WATCH="${NO_WATCH:-0}"
# Host tools installed by this script live here and stay on PATH for every verb,
# so the watcher and stop see the same tools start installed.
BIN_DIR="$OUT_DIR/.tools"
mkdir -p "$BIN_DIR" 2>/dev/null || true
export PATH="$BIN_DIR:$PATH"
SSG_DIR="$OUT_DIR/.ssg"

log()  { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }
status() { mkdir -p "$STATE"; printf '%s=%s\n' "$1" "$2" >> "$STATE/status"; }
now()  { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

need_root()   { [ "$(id -u)" -eq 0 ] || die "run as root (captures, Falco, Docker Bench, and OpenSCAP require it)"; }
need_docker() { command -v docker >/dev/null && docker info >/dev/null 2>&1 || die "docker not available"; }

# digest of a pulled image, for provenance
img_digest() { docker inspect --format '{{index .RepoDigests 0}}' "$1" 2>/dev/null || echo "unresolved"; }

# --- Host tool acquisition --------------------------------------------------
# Installed once at 'start' so collect and stop find them. Package names differ
# by distribution: on Ubuntu the oscap binary ships in libopenscap8, and neither
# openscap-scanner nor scap-security-guide exists there. Each tool is installed
# independently so one unavailable package cannot abort the others.
pkg_install() {
  if command -v apt-get >/dev/null; then apt-get install -y -q "$@" >/dev/null 2>&1
  elif command -v dnf >/dev/null; then dnf install -y -q "$@" >/dev/null 2>&1
  elif command -v yum >/dev/null; then yum install -y -q "$@" >/dev/null 2>&1
  else return 1; fi
}

ensure_nmap() {
  command -v nmap >/dev/null && { status tool_nmap present; return 0; }
  pkg_install nmap
  command -v nmap >/dev/null && status tool_nmap installed || status tool_nmap unavailable
}

ensure_trivy() {
  command -v trivy >/dev/null && { status tool_trivy present; return 0; }
  # Trivy is not packaged in Ubuntu or Debian; use the vendor install script.
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b "$BIN_DIR" >/dev/null 2>&1
  command -v trivy >/dev/null && status tool_trivy installed || status tool_trivy unavailable
}

ensure_oscap() {
  if ! command -v oscap >/dev/null; then
    if command -v apt-get >/dev/null; then
      # Ubuntu and Debian ship the oscap binary in libopenscap8.
      pkg_install libopenscap8 || pkg_install openscap-scanner || true
    else
      pkg_install openscap-scanner || true
    fi
  fi
  command -v oscap >/dev/null && { status tool_oscap present; return 0; }
  status tool_oscap unavailable; return 1
}

# SCAP Security Guide content is packaged on RHEL-family but not on Ubuntu.
# Fetch datastreams from the ComplianceAsCode release if none are installed.
ensure_ssg() {
  ls /usr/share/xml/scap/ssg/content/*-ds.xml >/dev/null 2>&1 && { status tool_ssg present; return 0; }
  ls "$SSG_DIR"/*-ds.xml >/dev/null 2>&1 && { status tool_ssg cached; return 0; }
  command -v unzip >/dev/null || pkg_install unzip || true
  mkdir -p "$SSG_DIR"
  local url
  url=$(curl -sfL "https://api.github.com/repos/ComplianceAsCode/content/releases/latest" 2>/dev/null \
        | python3 -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit()
for a in d.get("assets",[]):
    n=a.get("name","")
    if n.startswith("scap-security-guide-") and n.endswith(".zip") and "doc" not in n:
        print(a.get("browser_download_url")); break' 2>/dev/null)
  [ -n "$url" ] || { status tool_ssg "no-release-asset"; return 1; }
  if curl -sfL "$url" -o "$SSG_DIR/ssg.zip" 2>/dev/null && command -v unzip >/dev/null; then
    unzip -o -j -q "$SSG_DIR/ssg.zip" '*-ds.xml' -d "$SSG_DIR" 2>/dev/null
    rm -f "$SSG_DIR/ssg.zip"
  fi
  ls "$SSG_DIR"/*-ds.xml >/dev/null 2>&1 && status tool_ssg downloaded || status tool_ssg unavailable
}

ensure_host_tools() {
  log "checking host tools (nmap, trivy, oscap, SSG content)"
  command -v apt-get >/dev/null && { apt-get update -qq >/dev/null 2>&1 || true; }
  ensure_nmap
  ensure_trivy
  if ensure_oscap; then ensure_ssg; else status tool_ssg skipped; fi
}

# BPF filter limiting the capture to Docker network address space, so traffic on
# the host's own interfaces is never written to the pcap. Unions the subnets of
# existing Docker networks with the configured pool, which covers networks
# OSS-CRS creates after the capture starts.
build_capture_filter() {
  [ -n "${CAPTURE_FILTER:-}" ] && { printf '%s' "$CAPTURE_FILTER"; return; }
  local subnets filt="" s
  subnets=$(docker network ls -q 2>/dev/null | xargs -r docker network inspect 2>/dev/null | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: d=[]
for n in d:
    for c in (n.get("IPAM",{}).get("Config") or []):
        s=c.get("Subnet")
        if s and ":" not in s: print(s)
' 2>/dev/null)
  subnets=$(printf '%s\n%s\n' "$subnets" "$DOCKER_NET_POOL" | sed '/^$/d' | sort -u)
  while read -r s; do
    [ -n "$s" ] || continue
    [ -n "$filt" ] && filt="$filt or "
    filt="${filt}net $s"
  done <<< "$subnets"
  printf '%s' "$filt"
}

# Polls for in-scope containers. Snapshots posture on every change, and triggers
# the full collection once the container population has been stable for
# SETTLE_POLLS polls. Runs in the background from 'start'; exits when 'stop'
# removes the started marker or creates the halt flag.
watch_loop() {
  mkdir -p "$STATE/snapshots"
  local prev="" cur ids stable=0 n=0 best=0 runs=0
  local max_runs="${MAX_COLLECTS:-3}"
  while [ ! -f "$STATE/halt" ] && [ -f "$STATE/started" ]; do
    mapfile -t ids < <(scoped_containers)
    if [ "${#ids[@]}" -gt 0 ]; then
      cur="$(printf '%s\n' "${ids[@]}" | sort | tr '\n' ' ')"
      if [ "$cur" != "$prev" ]; then
        docker inspect "${ids[@]}" > "$STATE/snapshots/$(date -u +%s)-$n.json" 2>/dev/null
        n=$((n+1)); stable=0; prev="$cur"
      else
        stable=$((stable+1))
      fi
      # Collect once the set is stable, and again if the population later grows,
      # so the heavy tools reflect the peak container count rather than the
      # infrastructure-only state that exists before the CRS containers start.
      if [ "$stable" -ge "$SETTLE_POLLS" ] && [ "${#ids[@]}" -gt "$best" ] && [ "$runs" -lt "$max_runs" ]; then
        echo "$(now) collecting: ${#ids[@]} containers stable for $stable polls (previous best $best)" >> "$STATE/watch.log"
        if cmd_collect >> "$STATE/watch.log" 2>&1; then
          best="${#ids[@]}"; runs=$((runs+1))
          status watch "collected-${best}-containers-run-${runs}"
        fi
      fi
    fi
    sleep "$POLL_INTERVAL"
  done
  echo "$(now) watcher exiting after $n snapshots, $runs collection(s)" >> "$STATE/watch.log"
  [ "$runs" -gt 0 ] || status watch "no-collection-triggered"
}

# Union every container observed across the campaign into containers-inspect.json,
# so posture covers containers that started and exited at different times.
merge_snapshots() {
  python3 - "$OUT_DIR" "$STATE" <<'PY'
import json, os, sys, glob
out, state = sys.argv[1], sys.argv[2]
seen = {}
files = sorted(glob.glob(os.path.join(state, "snapshots", "*.json")))
cur = os.path.join(out, "containers-inspect.json")
if os.path.exists(cur): files.append(cur)
for f in files:
    try: arr = json.load(open(f))
    except Exception: continue
    for c in arr if isinstance(arr, list) else []:
        cid = c.get("Id")
        if cid and cid not in seen: seen[cid] = c
if seen:
    json.dump(list(seen.values()), open(cur, "w"))
print(f"merged {len(files)} snapshot(s) into {len(seen)} distinct container(s)")
PY
}

# in-scope running container IDs: name, image, or an attached network contains SCOPE_MATCH
scoped_containers() {  docker ps -q | while read -r id; do
    docker inspect --format '{{.Id}} {{.Name}} {{.Config.Image}} {{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$id" 2>/dev/null
  done | grep -i "$SCOPE_MATCH" | awk '{print $1}'
}

# ============================================================================
cmd_start() {
  need_root; need_docker
  mkdir -p "$OUT_DIR" "$STATE" "$OUT_DIR/zeek" "$BIN_DIR"
  [ -f "$STATE/started" ] && die "already started; run 'stop' first or remove $STATE"
  if ! command -v tcpdump >/dev/null; then
    command -v apt-get >/dev/null && { apt-get update -qq >/dev/null 2>&1 || true; }
    pkg_install tcpdump || true
  fi
  command -v tcpdump >/dev/null || die "tcpdump not found and could not be installed"
  ensure_host_tools

  now > "$STATE/started"
  hostname > "$STATE/host"
  uname -srmo > "$STATE/uname"
  log "baseline snapshot"
  docker ps --no-trunc --format '{{json .}}' > "$OUT_DIR/baseline-ps.json" 2>/dev/null
  docker network ls --format '{{json .}}' > "$OUT_DIR/baseline-networks.json" 2>/dev/null

  CAP_FILTER="$(build_capture_filter)"
  [ -n "$CAP_FILTER" ] || die "could not build a capture filter; set CAPTURE_FILTER explicitly"
  printf '%s' "$CAP_FILTER" > "$STATE/capture.filter"
  log "starting packet capture on '$CAPTURE_IFACE' restricted to Docker networks"
  log "filter: $CAP_FILTER"
  nohup tcpdump -i "$CAPTURE_IFACE" -n -s 0 -U -w "$OUT_DIR/capture.pcap" $CAP_FILTER >"$STATE/tcpdump.log" 2>&1 &
  echo $! > "$STATE/tcpdump.pid"
  sleep 1; kill -0 "$(cat "$STATE/tcpdump.pid")" 2>/dev/null && status capture started || { status capture FAILED; warn "tcpdump did not start; see $STATE/tcpdump.log"; }

  log "starting Falco ($FALCO_IMAGE)"
  docker pull -q "$FALCO_IMAGE" >/dev/null 2>&1 || warn "could not pull $FALCO_IMAGE"
  docker rm -f oss-crs-runtime-falco >/dev/null 2>&1
  if docker run -d --name oss-crs-runtime-falco --privileged \
      -v /var/run/docker.sock:/host/var/run/docker.sock \
      -v /proc:/host/proc:ro -v /etc:/host/etc:ro \
      -v "$OUT_DIR":/out \
      "$FALCO_IMAGE" falco \
        -o json_output=true \
        -o file_output.enabled=true -o file_output.keep_alive=true \
        -o file_output.filename=/out/falco-events.json >/dev/null 2>&1; then
    status falco started; img_digest "$FALCO_IMAGE" > "$STATE/falco.digest"
  else
    status falco FAILED; warn "Falco container did not start"
  fi
  if [ "$NO_WATCH" = "1" ]; then
    status watch disabled
    log "started at $(cat "$STATE/started"). Watcher disabled; run 'collect' while containers are up, then 'stop'."
  else
    rm -f "$STATE/halt"
    OSS_CRS_RUNTIME_OUT="$OUT_DIR" OSS_CRS_SCOPE="$SCOPE_MATCH" \
      nohup "$(readlink -f "$0")" __watch >>"$STATE/watch.log" 2>&1 &
    echo $! > "$STATE/watch.pid"
    sleep 1
    if kill -0 "$(cat "$STATE/watch.pid")" 2>/dev/null; then
      status watch started
      log "started at $(cat "$STATE/started"). Watcher polling every ${POLL_INTERVAL}s; run the campaign, then 'stop'."
    else
      status watch FAILED
      warn "watcher did not start; run 'collect' manually while containers are up"
    fi
  fi
}

# ============================================================================
cmd_collect() {
  need_root; need_docker
  [ -f "$STATE/started" ] || die "not started; run 'start' first"
  now > "$STATE/collected"
  mapfile -t IDS < <(scoped_containers)
  if [ "${#IDS[@]}" -eq 0 ]; then
    warn "no running containers match '$SCOPE_MATCH'; snapshotting all running containers"
    mapfile -t IDS < <(docker ps -q)
  fi
  [ "${#IDS[@]}" -gt 0 ] || die "no running containers to collect from; is the campaign up?"
  log "in-scope running containers: ${#IDS[@]}"

  log "container posture snapshot"
  docker inspect "${IDS[@]}" > "$OUT_DIR/containers-inspect.json" 2>/dev/null && status inspect ok || status inspect FAILED
  docker network ls -q | xargs -r docker network inspect > "$OUT_DIR/networks-inspect.json" 2>/dev/null && status networks ok || status networks FAILED

  log "Docker Bench for Security ($BENCH_IMAGE)"
  docker pull -q "$BENCH_IMAGE" >/dev/null 2>&1
  if docker run --rm --net host --pid host --userns host --cap-add audit_control \
      -e DOCKER_CONTENT_TRUST="${DOCKER_CONTENT_TRUST:-}" \
      -v /etc:/etc:ro -v /lib/systemd/system:/lib/systemd/system:ro \
      -v /usr/bin/containerd:/usr/bin/containerd:ro -v /usr/bin/runc:/usr/bin/runc:ro \
      -v /usr/lib/systemd:/usr/lib/systemd:ro -v /var/lib:/var/lib:ro \
      -v /var/run/docker.sock:/var/run/docker.sock:ro \
      -v "$OUT_DIR":/out --label docker_bench_security \
      "$BENCH_IMAGE" -b -l /out/docker-bench.log >/dev/null 2>&1; then
    status docker_bench ok; img_digest "$BENCH_IMAGE" > "$STATE/bench.digest"
  else
    [ -s "$OUT_DIR/docker-bench.log" ] && status docker_bench ok || status docker_bench FAILED
  fi

  # collect container IPs and published host ports for scanning
  python3 - "$OUT_DIR" <<'PY'
import json,sys,os
out=sys.argv[1]
ips=set(); http=[]
try:
    for c in json.load(open(os.path.join(out,"containers-inspect.json"))):
        name=c.get("Name","").lstrip("/")
        for net,v in (c.get("NetworkSettings",{}).get("Networks") or {}).items():
            ip=v.get("IPAddress")
            if ip: ips.add(ip)
            for p in (c.get("NetworkSettings",{}).get("Ports") or {}):
                port=p.split("/")[0]
                if ip and port in ("80","8080","8000","4000","3000","5000","8443","443"):
                    http.append((name,net,ip,port))
except Exception as e:
    pass
open(os.path.join(out,".state","scan-ips"),"w").write("\n".join(sorted(ips)))
open(os.path.join(out,".state","http-targets"),"w").write("\n".join(f"{n}|{net}|{ip}|{p}" for n,net,ip,p in sorted(set(http))))
print(f"scan targets: {len(ips)} container IPs, {len(set(http))} HTTP candidates")
PY

  log "nmap service scan of in-scope containers"
  if command -v nmap >/dev/null && [ -s "$STATE/scan-ips" ]; then
    nmap -sT -sV -Pn -T4 -oX "$OUT_DIR/nmap.xml" -iL "$STATE/scan-ips" >/dev/null 2>&1 && status nmap ok || status nmap FAILED
  else
    status nmap "tool-missing-or-no-targets"
  fi

  log "ZAP baseline against HTTP endpoints"
  docker pull -q "$ZAP_IMAGE" >/dev/null 2>&1
  ZAP_RAN=0
  while IFS='|' read -r name net ip port; do
    [ -n "$ip" ] || continue
    safe="$(echo "${name}_${port}" | tr -c 'A-Za-z0-9_-' '_')"
    if docker run --rm --network "$net" -v "$OUT_DIR":/zap/wrk:rw "$ZAP_IMAGE" \
        zap-baseline.py -t "http://$ip:$port" -J "zap-${safe}.json" -I >/dev/null 2>&1; then
      ZAP_RAN=$((ZAP_RAN+1))
    elif [ -s "$OUT_DIR/zap-${safe}.json" ]; then
      ZAP_RAN=$((ZAP_RAN+1))   # baseline exits nonzero on warnings but still writes the report
    fi
  done < "$STATE/http-targets"
  if [ "$ZAP_RAN" -gt 0 ]; then status zap ok; img_digest "$ZAP_IMAGE" > "$STATE/zap.digest"
  elif [ -s "$STATE/http-targets" ]; then status zap FAILED
  else status zap "no-http-targets"; fi

  log "Trivy compliance ($TRIVY_COMPLIANCE) on running images"
  if command -v trivy >/dev/null; then
    T_OK=0
    docker inspect --format '{{.Config.Image}}' "${IDS[@]}" 2>/dev/null | sort -u | while read -r img; do
      safe="$(echo "$img" | tr -c 'A-Za-z0-9_.-' '_' | cut -c1-80)"
      trivy image --compliance "$TRIVY_COMPLIANCE" --format json -o "$OUT_DIR/trivy-compliance-${safe}.json" "$img" >/dev/null 2>&1 || true
    done
    ls "$OUT_DIR"/trivy-compliance-*.json >/dev/null 2>&1 && status trivy_compliance ok || status trivy_compliance FAILED
  else
    status trivy_compliance tool-missing
  fi
  log "collect complete at $(cat "$STATE/collected")"
}

# ============================================================================
cmd_stop() {
  need_root; need_docker
  [ -f "$STATE/started" ] || die "not started"
  now > "$STATE/stopped"

  log "stopping watcher"
  touch "$STATE/halt"
  if [ -f "$STATE/watch.pid" ]; then kill "$(cat "$STATE/watch.pid")" 2>/dev/null; fi
  merge_snapshots

  log "stopping packet capture"
  if [ -f "$STATE/tcpdump.pid" ]; then kill "$(cat "$STATE/tcpdump.pid")" 2>/dev/null; sleep 1; fi
  [ -s "$OUT_DIR/capture.pcap" ] && status capture ok || status capture "empty"

  log "stopping Falco"
  docker rm -f oss-crs-runtime-falco >/dev/null 2>&1
  [ -s "$OUT_DIR/falco-events.json" ] && status falco ok || status falco "no-events"

  log "Zeek analysis of the capture ($ZEEK_IMAGE)"
  if [ -s "$OUT_DIR/capture.pcap" ]; then
    docker pull -q "$ZEEK_IMAGE" >/dev/null 2>&1
    if docker run --rm -v "$OUT_DIR":/pcap:ro -v "$OUT_DIR/zeek":/out -w /out "$ZEEK_IMAGE" \
        zeek -r /pcap/capture.pcap LogAscii::use_json=T >/dev/null 2>&1 && ls "$OUT_DIR/zeek"/*.log >/dev/null 2>&1; then
      status zeek ok; img_digest "$ZEEK_IMAGE" > "$STATE/zeek.digest"
    else
      status zeek FAILED
    fi
  else
    status zeek "no-capture"
  fi

  log "OpenSCAP host scan"
  run_openscap

  cmd_report
}

run_openscap() {
  ensure_oscap || { status openscap tool-missing; return; }
  ensure_ssg >/dev/null 2>&1 || true
  . /etc/os-release 2>/dev/null
  DS=""
  for dir in "$SSG_DIR" /usr/share/xml/scap/ssg/content; do
    for cand in "$dir/ssg-${ID}${VERSION_ID//./}-ds.xml" \
                "$dir/ssg-${ID}-ds.xml" \
                "$dir/ssg-rhel${VERSION_ID%%.*}-ds.xml"; do
      [ -f "$cand" ] && { DS="$cand"; break 2; }
    done
  done
  [ -n "$DS" ] || { status openscap "no-datastream-for-${ID:-unknown}"; return; }
  PROFILE=""
  for p in xccdf_org.ssgproject.content_profile_cui \
           xccdf_org.ssgproject.content_profile_cis_level1_server \
           xccdf_org.ssgproject.content_profile_stig; do
    oscap info "$DS" 2>/dev/null | grep -q "$p" && { PROFILE="$p"; break; }
  done
  [ -n "$PROFILE" ] || { status openscap "no-usable-profile"; return; }
  echo "$PROFILE" > "$STATE/openscap.profile"; echo "$DS" > "$STATE/openscap.ds"
  oscap xccdf eval --profile "$PROFILE" --results "$OUT_DIR/openscap-results.xml" \
    --report "$OUT_DIR/openscap-report.html" "$DS" >/dev/null 2>&1
  [ -s "$OUT_DIR/openscap-results.xml" ] && status openscap ok || status openscap FAILED
}

# ============================================================================
cmd_report() {
  mkdir -p "$OUT_DIR" "$STATE"
  log "generating RUNTIME-FINDINGS.md"
  python3 - "$OUT_DIR" "$STATE" "$SCOPE_MATCH" "$FALCO_IMAGE" "$ZEEK_IMAGE" "$BENCH_IMAGE" "$ZAP_IMAGE" "$TRIVY_COMPLIANCE" <<'PY'
import json, os, sys, glob, ipaddress, xml.etree.ElementTree as ET
from collections import Counter, defaultdict
out, state, scope, falco_img, zeek_img, bench_img, zap_img, trivy_cmp = sys.argv[1:9]

def rd(p, default=""):
    try: return open(p).read().strip()
    except Exception: return default
def jl(p):
    try: return json.load(open(p))
    except Exception: return None
def jlines(p):
    rows=[]
    try:
        for line in open(p):
            line=line.strip()
            if line:
                try: rows.append(json.loads(line))
                except Exception: pass
    except Exception: pass
    return rows
def tbl(rows, header):
    o=["| "+" | ".join(header)+" |","|"+"|".join(["---"]*len(header))+"|"]
    for r in rows: o.append("| "+" | ".join(str(x) for x in r)+" |")
    return "\n".join(o)
def is_private(ip):
    try:
        a=ipaddress.ip_address(ip); return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified
    except Exception: return True

started, collected, stopped = rd(f"{state}/started","not recorded"), rd(f"{state}/collected","not run"), rd(f"{state}/stopped","not recorded")
host, uname = rd(f"{state}/host","unknown"), rd(f"{state}/uname","unknown")
status = dict(l.split("=",1) for l in rd(f"{state}/status").splitlines() if "=" in l)

# ---- docker subnets for attribution ----
subnets=[]
nets = jl(f"{out}/networks-inspect.json") or []
for n in nets:
    for c in (n.get("IPAM",{}).get("Config") or []):
        if c.get("Subnet"): subnets.append((n.get("Name"), c["Subnet"]))
def in_docker(ip):
    for name,s in subnets:
        try:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(s, strict=False): return name
        except Exception: pass
    return None

# ---- container posture ----
cons = jl(f"{out}/containers-inspect.json") or []
posture=[]
n_root=n_priv=n_caps=n_hostmount=n_hostnet=0
for c in cons:
    name=c.get("Name","").lstrip("/"); img=c.get("Config",{}).get("Image","")
    user=c.get("Config",{}).get("User") or "(root)"
    hc=c.get("HostConfig",{})
    priv=bool(hc.get("Privileged")); caps=hc.get("CapAdd") or []
    mounts=[m.get("Source","") for m in (c.get("Mounts") or []) if m.get("Type")=="bind"]
    hostm=[m for m in mounts if m.startswith(("/var/run/docker.sock","/proc","/sys","/etc","/","/var/lib/docker"))]
    netmode=hc.get("NetworkMode","")
    nets_=list((c.get("NetworkSettings",{}).get("Networks") or {}).keys())
    if user=="(root)": n_root+=1
    if priv: n_priv+=1
    if caps: n_caps+=1
    if any(m in ("/var/run/docker.sock",) or m.startswith(("/proc","/sys")) for m in mounts): n_hostmount+=1
    if netmode=="host": n_hostnet+=1
    posture.append([name, img[:60], user, "yes" if priv else "no", ",".join(caps) or "-", ",".join(nets_) or netmode, str(len(mounts))])

# ---- Zeek egress ----
conn = jlines(f"{out}/zeek/conn.log"); dns = jlines(f"{out}/zeek/dns.log"); ssl = jlines(f"{out}/zeek/ssl.log")
ext=Counter(); ext_ports=defaultdict(set); internal=Counter(); cross=Counter()
for r in conn:
    o,d,p,svc = r.get("id.orig_h"), r.get("id.resp_h"), r.get("id.resp_p"), r.get("service") or "-"
    if not d: continue
    if not is_private(d):
        ext[d]+=1; ext_ports[d].add(f"{p}/{svc}")
    else:
        dn=in_docker(d); on=in_docker(o) if o else None
        if dn: internal[dn]+=1
        if dn and on and dn!=on: cross[(on,dn)]+=1
sni=Counter(r.get("server_name") for r in ssl if r.get("server_name"))
queries=Counter(r.get("query") for r in dns if r.get("query"))

# ---- Falco ----
fal = jlines(f"{out}/falco-events.json")
f_pri=Counter(e.get("priority") for e in fal); f_rule=Counter(e.get("rule") for e in fal)

# ---- Docker Bench ----
bench=None
for cand in (f"{out}/docker-bench.log.json", f"{out}/docker-bench.json"):
    bench = jl(cand)
    if bench: break
b_res=Counter(); b_warn=[]
if bench:
    for t in bench.get("tests", []):
        for r in t.get("results", []):
            b_res[r.get("result")]+=1
            if r.get("result")=="WARN": b_warn.append([r.get("id"), r.get("desc","")[:90]])
elif os.path.exists(f"{out}/docker-bench.log"):
    txt=open(f"{out}/docker-bench.log",errors="ignore").read()
    for k in ("PASS","WARN","INFO","NOTE"): b_res[k]=txt.count(f"[{k}]")

# ---- nmap ----
nm_rows=[]
try:
    root=ET.parse(f"{out}/nmap.xml").getroot()
    for h in root.iter("host"):
        addr=next((a.get("addr") for a in h.iter("address") if a.get("addrtype")=="ipv4"),"?")
        for p in h.iter("port"):
            st=p.find("state")
            if st is not None and st.get("state")=="open":
                sv=p.find("service"); nm_rows.append([addr, in_docker(addr) or "-", p.get("portid"), p.get("protocol"), (sv.get("name") if sv is not None else "-"), (sv.get("product","") if sv is not None else "")[:40]])
except Exception: pass

# ---- ZAP ----
zap_rows=[]
for f in sorted(glob.glob(f"{out}/zap-*.json")):
    d=jl(f) or {}; risk=Counter()
    for site in d.get("site",[]):
        for a in site.get("alerts",[]): risk[a.get("riskdesc","").split(" ")[0]]+=int(a.get("count",1) or 1)
    zap_rows.append([os.path.basename(f), risk.get("High",0), risk.get("Medium",0), risk.get("Low",0), risk.get("Informational",0)])

# ---- Trivy compliance ----
tc_rows=[]
for f in sorted(glob.glob(f"{out}/trivy-compliance-*.json")):
    d=jl(f) or {}; ok=fail=0
    for r in (d.get("SummaryReport",{}).get("SummaryResults") or d.get("Results") or []):
        ok+=int(r.get("TotalPass",0) or 0); fail+=int(r.get("TotalFail",0) or 0)
    tc_rows.append([os.path.basename(f).replace("trivy-compliance-","").replace(".json","")[:60], ok, fail])

# ---- OpenSCAP ----
osc=Counter(); osc_profile=rd(f"{state}/openscap.profile","-")
try:
    root=ET.parse(f"{out}/openscap-results.xml").getroot()
    for rr in root.iter():
        if rr.tag.endswith("rule-result"):
            res=next((c.text for c in rr if c.tag.endswith("result")),None)
            if res: osc[res]+=1
except Exception: pass

# ---- digests ----
dig={k:rd(f"{state}/{k}.digest","unresolved") for k in ("falco","zeek","bench","zap")}

# ================= RUNTIME-PROVENANCE.md =================
P=f"""# OSS-CRS Runtime Analysis: Provenance

| Field | Value |
|---|---|
| Host | {host} |
| Kernel / OS | {uname} |
| Capture started (UTC) | {started} |
| Posture collected (UTC) | {collected} |
| Capture stopped (UTC) | {stopped} |
| In-scope selector | containers, images, or networks containing "{scope}" |
| Capture filter | {rd(f"{state}/capture.filter","not recorded")} |

## Tool images and resolved digests

| Tool | Image | Resolved digest |
|---|---|---|
| Falco | {falco_img} | {dig['falco']} |
| Zeek | {zeek_img} | {dig['zeek']} |
| Docker Bench for Security | {bench_img} | {dig['bench']} |
| OWASP ZAP | {zap_img} | {dig['zap']} |
| Trivy compliance spec | {trivy_cmp} | - |
| OpenSCAP profile | {osc_profile} | - |

Pin the digests above for a reproducible re-run.

## Step status

{tbl([[k,v] for k,v in sorted(status.items())], ["Step","Status"])}
"""
open(f"{out}/RUNTIME-PROVENANCE.md","w").write(P)
open(f"{out}/RUNTIME-STATUS.txt","w").write("\n".join(f"{k}={v}" for k,v in sorted(status.items()))+"\n")

# ================= RUNTIME-FINDINGS.md =================
L=[]
L.append("# OSS-CRS Runtime Findings\n")
L.append("**Companion to:** OSS-CRS-OVERVIEW.md and 800-171-findings.md (static evidence)")
L.append("**Observation window (UTC):** "+f"{started} to {stopped}\n")
L.append("This document reports what was observed while an OSS-CRS campaign was running,")
L.append("as recorded by the tools listed in RUNTIME-PROVENANCE.md. Counts are read directly")
L.append("from the tool output.\n")
L.append("---\n")

L.append("## 1. Summary\n")
L.append(tbl([
    ["In-scope running containers", len(cons)],
    ["Containers running as root (no USER set)", n_root],
    ["Privileged containers", n_priv],
    ["Containers with added capabilities", n_caps],
    ["Containers mounting the Docker socket, /proc, or /sys", n_hostmount],
    ["Containers using host networking", n_hostnet],
    ["External destinations contacted", len(ext)],
    ["Cross-network container flows observed", sum(cross.values())],
    ["Falco events", len(fal)],
    ["Docker Bench WARN items", b_res.get("WARN",0)],
    ["Open ports found by nmap", len(nm_rows)],
    ["ZAP targets scanned", len(zap_rows)],
    ["OpenSCAP failed rules", osc.get("fail",0)],
], ["Area","Result"]))
L.append("")
L.append("---\n")
L.append("## 2. Detailed findings\n")

L.append("### 2.1 Container posture (docker inspect)\n")
if posture:
    L.append("Configuration of each in-scope container while running.\n")
    L.append(tbl(posture, ["Container","Image","User","Privileged","Added caps","Networks","Bind mounts"]))
    L.append("")
else:
    L.append("No container snapshot present (collect was not run while containers were up).\n")

L.append("### 2.2 Network egress (Zeek over the packet capture)\n")
if conn:
    L.append(f"{len(conn)} connections recorded. External (non-private) destinations:\n")
    if ext:
        L.append(tbl([[ip, cnt, ", ".join(sorted(ext_ports[ip]))[:80]] for ip,cnt in ext.most_common()], ["Destination","Connections","Port/service"]))
    else:
        L.append("None. All recorded connections were to private or loopback addresses.")
    L.append("")
    if sni:
        L.append("TLS server names observed (SNI):\n")
        L.append(tbl([[n,c] for n,c in sni.most_common(40)], ["Server name","Handshakes"])); L.append("")
    if queries:
        L.append("DNS names queried:\n")
        L.append(tbl([[q,c] for q,c in queries.most_common(40)], ["Query","Count"])); L.append("")
    if internal:
        L.append("Connections into Docker networks, by destination network:\n")
        L.append(tbl([[n,c] for n,c in internal.most_common()], ["Network","Connections"])); L.append("")
    if cross:
        L.append("Flows between different Docker networks:\n")
        L.append(tbl([[a,b,c] for (a,b),c in cross.most_common()], ["From network","To network","Connections"])); L.append("")
    else:
        L.append("No flows between different Docker networks were observed.\n")
else:
    L.append("No Zeek connection log present.\n")

L.append("### 2.3 Runtime activity (Falco)\n")
if fal:
    L.append(tbl([[p,c] for p,c in f_pri.most_common()], ["Priority","Events"])); L.append("")
    L.append(tbl([[r,c] for r,c in f_rule.most_common(30)], ["Rule","Events"])); L.append("")
else:
    L.append("No Falco events recorded.\n")

L.append("### 2.4 Docker host and daemon configuration (Docker Bench, CIS Docker Benchmark)\n")
if b_res:
    L.append(tbl([[k,b_res.get(k,0)] for k in ("PASS","WARN","INFO","NOTE")], ["Result","Count"])); L.append("")
    if b_warn:
        L.append("WARN items:\n"); L.append(tbl(b_warn, ["Check","Description"])); L.append("")
else:
    L.append("Docker Bench output not present.\n")

L.append("### 2.5 Exposed services (nmap)\n")
if nm_rows:
    L.append(tbl(nm_rows, ["Address","Network","Port","Proto","Service","Product"])); L.append("")
else:
    L.append("No nmap results present.\n")

L.append("### 2.6 HTTP surfaces (OWASP ZAP baseline)\n")
if zap_rows:
    L.append(tbl(zap_rows, ["Report","High","Medium","Low","Informational"])); L.append("")
else:
    L.append("No HTTP endpoints were scanned (none detected in scope, or ZAP did not run).\n")

L.append("### 2.7 Image compliance (Trivy, "+trivy_cmp+")\n")
if tc_rows:
    L.append(tbl(tc_rows, ["Image","Pass","Fail"])); L.append("")
else:
    L.append("No Trivy compliance output present.\n")

L.append("### 2.8 Host configuration (OpenSCAP)\n")
if osc:
    L.append(f"Profile: `{osc_profile}`.\n")
    L.append(tbl([[k,v] for k,v in sorted(osc.items())], ["Result","Rules"])); L.append("")
else:
    L.append("OpenSCAP results not present (see RUNTIME-PROVENANCE.md step status).\n")

L.append("---\n")
L.append("## 3. Control mapping (NIST SP 800-171 Rev 2)\n")
L.append(tbl([
    ["Access Control (3.1)", "3.1.5, 3.1.6, 3.1.7", "Container user, privileged flag, capabilities (2.1); Falco privilege events (2.3)"],
    ["Audit and Accountability (3.3)", "3.3.1", "Zeek connection logs (2.2), Falco event log (2.3)"],
    ["Configuration Management (3.4)", "3.4.1, 3.4.2, 3.4.7", "Docker Bench (2.4), exposed services (2.5), OpenSCAP (2.8), Trivy compliance (2.7)"],
    ["Risk Assessment (3.11)", "3.11.2", "ZAP (2.6), Trivy compliance (2.7)"],
    ["System and Communications Protection (3.13)", "3.13.1, 3.13.5, 3.13.6", "External destinations, SNI, DNS, cross-network flows (2.2); exposed services (2.5)"],
    ["System and Information Integrity (3.14)", "3.14.6, 3.14.7", "Falco runtime events (2.3)"],
], ["Family","Requirement","Evidence"]))
L.append("")
L.append("Docker Bench and Trivy report against the CIS Docker Benchmark, which has a")
L.append("published crosswalk to NIST SP 800-53; 800-171 derives from the 800-53 moderate")
L.append("baseline. OpenSCAP reports against the SCAP Security Guide profile named above.")
L.append("The remaining tools produce evidence mapped to the families in this table.\n")

L.append("---\n")
L.append("## 4. Scope\n")
L.append("Observations cover the window above on the named host. The packet capture is")
L.append("restricted by capture filter to Docker network address space (see")
L.append("RUNTIME-PROVENANCE.md for the exact filter), so traffic on the host's own")
L.append("interfaces is not recorded; if other containers ran on this host during the")
L.append("window, their traffic is in scope of that filter. Docker-network attribution is")
L.append("derived from the network subnets recorded at collect time. Container posture is")
L.append("the union of every in-scope container observed while the watcher was running, so")
L.append("it covers containers that started and exited at different points in the campaign.")
L.append("Docker Bench, nmap, ZAP, and Trivy results are point-in-time and reflect the")
L.append("containers running when a collection fired; see the step status in")
L.append("RUNTIME-PROVENANCE.md for how many collections ran.\n")
open(f"{out}/RUNTIME-FINDINGS.md","w").write("\n".join(L))
print(f"RUNTIME-FINDINGS.md: {len(cons)} containers, {len(conn)} connections, {len(fal)} falco events")
PY
  status report ok
  ( cd "$OUT_DIR" && find . -maxdepth 1 -type f ! -name SHA256SUMS.txt ! -name '*Zone.Identifier' -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt )
  log "done: $OUT_DIR"
}

# ============================================================================
case "$VERB" in
  start)   cmd_start ;;
  collect) cmd_collect ;;
  stop)    cmd_stop ;;
  report)  cmd_report ;;
  __watch) watch_loop ;;
  *) sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
