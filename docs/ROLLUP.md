# HEAPY Edge — project rollup for a new collaborator

Written 2026-10-16 by Justin Cross's Claude session. Give this to anyone (person or Claude session)
who will work on HEAPY Edge. It assumes you have the same `Data Collection QC` folder and the
`DYS3D/Heapy-edge` repository.

## What it is

HEAPY Edge is HEAPY's own on-site BAS data collector and the long-term replacement for Novant.
A small **site box** (Raspberry Pi 5, industrial x86 mini-PC, or a client Linux VM) plugs into the
client network, finds the BAS devices, reads their points on a schedule, buffers the readings
locally and sends them over outbound HTTPS to a **central HEAPY server** running HEAPY Trend
Tracker (being renamed HEAPY Atlas), where naming, FDD, alerts and reports already exist.

Design rules that never change: read-only to the BAS (no writes, no routing changes), outbound
HTTPS 443 only (no inbound ports), per-device request-rate limits, scans in time windows,
passwords and keys never shown again once saved.

## Where everything lives

| Thing | Where |
|---|---|
| Repository | `https://github.com/DYS3D/Heapy-edge` (public, main branch) |
| Working copy | `Data Collection QC\HEAPYEdge` (OneDrive, Justin's PC) |
| Project plan (HEAPY-branded HTML) | `docs/HEAPY Edge - Project Plan.html` in the repo; same file in the Claude project as `claude/HEAPY Edge - Project Plan.html`; live artifact https://claude.ai/artifact/Rmd2k4udnhAkmzicPkvFjd — **update all three on every phase change** |
| Client-facing security sheet | `docs/HEAPY Edge - Security Sheet.html`; artifact https://claude.ai/artifact/L218hUxtHaSEB2wkkuB3Qf |
| Status note (Claude project) | `claude/heapy-edge-status.md` — the running log of decisions, results and what's next |
| Hand-off for Claude Code | `docs/handoff.md` — WSL lab setup, lessons learned, commit conventions, open items |
| Soak results | branch `soak-results`, one folder per driver (`state.json`, `soak.log`) |
| Box image | `ghcr.io/dys3d/heapy-edge` (arm64 + amd64), built by `.github/workflows/image.yml` on every push to main |

## How it is built

- **Core** (`core/`): Node 22, no npm packages. Settings, driver host, scanner, poll scheduler with
  per-device lanes, SQLite buffer (readings kept until the server confirms them), uploader with
  acknowledged batches, pairing and check-in, HEAPY-branded setup page on port 8770.
- **Drivers** (`drivers/`): one program per protocol, any language, talking JSON lines over
  stdin/stdout (`contracts/driver-protocol.json`: hello, configure, discover, browse, read,
  subscribe, locate, shutdown). Built and proven: BACnet/IP (BACpypes3), BACnet MS/TP (direct on
  RS-485 via bacnet-stack's router inside the box), Modbus TCP / gateways / RTU / RTU-over-TCP
  (own framing, register templates), SNMP v1/v2c/v3 (pysnmp), Project Haystack (SCRAM, JSON v3/v4),
  Niagara oBIX. Shared Python plumbing in `drivers/common/` (protocol, rate limiter, HTTPS client
  with certificate pinning).
- **Point address**, one format for every protocol: `bacnet://1201/analog-input:5`,
  `modbus://meter-1/holding:40001?type=f32`, `snmp://ups-1/1.3.6...`, `haystack://...`, `obix://...`.
  The key holds the device's own id, never its IP, so a device that moves keeps its history.
- **Upload contract** (`contracts/upload-api.json`): box → server batches; the buffer clears only
  after the server says "stored".
- **Simulators** (`sim/`) and **lab** (`tests/lab.js`): every driver has a simulated site with fault
  injection, built on Linux network namespaces, a bridge, iptables and virtual serial buses.

## Where it stands (2026-10-16, v0.3.3)

**Every driver has passed its full fault suite and a 24-hour soak with scheduled faults.** The soak
injects a fault every few minutes (devices off, lost/garbled/stale replies, network loss, server
errors and hangs, clock jumps, driver and box killed) and checks slot by slot: one reading per
point per interval, every reading counted on the box and on the server.

| Driver | Fault suite | 24 h soak (GitHub run) | Readings |
|---|---|---|---|
| BACnet/IP | all pass | PASS 2026-10-01 (36901590727) | 732,893 |
| BACnet MS/TP | 15/15 | PASS 2026-10-04 (37118530932) | 343,680 |
| Modbus | 27/27 | PASS 2026-10-02 (36901607319) and 2026-10-03 (37000696195) | 1,430,545 |
| SNMP | 17/17 | PASS 2026-10-03 (36997864122) | 207,103 |
| Haystack | 16/16 | PASS 2026-10-03 (36997869776) | 152,564 |
| Niagara oBIX | 16/16 | PASS 2026-10-03 (36997875287) | 84,037 |

All soaks: 0 gaps, 0 wrong values, 0 readings lost or duplicated box→server, 0 unexpected box
stops, memory flat (96–113 MB). This meets Justin's rule of 2026-09-30: collection must be
foolproof before anything connects to Trend Tracker. It is proven on simulators only; real
equipment (bench kit) is still owed before the pilot.

Phases: 0 design, 1 core + BACnet/IP, 5 MS/TP + Modbus, 6 Niagara/Haystack/SNMP — done.
2 central intake — next, **paused**. 3 packaging/fleet, 4 pilot, 8 full on-site mode/VPN — planned.
7 LON/ARCNET — only if a site needs it.

## Decisions on record

- 2026-09-29: site box + central server model; Docker on Linux ARM + x86; outbound HTTPS only.
- 2026-09-30: all drivers first, each must pass fault suite + 24 h soak before Phase 2.
- 2026-10-01: soaks run on GitHub Actions; finish the soak cycle in Cowork, then continue in Claude Code.
- 2026-10-02: repository made public so Actions minutes are unlimited.
- 2026-10-04: **Phase 2 paused** — Justin may make a major change to Trend Tracker (HEAPY Atlas).
  Phase 2 is mostly Trend Tracker code, so it waits for that. No central server exists yet.
- 2026-10-16: **LON and ARCNET are read through the site's existing gateway** (JACE, iLON /
  SmartServer, BACnet router) with the drivers already built. Direct hardware support only if a
  real site has a bare trunk. The Pi stays the standard box.

## What is next

1. **Phase 2 — central intake** (when Justin unpauses, after his Trend Tracker change): a
   "HEAPY Edge" data source beside Novant and Manual import; intake API (pairing with a one-time
   code, upload endpoint, acknowledgements); Sites-and-boxes page (online / last seen, backlog,
   errors, version) and Discovery page (devices and points found, pick what to trend and at what
   interval). Build it as a **separate module on a branch** so nothing existing changes behaviour;
   prove it with the simulated box feeding Trend Tracker and FDD running on its data
   (`tests/mock-intake.js` is the current stand-in for the server side). Deployable to whichever
   host is chosen later.
2. Open items that need Justin: central server host and owner; bench kit parts list (Pi 5 kit with
   SSD, x86 mini-PC, USB RS-485 adapters, one MS/TP controller, one Modbus meter, a UPS with SNMP
   card) then every driver against real equipment; a pilot site (a Novant site with BACnet/IP,
   ideally an MS/TP trunk behind a router, and an IT contact); HEAPY IT review of the security sheet;
   whether "HEAPY Edge" stays the name.

## Working on it

- **Lab on a PC**: WSL2 Ubuntu as root. `apt-get install iproute2 iptables faketime build-essential
  git python3-venv`; venv with `drivers/bacnet-ip/requirements.txt`, `drivers/snmp/requirements.txt`,
  `tests/requirements-test.txt`; `HEAPY_EDGE_PYTHON` pointing at the venv; `sh tools/build-bacnet-stack.sh`
  for MS/TP. Then `node --no-warnings tests/selftest.js` (26 checks, ~10 min), `tests/faults*.js`
  per driver, `tests/soak24.js --kind <driver>`. Full details in `docs/handoff.md`.
- **Soaks on GitHub**: Actions → Soak test → Run workflow → pick the driver (five ~5.5-hour parts
  handed on through artifacts; results on the `soak-results` branch).
- **Git**: commit as `Justin Cross <jrcross@heapy.com>`; push with the fine-grained token
  (Contents, Workflows, Actions: read and write) via `~/mnt/.heapy/git-push.sh`. From a Claude
  cloud session the route is: `git bundle` → copy into `Data Collection QC` (never into `.git`) →
  `git fetch ../x.bundle main:refs/heads/incoming` → `git merge --ff-only incoming` → push. OneDrive
  leaves stale lock files; clear with `find .git -name "*.lock" -delete; find .git/objects -name "tmp_obj_*" -delete`.
- **Conventions**: HEAPY-branded HTML for anything Justin reads (brand layer is inlined in the plan);
  brief, results-first replies; Claude does all testing and debugging; the pass bar above is not
  negotiable; the plan is updated in all three places; the status note is updated at the end of
  every working session.
- **Things that bit us** (full list in `docs/handoff.md`): `pkill -f` kills the shell that runs it;
  an orphaned lab box becomes a second Modbus master; a libfaketime shim must never reach driver
  processes; MS/TP controllers that wake up late can land on the box's address (the driver detects
  and moves); BACnet/IP must ask for routers at start; GitHub soak parts must end within their
  time budget even while faults are chained.
