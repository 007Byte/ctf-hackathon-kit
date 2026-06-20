# Web Cache Poisoning / Deception Toolkit

Two cooperating Python scripts for reconnaissance and exploitation of HTTP
**web cache poisoning**, **cache deception**, and **request smuggling / desync**
vulnerabilities — built for CTF challenges and authorized lab testing.

| Script | Role | One-liner |
|---|---|---|
| `autopilot.py` | **Both, automatically** | One command: scans, ranks, picks the best target, then runs every attack + chain against it. Start here. |
| `full_recon.py` | **Map** | Discovers endpoints, status codes, cache behavior, and the proxy↔origin relationship, then *ranks* which paths are worth attacking. |
| `full_attack.py` | **Attack** | Sweeps every combination of framing headers, X-headers, obfuscations, and payloads to actually achieve smuggling/poisoning/deception, then tells you exactly what worked. |

> ⚠️ **Authorized use only.** Run these against CTF targets, your own lab, or
> systems you have explicit permission to test.

---

## The big picture

These challenges hinge on a **front-end cache/proxy and a back-end origin server
disagreeing** about a request — how long the body is, where it ends, what URL or
host it's for. When they disagree, you can:

- **Poison** the cache so other users get *your* injected response.
- **Deceive** the cache into storing private/authenticated content under a URL
  anyone can fetch.
- **Smuggle** a hidden second request past the front-end to the origin.
- **CPDoS** (Cache-Poisoned Denial of Service): make the cache store an *error*
  page so legitimate users get it instead of the real page.

`full_recon.py` finds *where* this disagreement might exist. `full_attack.py`
*exploits* it.

---

## Requirements

- **Python 3.7+** — standard library only (`socket`, `gzip`, `hashlib`, `json`, …).
  No `pip install` needed.
- Both files **must live in the same folder** — `full_attack.py` imports the
  shared socket/parsing code from `full_recon.py`.

---

## Recommended workflow

### Easiest: autopilot (one command)

```bash
python autopilot.py --host TARGET --port 5002 \
    --cookie "session=<your-token-here>"
```

> **Cookies / session tokens are not bundled.** Supply your own with `--cookie`.
> If you leave `--cookie` off, the tool asks *"Does the target require an auth
> cookie / session token? [y/N]"* and prompts you to paste it. Pass `--cookie ""`
> to skip both the prompt and any cookie.

`autopilot.py` runs recon, ranks the endpoints, auto-selects the best target (and a
content-substitution source), then runs **every attack technique and all the chains**
against it — finishing with a consolidated list of working vectors and replay
requests. Add `--aggressive` for the full sweep, `--target /foo` to skip
auto-selection, `--json recon.json` to also save the recon results.

### Manual: recon → attack (more control)

Run recon, save its findings, then let the attacker aim itself from that file:

```bash
# 1. Map the target and write findings to recon.json
python full_recon.py --host TARGET --port 5002 \
    --cookie "session=<your-token-here>" \
    --json recon.json

# 2. Attack using whatever recon decided was the best target
python full_attack.py --from-recon recon.json --aggressive
```

You can also run any script entirely on its own (see examples below).

---

## Script 1 — `full_recon.py` (mapping)

Runs in **7 phases**. You can run a subset with `--phases`.

| Phase | Name | What it answers |
|------|------|-----------------|
| 1 | Endpoint discovery | Which paths exist? (wordlist + your `--path` entries) |
| 2 | Status-code mapping | What does each method (GET/POST/PUT/…/bogus) return per endpoint? |
| 3 | Cache behavior | Is it cached? Does the cache key include the query string? the cookie? |
| 4 | Proxy↔origin relationship | Does the origin honor `X-Content-Length` / `X-Transfer-Encoding` / gzip? (i.e. CE/TL vs TL/CE) |
| 5 | Cache deception | Do path-confusion tricks (`.css`, `;`, `%2f`, `%00`…) cache real content? |
| 6 | CPDoS | Can oversized headers / bad methods / meta-chars cache an error? |
| 7 | Ranking | Scores every path and names the **best target** + next step. |

### Common options

| Flag | Meaning |
|---|---|
| `--host`, `--port` | Target address. |
| `--cookie` | Session/auth cookie value. |
| `--drop-path` | Endpoint that flushes the app cache between tests (use `--drop-path ""` if none). |
| `--path /foo` | Add an extra path to probe (repeatable). |
| `--phases 1,3,5` | Run only those phases. |
| `--json recon.json` | Write machine-readable results for `full_attack.py --from-recon`. |
| `--no-color` | Plain output (for logs/pipes). |

### Examples

```bash
# Full recon, colored to screen (omit --cookie to be asked if one is needed)
python full_recon.py --host TARGET --port 5002 \
    --cookie "session=<your-token-here>"

# Add custom endpoints you already know about
python full_recon.py --host T --port 80 --path /api/flag --path /admin

# Quick look: only discovery + cache behavior + ranking
python full_recon.py --host T --port 80 --phases 1,3,7

# Target with no cache-flush endpoint, save findings, no color (for a logfile)
python full_recon.py --host T --port 80 --drop-path "" --no-color --json recon.json
```

---

## Script 2 — `full_attack.py` (exploitation)

Sweeps the **full combination space** of attack techniques. For each attempt it
flushes the cache, fires the attack, then fetches the target on a **fresh
anonymous connection** to see whether the cache is now poisoned. On success it
prints the **exact request to replay**.

### Techniques (`--tech`)

| Name | What it tries |
|---|---|
| `smuggle` | Request-smuggling carriers: `CL.TE`, `CL.xTE`, `TE.CL`, `xCL.CL`, gzip/`CE` — crossed with Transfer-Encoding obfuscations, several smuggled inner requests, **POST & GET carriers**, and gzip bodies **with or without a real `Content-Length`**. |
| `desync` | Timing probe: a partial request that stalls the origin if front-end & origin disagree on length. |
| `poison` | Cache poisoning via **unkeyed headers** (`X-Forwarded-Host`, `X-Original-URL`, method-override, …) that leak into a shared cache entry. |
| `deception` | Web cache deception: path-confusion **delimiter × extension matrix** — `path-param`, `;`, `%2f`, `%0a`, `%00`, `%3b`, `%23`, `%3f`, plus the **double-encoded** variants (`%252f`, `%25%30%41`, …) from *WCD Escalates!*. |
| `cpdos` | Cache-poisoned DoS: oversized headers, method-override, bad methods, header meta-chars that cache an error. |
| `hmc` | Header meta-character request splitting (bare LF/CR injects a second request). |
| `chain` | **Multi-stage attacks** that compose the primitives above into end-to-end exploits (see below). |

Default is `--tech all`.

#### Chaining (`--tech chain`)

Real exploits are rarely a single trick — they chain primitives together. This mode
takes what the other techniques discover and escalates:

| Chain | What it does |
|---|---|
| **desync → persistent poison** | Use a working smuggle carrier to poison the shared cache entry and confirm the poison is served to *multiple consecutive* anonymous victims. |
| **reflection → poison → stored XSS** | Find an unkeyed header reflected unescaped, inject an XSS payload, and confirm it gets cached and served to all anonymous visitors (the *WCD Escalates!* reflected-XSS escalation). |
| **smuggle → CPDoS** | Smuggle an error-triggering request (oversized header / method override) *past* the front-end so the cache stores an error under the victim URL — a DoS that bypasses front-end filtering. |
| **deception → secret extraction** | After a deception hit, scan the cached private page for CSRF tokens, session IDs, OAuth state, and other high-entropy secrets (the papers' secret-extraction step, automated). |

Chains reuse primitives found earlier in the same run, or discover them on demand —
so `--tech chain` works standalone too. Each chain prints the exact request to replay.

### Common options

| Flag | Meaning |
|---|---|
| `--host`, `--port`, `--cookie` | Target + auth (optional if using `--from-recon`). |
| `--target /login` | The page you want to poison/attack. |
| `--source /join` | A *different* page whose body proves content substitution worked. |
| `--from-recon recon.json` | Auto-load target/source/connection from a recon dump. |
| `--tech smuggle,poison` | Run only selected techniques. |
| `--retries N` | Attempts per race-sensitive carrier (default 6). |
| `--aggressive` | Full obfuscation sweep + keep going past the first hit. |
| `--keep` | Do **not** restore the cache afterward — leave it poisoned (e.g. to grab a flag). |
| `--verbose` | Show every attempt, not just successes. |
| `--no-color` | Plain output. |

> **Precedence:** an explicit flag always wins over `--from-recon`, which wins over
> the built-in defaults. So you can load a recon file and still override just the
> target.

### Examples

```bash
# Standalone: attack a known target/source directly
python full_attack.py --host TARGET --port 5002 \
    --cookie "session=<your-token-here>" --target /login --source /join

# Only smuggling + poisoning, full obfuscation sweep
python full_attack.py --host T --port 80 --target /login \
    --tech smuggle,poison --aggressive

# Just check for cache deception, verbose so you see every suffix tried
python full_attack.py --host T --port 80 --target /login \
    --tech deception --verbose

# CPDoS only — can we cache an error page?
python full_attack.py --host T --port 80 --target /login --tech cpdos

# Land the poison and LEAVE it in place to capture a flag
python full_attack.py --host T --port 80 --target /login --keep

# Run only the multi-stage chains (discovers its own primitives if needed)
python full_attack.py --host T --port 80 --target /login --tech chain

# Full run, aggressive: all single techniques THEN compose them into chains
python full_attack.py --from-recon recon.json --aggressive
```

---

## Chaining recon → attack (`--from-recon`)

```bash
# 1. Recon writes its conclusions (best target, suggested source, connection info)
python full_recon.py --host T --port 80 --cookie "..." --json recon.json

# 2a. Attack exactly what recon recommended
python full_attack.py --from-recon recon.json

# 2b. Use recon's connection + source, but override the target yourself
python full_attack.py --from-recon recon.json --target /admin

# 2c. Use recon, go aggressive, and leave the cache poisoned
python full_attack.py --from-recon recon.json --aggressive --keep
```

The `recon.json` file carries everything the attacker needs: `host`, `port`,
`cookie`, `drop_path`, the ranked path list, the detected proxy↔origin
relationship, and a `best` block with the top target and a suggested source page.

---

## Reading the output

- **`full_recon.py`** ends with a **PHASE 7 ranking** table. Higher score = more
  attackable. It names a **BEST TARGET** and a recommended next step.
- **`full_attack.py`** ends with a **RESULTS** block listing each working vector,
  the evidence (e.g. *"clean GET now serves /join body"*), and the **raw request to
  replay**. If nothing worked, it suggests trying `--aggressive`, a different
  `--source`, or more `--retries`.

### Tips

- **No hits?** Re-run the attacker with `--aggressive` (much larger sweep) and a
  higher `--retries` — smuggling/poisoning often depend on a race window.
- **Wrong source page?** The auto-suggested `--source` is just *some* different
  live page. If the interesting comparison page is specific (e.g. an admin page),
  pass `--source /that/page` explicitly.
- **No `/drop` endpoint?** Pass `--drop-path ""`. Without it the tools can't force
  a clean cache state between tests, so results are noisier — re-run a few times.
- **Saving logs?** Add `--no-color` so the output file isn't full of ANSI codes.

---

## File layout

```
Web_Recon/
├── autopilot.py      # one-command recon -> rank -> chained exploitation (start here)
├── full_recon.py     # mapping / ranking
├── full_attack.py    # exploitation + chains (imports primitives from full_recon.py)
├── README.md         # this file
└── recon.json        # (optional) generated by --json, consumed by --from-recon
```

> The older `discover*.py`, `qaqa*.py`, `fifi*.py`, `ww*.py`, etc. were the
> iterative experiments these two consolidated scripts were distilled from. They're
> kept for reference but are superseded by `full_recon.py` + `full_attack.py`.
