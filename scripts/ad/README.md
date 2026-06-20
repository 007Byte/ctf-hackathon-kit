# scripts/ad — Active Directory attack chain

Next-level AD tooling that chains together the kit installed on the Kali image
(netexec, impacket, certipy, bloodhound-python, mitm6, Coercer, krbrelayx,
hashcat). Each script self-documents (`-h`), saves to a per-run output dir, and
degrades gracefully when a tool is missing.

> **Authorized use only.** Hackathon range, lab, or a scoped engagement. These
> are intrusive — coercion/relay especially can disrupt a live network.

## The typical kill chain

| # | Goal | Script | Creds needed |
|---|------|--------|--------------|
| 1 | Map the domain | `ad-enum.sh` | none → better with any user |
| 2 | Crackable hashes | `roast.sh` | AS-REP: none (userlist) · Kerberoast: any user |
| 3 | Visualise paths | upload BloodHound zip → `bhcypher.sh` | the zip from step 1 |
| 4 | Cert abuse → DA | `adcs-hunt.sh` | any user |
| 5 | Coerce + relay → DA | `coerce-relay.sh` | none–any (network position) |

All are on your PATH as `hk-<name>` (e.g. `hk-ad-enum`, `hk-roast`, `hk-bhcypher`).

## Scripts

- **ad-enum.sh** — SMB + LDAP recon, RID-brute, password policy, roastable/
  delegation/LAPS/gMSA hunting, `ldapdomaindump`, and a BloodHound `-c All`
  collection zip ready to upload at http://127.0.0.1:8080.
- **roast.sh** — AS-REP roast (no creds with a userlist) + Kerberoast (any
  creds). Writes hashcat-format hashes and prints the exact crack commands
  (rockyou + OneRule rule).
- **adcs-hunt.sh** — `certipy find -vulnerable`; summarises ESC1–ESC16 findings
  with copy-paste exploitation hints (request cert → `certipy auth`).
- **coerce-relay.sh** — two playbooks: `mitm6` (IPv6 DNS takeover → ntlmrelayx)
  and `coerce` (PetitPotam/PrinterBug/DFSCoerce → relay, incl. ESC8/ADCS).
  Prints the plan and asks before firing the (loud) trigger.
- **bhcypher.sh** — runs high-value Cypher queries against BloodHound CE's Neo4j
  (Domain Admins, kerberoastable, AS-REP, delegation, DCSync, shortest path
  from Owned → DA, etc.). Mark nodes **Owned** in the GUI first.

## Crack workflow reminder
```
hk-roast -d corp.local -i 10.10.10.10 -u svc -p 'pw'   # -> kerb_hashes.txt + crack_kerb.cmd
hashcat -m 13100 kerb_hashes.txt /opt/data/wordlists/rockyou.txt \
        -r /opt/data/wordlists/rules/OneRuleToRuleThemStill.rule
```
