# scripts/creds — credential operations

Turn one credential into many: spray to get a foothold, validate where it gives
admin, dump more secrets, crack what you collect. Built on netexec + impacket +
hashcat (rockyou + OneRule from `/opt/data/wordlists`).

> **Authorized use only.** Spraying locks accounts; dumping is post-exploitation.
> In-scope hosts only.

## Loop
```
hk-spray  -i 10.10.10.10 -U users.txt -p 'Season2026!' -d corp.local   # 1 pw/round
hk-validate -t 10.10.10.0/24 -u found -p 'pw' -d corp.local            # where = admin?
hk-secretsdump -i <admin-host> -u found -p 'pw' -d corp.local          # SAM/LSA (--ntds on DC)
hk-crack  nt_hashes.txt                                                 # auto-ID -> hashcat
```

## Scripts
- **spray.sh** — lockout-aware spraying (one password across all users per
  round, configurable delay). SMB/LDAP/WinRM/MSSQL/RDP. Reads lockout policy
  first. Saves valid creds.
- **validate.sh** — sweeps a host set with a credential and flags where it
  authenticates vs where it's **local admin** (`Pwn3d!`). Optional WinRM check.
- **secretsdump.sh** — SAM + LSA + DPAPI, and full **NTDS.dit** (DCSync) on a DC.
  Drops a crack-ready `nt_hashes.txt`.
- **crack.sh** — identifies the hash type (nth/heuristics), maps to the hashcat
  mode, runs rockyou then rockyou+OneRule, prints what cracked. `-m` to override,
  `--show` to just dump existing cracks.

## Pass-the-hash
Every script takes `-H lm:nt` (use `:nt` if you only have the NT half) anywhere
you'd pass `-p`. So a dumped NT hash feeds straight back into `validate.sh` and
`secretsdump.sh` without cracking.
