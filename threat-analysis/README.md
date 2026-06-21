# threat-analysis

Defensive write-ups of malware / attack samples — what they do, their IOCs, and
how to **detect, block, and respond** to them. These are analysis documents, not
runnable code, and network indicators are defanged in prose.

| Report | Summary |
|--------|---------|
| [`easy-day-js-malicious-setup-cjs.md`](easy-day-js-malicious-setup-cjs.md) | npm typosquat (`easy-day-js`) install-time dropper: TLS-bypass → download second stage → run hidden/detached → self-delete. Includes ATT&CK mapping, IOCs, and Sigma/Suricata detections. |
