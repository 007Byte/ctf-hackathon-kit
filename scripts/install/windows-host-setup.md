# Windows 11 CTF Host Setup

A practical guide to turning a Windows 11 machine into a comfortable CTF base.
The heavy lifting (exploitation, scanning) happens on **Kali Linux** — either in
**WSL2** or a **VM** — but Windows itself runs plenty of useful tools and is a
fine place to keep notes, hex editors, and your browser tooling.

> TL;DR recommended setup:
> 1. **WSL2 + Kali** for everyday command-line work (fast, lightweight).
> 2. A **full Kali VM** (VirtualBox or VMware) for GUI tools, VPN routing, and
>    anything that needs a "real" network stack (e.g. some reverse-shell / raw
>    socket scenarios behave better in a VM than in WSL).
> 3. Windows-native tools (Wireshark, HxD, CyberChef, VS Code, Obsidian).

---

## 1. WSL2 + Kali Linux (primary CLI environment)

WSL2 gives you a real Linux kernel with great performance and easy file sharing
with Windows.

### Install

Open **PowerShell as Administrator** and run:

```powershell
# Installs WSL2 + the default distro plumbing
wsl --install

# List what's available, then install Kali specifically
wsl --list --online
wsl --install -d kali-linux

# Make sure you're on WSL version 2 (not the legacy v1)
wsl --set-default-version 2
wsl --status
```

Reboot if prompted. Launch **Kali** from the Start menu, create your user, then:

```bash
sudo apt update && sudo apt full-upgrade -y
# Optional: pull the Kali metapackage of common tools
sudo apt install -y kali-linux-headless
```

Then run the installer scripts from this repo inside Kali:

```bash
# from your mounted Windows path or after copying the scripts in
sudo ./install-tools.sh
./install-python-libs.sh venv
```

### WSL tips
- Your Windows drives are mounted under `/mnt/c`, `/mnt/d`, etc.
- Your WSL home (`~`) is the fast native filesystem — **work there**, not under
  `/mnt/c`, for big scans/builds (DrvFS is slow).
- GUI Linux apps work out of the box on Windows 11 via WSLg (e.g. `burpsuite`,
  `wireshark` launched from WSL will open a window).
- Limit RAM/CPU if needed via `C:\Users\<you>\.wslconfig`:

  ```ini
  [wsl2]
  memory=8GB
  processors=4
  ```

### WSL limitations to know
- VPN routing (HTB/THM OpenVPN) can be finicky in WSL2's NAT network. If your
  attacks can't reach the target through the VPN, use the **VM** instead, where
  `tun0` behaves normally. (WSL2 mirrored networking mode helps but a VM is the
  reliable fallback.)
- Raw packet / some `nmap` scan types may need the VM.

---

## 2. Kali in a VM (VirtualBox or VMware)

Use a VM when you want the full Kali desktop, reliable VPN routing, snapshots,
or network isolation.

### Option A — VirtualBox (free)
1. Install **Oracle VirtualBox** + the **Extension Pack**.
2. Download the prebuilt **Kali VirtualBox image** from
   <https://www.kali.org/get-kali/#kali-virtual-machines> (saves you an install).
3. Import the `.ova` / unzip the `.vbox` and boot it.
4. Install **Guest Additions** for clipboard sharing, resizing, shared folders.

### Option B — VMware Workstation Player / Pro (free for personal use)
1. Install **VMware Workstation**.
2. Download the prebuilt **Kali VMware image** from the same Kali page.
3. Open the `.vmx`, then install **open-vm-tools** inside Kali:
   ```bash
   sudo apt install -y open-vm-tools open-vm-tools-desktop
   ```

### VM networking cheat-sheet
- **NAT** — simplest; VM can reach the internet/VPN, host can't easily reach VM.
- **Bridged** — VM gets an IP on your LAN (useful for host<->VM or lab targets).
- **Host-only** — isolated host<->VM network (good for local target VMs).
- For HTB/THM: NAT or Bridged + run OpenVPN **inside** the Kali VM.

> Default Kali VM credentials for prebuilt images: user `kali` / pass `kali`
> (change it immediately).

---

## 3. VPN / lab connectivity (HTB / THM)

- Download your `.ovpn` pack from the platform.
- Connect from **inside Kali** (WSL or VM):
  ```bash
  sudo openvpn user.ovpn
  # in another terminal, confirm your tunnel IP:
  ip addr show tun0
  ```
- The `tun0ip` helper in `ctf-aliases.sh` prints this for you.
- If you prefer a GUI on Windows for non-Kali stuff, **OpenVPN Connect** for
  Windows works, but route attacks through the box that holds `tun0`.

---

## 4. Recommended Windows-native tools

Install via **winget** for speed (run in PowerShell):

```powershell
winget install --id WiresharkFoundation.Wireshark -e
winget install --id 7zip.7zip -e
winget install --id Python.Python.3.12 -e
winget install --id Microsoft.VisualStudioCode -e
winget install --id Obsidian.Obsidian -e
winget install --id Git.Git -e
winget install --id Mozilla.Firefox -e
winget install --id OpenVPNTechnologies.OpenVPNConnect -e
```

| Tool | Why you want it |
|------|-----------------|
| **Wireshark** | PCAP / network forensics challenges; inspect captured traffic. |
| **CyberChef** | The "Swiss-army knife" for encoding/crypto/data. Use the web app at <https://gchq.github.io/CyberChef/> or download the standalone single-page HTML for offline use. |
| **HxD** | Fast, free hex editor for binary/file-format and stego work. <https://mh-nexus.de/en/hxd/> |
| **7-Zip** | Opens just about any archive; inspect/repair zips, extract firmware. |
| **Python 3** | Quick solve scripts on the Windows side; install `pip install pwntools requests pycryptodome` if you want. |
| **VS Code** | Editor for scripts/notes; install the **Remote - WSL** extension to edit Kali files natively. |
| **Obsidian** | Markdown note-taking / knowledge base for writeups (pairs perfectly with the `notes.md` from `mkctf`). |
| **Git** | Version your scripts/notes; clone tools. |
| **Firefox** | Dedicated CTF browser so your extensions/proxy don't mess with daily browsing. |

Other handy optional installs:
- **PuTTY / Windows Terminal** — SSH and a much nicer terminal (`winget install Microsoft.WindowsTerminal`).
- **Ghidra** (needs a JDK) — reverse engineering on the Windows side if you don't
  want it in the VM. `winget install Microsoft.OpenJDK.21` then download Ghidra
  from <https://ghidra-sre.org/>.
- **Detect It Easy (DIE)** — quick PE/file identification & packer detection.

---

## 5. Browser extensions (install in your CTF Firefox/Chrome profile)

| Extension | Purpose |
|-----------|---------|
| **Wappalyzer** | Fingerprints the web stack (CMS, frameworks, languages). |
| **Cookie-Editor** | View/edit/forge cookies (session fixation, JWT in cookies). |
| **FoxyProxy** | One-click toggle to route the browser through Burp/ZAP (127.0.0.1:8080). |
| **HackTools** | All-in-one cheat-sheet panel: reverse shells, payloads, encoders. |

Optional extras: **User-Agent Switcher**, **EditThisCookie**, **Hackbar**.

> When proxying through Burp, install Burp's CA cert in the browser so HTTPS
> targets don't throw certificate errors.

---

## 6. Sharing files between Windows host and Kali

Pick whichever fits your setup:

### WSL2
- From **Windows**, browse the Kali filesystem at: `\\wsl$\kali-linux\home\<user>`
  (paste into File Explorer's address bar).
- From **Kali**, your C: drive is at `/mnt/c/...`.
- Example: copy a challenge file in from Downloads:
  ```bash
  cp /mnt/c/Users/<you>/Downloads/challenge.bin ~/work/
  ```

### VM — Shared Folders
- **VirtualBox**: VM Settings → Shared Folders → add a host folder, tick
  *Auto-mount*. With Guest Additions installed it appears under `/media/sf_<name>`
  (add your user to the `vboxsf` group: `sudo usermod -aG vboxsf $USER`, then relog).
- **VMware**: VM Settings → Options → Shared Folders → Enable. With open-vm-tools
  it shows up under `/mnt/hgfs/<name>`.

### VM — Drag & Drop / Clipboard
- Enable **Bidirectional** clipboard and drag-and-drop in the VM settings
  (requires Guest Additions / open-vm-tools). Great for pasting hashes and small
  files quickly.

### Universal fallback — quick HTTP transfer
On the machine that **has** the file:
```bash
python3 -m http.server 8000        # serve current dir
```
On the other machine, fetch it:
```bash
# Linux
wget http://<host-ip>:8000/file
# Windows PowerShell
Invoke-WebRequest http://<host-ip>:8000/file -OutFile file
```
(The `serve` and `updogserve` helpers in `ctf-aliases.sh` wrap this.)

---

## 7. Suggested folder layout on the host

```
C:\Users\<you>\CY5770\Hackathon\
├── scripts\install\      # install-tools.sh, install-python-libs.sh, this guide
├── aliases\              # ctf-aliases.sh  (source it inside WSL/VM Kali)
├── boxes\                # one folder per machine/challenge (mkctf scaffolds these)
└── notes\                # Obsidian vault for writeups & cheat-sheets
```

Keep `scripts/` and `aliases/` in **Git** so you can clone your whole setup onto
a fresh Kali install in seconds:

```bash
git clone <your-repo> ~/ctf-setup
sudo ~/ctf-setup/scripts/install/install-tools.sh
echo 'source ~/ctf-setup/aliases/ctf-aliases.sh' >> ~/.bashrc
```

---

## Quick start checklist

- [ ] `wsl --install -d kali-linux` and update Kali
- [ ] Run `install-tools.sh` and `install-python-libs.sh venv` inside Kali
- [ ] Source `ctf-aliases.sh` from `~/.bashrc`
- [ ] (Optional) Import a Kali VM for VPN-heavy boxes
- [ ] Install Wireshark, HxD, 7-Zip, VS Code, Obsidian on Windows
- [ ] Set up the CTF Firefox profile + extensions
- [ ] Connect VPN inside Kali, confirm `tun0ip`
- [ ] `mkctf <boxname>` and go!
```
