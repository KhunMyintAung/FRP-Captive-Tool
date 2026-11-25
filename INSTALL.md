# FRP TOOL — GUI and install guide for another computer

The project ships in two forms:

| Form | Needs Python on the target PC? | Who it is for |
|---|---|---|
| **`dist\FRP-Tool\FRP-Tool.exe`** (packaged GUI) | **No** — it contains its own Python interpreter | End users. Copy the folder, run the exe. |
| `frp_gui.py` / `frp_portal.py` (source) | Yes, Python 3.9+ | Development, or anyone who prefers the console tool. |

Both forms use **only the Python standard library** — there is nothing to
`pip install` in order to run the program.

---

## 1. Run the GUI on another computer (no Python needed)

1. Copy the whole **`dist\FRP-Tool`** folder to the other PC (zip it first; the
   folder is ~28 MB, the exe itself ~2 MB).
2. Right-click **`FRP-Tool.exe` → Run as administrator**, or just double-click
   it: pressing **Start** asks for Administrator rights by itself.
3. In the window:

   | Control | Meaning |
   |---|---|
   | **Wi-Fi name (SSID)** | The network the PC will broadcast. Saved to `config.json`. |
   | **Password** | WPA2 passphrase, 8–63 characters (leave empty for an open network). |
   | **Network band** | `2.4 GHz` (default), `5 GHz` or `Auto`. Windows 11 often picks 5 GHz on Auto, and phones that only scan 2.4 GHz then **never see the SSID** — keep 2.4 GHz unless you need the speed. Also `hotspot_band` in `config.json` / `--band` on the console. |
   | **Android DNS probe dance** | Experimental: fixes the missing "Sign in to network" popup on Android 14+. Changes no adapter settings. |
   | **Start** | Turns on the Windows Mobile Hotspot and the captive portal (DNS 53 + HTTP 80). |
   | **Stop** | Clean shutdown: firewall rules removed, hotspot stopped, servers closed. |

4. The log pane shows everything the portal does, including the phone's probe
   requests (`GET /generate_204 -> 302`).
5. Everything editable sits **next to the exe** — `config.json`, `web\`,
   `shared\` — so the other user can change the SSID, the portal page or add
   downloadable files without touching the bundle.

Closing the window while the portal is running asks whether to stop it first.

### What the packaged folder contains

```
dist\FRP-Tool\
├─ FRP-Tool.exe           the GUI (bundled interpreter, no Python needed)
├─ config.json            user settings (SSID, password, ports, paths)
├─ web\                   portal page + assets
├─ shared\                files offered under /download/
├─ core\hotspot.ps1       WinRT hotspot helper
├─ INSTALL.md             this guide
└─ _internal\             Python runtime, libraries, tcl/tk (do not edit)
```

Do **not** move `FRP-Tool.exe` out of its folder — it needs `_internal\`
beside it.

### System requirements (packaged build)

| Requirement | Details |
|---|---|
| **Windows 10 or 11, 64-bit** | WinRT Mobile Hotspot + `netsh`. |
| **Administrator rights** | Ports 53/80, `netsh advfirewall`, hotspot control. Mandatory: `FRP-Tool.exe` declares `requestedExecutionLevel=requireAdministrator`, so Windows asks for UAC **before the window opens**, and the program does not run at all if you decline. The source GUI (`python frp_gui.py`) also re-launches itself elevated at startup. |
| **Windows PowerShell 5.1** | Shipped with Windows at `System32\WindowsPowerShell\v1.0\powershell.exe`. Must not be blocked by AppLocker/Group Policy. |
| **Wi-Fi adapter with Mobile Hotspot support** | *Settings → Network & Internet → Mobile Hotspot* must exist and not be greyed out. |
| **An active internet connection profile** | The hotspot is shared from the current Wi-Fi/Ethernet profile. |
| **Free TCP 80 and UDP 53** | IIS, Apache, Skype, Docker or another DNS service will block the popup. |

No Python, no pip, no Visual C++ redistributable, no .NET SDK.

---

## 2. Windows Defender / SmartScreen ("virus" warning)

An unsigned executable that opens ports, starts a hotspot, runs `netsh` and
elevates is **statistically similar to malware**, so Defender and SmartScreen
may warn about it even though the code is the same Python you can read here.
Nothing can guarantee a clean verdict from heuristics; the build is set up to
avoid the usual causes and you have these options:

**Already applied in `build_exe.bat` (reduces false positives):**

* `--onedir` — a normal folder with a real `_internal`, **not** the
  self-extracting onefile bootloader that triggers most heuristic hits.
* `--noupx` — no executable compression, which is a classic packer signature.
* `--version-file packaging\version_info.txt` — full version metadata
  (product, description, version) instead of a blank, anonymous binary.
* Latest PyInstaller (6.20 here) — newer bootloaders have fewer detections
  than the ones malware authors used.

**If SmartScreen blocks the first run** ("Windows protected your PC"):
*More info → Run anyway*. This is expected for any unsigned exe.

**If Defender quarantines it:**
1. *Windows Security → Virus & threat protection → Protection history* →
   allow the item, and add the folder as an exclusion.
2. Report it as a false positive to Microsoft:
   <https://www.microsoft.com/en-us/wdsi/filesubmission> — usually reclassified
   within a day or two.
3. Build the exe again after a PyInstaller upgrade; detections are often
   fixed upstream.

**The only permanent fix is code signing.** Buy/obtain an Authenticode
certificate (OV or EV) and sign the exe, e.g.:

```bat
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 ^
  /f mycert.pfx /p <password> dist\FRP-Tool\FRP-Tool.exe
```

A signed binary shows a publisher name and stops the SmartScreen "unknown
publisher" prompt; reputation builds over downloads. If signing is not an
option, distributing the plain Python source (section 4) sidesteps Defender
packer heuristics entirely, at the cost of requiring Python.

---

## 3. Rebuilding the package

Build on any Windows PC with Python 3.9+ (the build machine needs PyInstaller;
the target PC does not):

```bat
python -m pip install --upgrade pyinstaller
build_exe.bat
```

The build uses `--uac-admin`, so the exe always requires Administrator, and
`--windowed`, so it never shows a console. Every `powershell.exe` / `netsh.exe`
child process is started with `CREATE_NO_WINDOW`, which is what stops the black
console windows from flashing while the portal runs and while it polls status.

`build_exe.bat` produces `dist\FRP-Tool\`, copies `web\`, `shared\`,
`config.json`, `core\hotspot.ps1` and this guide next to the exe, and prints the
result path. Rebuilding never overwrites an existing `dist\FRP-Tool\config.json`,
so the other user's SSID/password survive an update.

Test the result on the build machine before shipping:

```bat
dist\FRP-Tool\FRP-Tool.exe
```

---

## 4. Running from source (needs Python)

Every import in the project is part of the standard library, so there is still
nothing to install with pip:

| File | Modules imported | Third-party? |
|---|---|---|
| `frp_gui.py` (GUI) | `argparse`, `ctypes`, `json`, `os`, `queue`, `subprocess`, `sys`, `threading`, `tkinter`, `pathlib` | no |
| `frp_portal.py` | `argparse`, `socket`, `sys`, `threading`, `time`, `webbrowser`, `pathlib` | no |
| `core/config.py` | `ipaddress`, `json`, `pathlib`, `types` | no |
| `core/dns.py` | `re`, `socket`, `struct`, `threading`, `time`, `ipaddress` | no |
| `core/http.py` | `json`, `mimetypes`, `os`, `socket`, `threading`, `http.server`, `pathlib`, `urllib.parse` | no |
| `core/log.py` | `datetime`, `threading`, `pathlib` | no |
| `core/windows.py` | `base64`, `ctypes`, `json`, `os`, `subprocess`, `sys`, `pathlib` | no |
| `gen_portal.py` (dev tool) | `html`, `re`, `pathlib` | no |

`tkinter` is part of the standard Windows Python installer — keep the
**tcl/tk and IDLE** component ticked when installing Python.

Files to copy for a source run:

```
frp_Tool\
├─ frp_gui.py             GUI (start this one)
├─ frp_portal.py          console version
├─ config.json            settings
├─ portal.bat             console launcher
├─ start_hotspot.bat      console launcher with --android-dns-dance
├─ core\                  all .py files + hotspot.ps1 (required)
├─ web\                   index.html + assets (required; missing => HTTP 500)
└─ shared\                downloads (created automatically if absent)
```

Install Python (skip if `python --version` already works):

```bat
winget install -e --id Python.Python.3.12
```

or the installer from <https://www.python.org/downloads/windows/> with
**Add python.exe to PATH** ticked. Then, in a new Command Prompt:

```bat
cd /d C:\frp_Tool
python frp_gui.py           :: GUI
python frp_portal.py --help :: console options
portal.bat                  :: console portal, asks for UAC
```

Verify the source tree loads cleanly on the new machine:

```bat
python -m compileall -q .
python frp_portal.py --help
```

Any `ModuleNotFoundError` means a `core\` file was not copied.

---

## 5. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `FRP-Tool.exe` does nothing | `_internal\` was not copied with the exe. Copy the whole folder. |
| SmartScreen "Windows protected your PC" | Unsigned exe — *More info → Run anyway*; see section 2. |
| Defender deletes the exe | Add an exclusion and submit a false-positive report; or run from source. |
| UAC prompt declined | The portal cannot bind 53/80 without it. Run the exe with **Run as administrator**. |
| `Python 3 was not found on PATH` (source only) | Reinstall with "Add to PATH", or use `py frp_portal.py`. In Windows 11 disable the Store `python.exe` app execution alias. |
| `ModuleNotFoundError: No module named 'core'` | The `core\` folder is missing; keep the layout intact. |
| `This tool is Windows-only` | Running on Linux/macOS/WSL. Use a native Windows prompt. |
| `Cannot bind UDP/53` | The hotspot is already on (ICS owns DNS) or another DNS service runs. Turn the hotspot off and retry; check `netstat -ano -p udp | findstr :53`. |
| `Cannot bind TCP/80` | IIS/Apache/Skype/Docker holds port 80. Stop it (the automatic popup needs 80). |
| `helper failed` / hotspot never starts | Enable *Settings → Network & Internet → Mobile Hotspot* once manually; if greyed out the driver/adapter does not support it. |
| Hotspot `On` but "ICS DHCP (UDP 67) is NOT listening" | Toggle Mobile Hotspot off/on in Settings, then Start again. |
| `PowerShell failed` | PowerShell 5.1 missing or blocked by policy: `powershell -NoProfile -Command "$PSVersionTable.PSVersion"`. |
| `Local DNS self-test failed` | A VPN/antivirus DNS-leak filter blocks outbound UDP 53. Harmless — inbound DNS from phones still works. |
| **Phone does not see the Wi-Fi name** | Set **Network band** to `2.4 GHz` (Windows 11's `Auto` often broadcasts on 5 GHz, which 2.4 GHz-only phones cannot scan). Confirm the log says `Band: TwoPointFourGigahertz` and `Hotspot is On; ICS DHCP is listening`. Also keep the phone close to the PC and rescan; the SSID is broadcast by the PC's Wi-Fi adapter, so it must not be disabled or in airplane mode. |
| Black console windows keep flashing | Old build: every `powershell`/`netsh` helper is now started hidden. Rebuild with `build_exe.bat` and use `dist\FRP-Tool\FRP-Tool.exe`. |
| Phone connects, no sign-in page (Android 14+) | Tick **Android DNS probe dance**, or try `--android-compat` from the console. |
| Portal shows `HTTP 500 ERROR: /index.html not found` | `web\index.html` is missing next to the exe. |

---

## 6. Checklist for the other user (packaged build)

1. Windows 10/11 64-bit, Wi-Fi adapter that supports Mobile Hotspot.
2. Copy the whole `dist\FRP-Tool` folder somewhere writable (e.g. `C:\FRP-Tool`).
3. Run `FRP-Tool.exe`; accept the UAC prompt when pressing **Start**.
4. Type the Wi-Fi name and password, tick the Android dance if the phone needs it.
5. Press **Start**, connect the phone, wait for the sign-in page; press **Stop**
   when done.
