# Setup: Windows agents, Kali lab

Use a new folder so your previous lab and project remain available. These instructions use the previously observed Kali IP `192.168.189.128`; verify it first. Commands use `python` inside virtual environments.

## 1. Stop old processes

Use Ctrl+C in the old Windows Sentinel and bridge/controller terminals and any manually started Kali Uvicorn/repair process. The new service uses the same ports 8000, 8080 and 9002. Run only the new `start.py` after this setup; there is no separate bridge command.

## 2. Kali: confirm network and SSH

```bash
ip -4 addr show eth0
sudo systemctl start ssh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

Copy only the `SHA256:...` field, not `256`, `root@kali` or `(ED25519)`. You will compare this fingerprint on Windows. If your IP changed, replace it in the commands below.

## 3. Windows: extract and prepare

Extract the ZIP so `start.py` is at:

```text
D:\team-b-sentinel-five-agents\start.py
```

In **Windows PowerShell**:

```powershell
cd D:\team-b-sentinel-five-agents
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe setup_env.py
```

Python 3.12+ is required. If Windows uses `py`, use `py -m venv .venv` for the first command. The remaining commands explicitly use the virtual environment.

## 4. Windows: copy only the execution files into a new Kali folder

```powershell
ssh kali@192.168.189.128 "mkdir -p /home/kali/sentinel-five-agent-lab"
scp .\kali_lab\*.py .\kali_lab\requirements.txt kali@192.168.189.128:/home/kali/sentinel-five-agent-lab/
```

If SSH asks to trust the host, compare the SHA256 fingerprint with step 2 before accepting. Enter your Kali password when prompted. A mismatched key must be investigated, not bypassed.

This copies an intentionally vulnerable **disposable** demo, not your actual production application. Copy it once into the new folder; re-copying `unsafe_demo.py` after repair would undo that repair.

## 5. Kali: install the lab dependencies

```bash
cd ~/sentinel-five-agent-lab
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m py_compile executor.py worker_support.py unsafe_demo.py
```

If `python` is available only inside your previous environment, activate it first, then create the new environment. Do not manually launch the server. Windows will start the executor and the lab through SSH.

## 6. Windows: configure the verified connection

In PowerShell:

```powershell
cd D:\team-b-sentinel-five-agents
$fingerprint = (Read-Host "Paste ONLY the verified SHA256 fingerprint").Trim()
.\.venv\Scripts\python.exe configure_kali.py --host 192.168.189.128 --fingerprint "$fingerprint"
```

This preserves the API tokens generated in step 3 and sets the Kali upstream and lab folder. The SSH password is never saved in `.env`.

## 7. Windows: start all five agents

```powershell
.\.venv\Scripts\python.exe start.py
```

After fingerprint verification, enter your Kali SSH password. Expected:

```text
Kali executor ready. All five LangGraph agents run in Windows.
Dashboard: http://127.0.0.1:8000 | Protected gateway: http://127.0.0.1:8080
```

Keep this terminal open. Open `http://127.0.0.1:8000`. In `.env`, copy `ADMIN_TOKEN` into the dashboard token field, enter the API address `http://127.0.0.1:8000`, and press Connect. Do not share this token.

The five agent cards and continuous upstream health will now be visible. `source repair enabled` means configured, not that a repair has already happened.

## 8. SQL injection demonstration — Windows, second terminal

```powershell
cd D:\team-b-sentinel-five-agents
.\.venv\Scripts\python.exe demo_requests.py sql
```

One bounded SQL injection request goes to your own gateway. Expected: HTTP 403 initially (or 429 if an existing guard matches). In the dashboard, select the SQL incident and follow Boss → Detection → Boss → SOC → Boss → Repair → Boss → Monitor → Boss.

Wait for the final result. For the supplied vulnerable lab, expect incident status `repaired`, source status `repaired`, passing candidate tests and `live_http_tests: passed`. `already_safe` means the query was already parameterized. `mitigated` alone means a gateway rule was verified; inspect the source result separately.

Kali report command:

```bash
cd ~/sentinel-five-agent-lab
source .venv/bin/activate
python -m json.tool repair-runs/latest-report.json
```

The three source tests cover normal Mouse search, apostrophe input and an injection input. Live verification also checks valid and invalid login responses.

## 9. Brute-force demonstration — Windows

```powershell
.\.venv\Scripts\python.exe demo_requests.py brute
```

This sends only six wrong-password attempts, one second apart, to the demo account. Expect initial 401 responses, then 429. The dashboard should show a brute-force incident with `mitigated`, an active `login_cooldown`, and `source_repair.status: not_applicable`.

A cooldown restricts login requests from the triggering source for 120 seconds. Normal product searches still work. After the cooldown and failed-login window expire, the same source can try the public demo credentials again:

```text
username: student
password: sentinel-lab-only
```

These credentials are for the demonstration only and create no real authenticated session.

## 10. Optional local LLM explanation

The five-agent workflow works without an LLM. If you already have an Ollama model installed and served locally, set `OLLAMA_MODEL` to that exact installed model name in `.env` and restart. SOC will request an advisory explanation of structured evidence. A model outage cannot approve a patch or change the deterministic policy.

## Troubleshooting

- **Port occupied:** stop the old bridge/controller/Uvicorn instance. On Kali inspect `ss -ltnp 'sport = :9002'`; on Windows inspect `Get-NetTCPConnection -State Listen -LocalPort 8000,8080`. Identify the process before stopping it.
- **Fingerprint mismatch:** run step 2 locally in Kali and compare with `.env`. Never disable verification.
- **No incident:** use port 8080. Requests directly to Kali do not pass through Sentinel. An existing temporary guard may block repeats without queuing another incident; wait for expiry.
- **Manual intervention / outcome unknown:** inspect Kali `repair-runs/latest-report.json`, any `pending.json`, and `app.log`. A healthy website does not prove its query was repaired.
- **Unsupported source pattern:** gateway mitigation can still work, but no generic patch is guessed. The onboarded source must satisfy its test contract.
- **Windows cannot connect:** verify Kali IP, SSH, and VM network connectivity. Update with `configure_kali.py` if the address changed.
- **No Kali available:** `.env` defaults can run the safe local Windows demo (`START_LAB=true`, `AUTO_SQL_REPAIR=false`). That mode demonstrates detection and policies only, not remote SQL source repair.

## Tests

Windows portable tests:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Linux-only executor/SSH integration tests are skipped on Windows. The included validation report states which environment was actually tested. No test result guarantees universal attack detection or compatibility with an arbitrary application.
