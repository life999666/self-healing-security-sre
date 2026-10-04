# Complete Merge Guide: Sentinel Five Agents + Self-Healing SRE Agent

## 1. Why the merge uses two internal services first

The two source projects use incompatible LangGraph versions:

- Sentinel: `langgraph==1.2.11`
- SRE: `langgraph==0.2.28`

Do **not** combine their requirements into one virtual environment in the first merge. Keep each project in its own virtual environment and connect them with a local HTTP bridge. This preserves both working graphs and makes troubleshooting much easier.

## 2. Final v1 layout

```text
Self-Healing-Security-SRE/
├── sentinel_service/
│   ├── sentinel/
│   │   ├── core.py
│   │   ├── web.py
│   │   ├── remote.py
│   │   ├── sql_patterns.py
│   │   └── sre_bridge.py          # NEW
│   ├── kali_lab/
│   ├── website/
│   ├── tests/
│   ├── start.py                   # MODIFIED
│   ├── lab_app.py
│   ├── demo_requests.py
│   ├── setup_env.py
│   └── requirements.txt
├── sre_service/
│   ├── agents.py
│   ├── graph.py
│   ├── tools.py
│   ├── state.py
│   ├── config.py
│   ├── security_state.py          # NEW
│   ├── security_tools.py          # NEW
│   ├── security_agents.py         # NEW
│   ├── security_graph.py          # NEW
│   ├── security_service.py        # NEW
│   └── requirements.txt
├── integration/
│   └── incident-contract.json
├── setup-merged.ps1
├── test-merged.ps1
├── start-merged.ps1
└── MERGE_GUIDE.md
```

## 3. Responsibilities after the merge

```text
Client
  -> Sentinel Gateway
      -> deterministic attack detection
      -> immediate bounded containment
      -> Boss -> Detection -> SOC -> Repair -> Monitor
      -> structured incident handoff
          -> SRE Security Investigator
              -> source inspection
              -> root-cause explanation
              -> Mechanic generates repair
              -> deterministic security validation
              -> GitHub Pull Request
```

Sentinel is the **security control plane**. SRE is the **source remediation and PR plane**.

## 4. First-time setup

Open PowerShell in the merged root and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\setup-merged.ps1
```

Or set them up manually.

### Sentinel

```powershell
cd sentinel_service
python -m venv venv
venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m pytest -q
deactivate
```

### SRE

```powershell
cd ..\sre_service
python -m venv venv
venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m pytest -q
deactivate
```

## 5. Create a shared bridge token

Run once:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Copy the generated value. Use the **same value** in both `.env` files.

Do not commit either `.env` file.

## 6. Configure Sentinel

Copy:

```powershell
cd sentinel_service
Copy-Item .env.example .env
```

Keep/generated values for `ADMIN_TOKEN` and `COLLECTOR_TOKEN`. Add/set:

```env
START_LAB=true
LOCAL_LAB_MODE=unsafe
UPSTREAM_URL=http://127.0.0.1:9000
AUTO_SQL_REPAIR=false
LOGIN_PATH=/login
LOGIN_LIMIT=5
LOGIN_WINDOW=60
RULE_TTL=120
ENABLE_HTTP_FLOOD=false

SRE_BRIDGE_ENABLED=true
SRE_BRIDGE_URL=http://127.0.0.1:8101
SRE_BRIDGE_TOKEN=PASTE_THE_SHARED_TOKEN_HERE
SRE_BRIDGE_TIMEOUT=180
```

For the first **end-to-end learning demonstration**, use `LOCAL_LAB_MODE=unsafe`. This starts the supplied intentionally vulnerable `kali_lab/unsafe_demo.py` only on `127.0.0.1:9000`, behind the Sentinel gateway. The SRE service therefore inspects the same source that is serving the incident.

If you only want detection/containment against already-safe code, use `LOCAL_LAB_MODE=safe`.

Keep `AUTO_SQL_REPAIR=false` for the first Windows-only merge. Sentinel contains the incident while the SRE service creates the persistent source-code PR.

## 7. Configure SRE

Copy:

```powershell
cd ..\sre_service
Copy-Item .env.example .env
```

Use the same Groq/Gemini and GitHub values that already worked in the original SRE project.

Important fields:

```env
LLM_PROVIDER=groq
GROQ_API_KEY=YOUR_KEY
GROQ_MODEL=USE_THE_MODEL_THAT_ALREADY_WORKED_IN_YOUR_SRE_SETUP

GITHUB_TOKEN=YOUR_GITHUB_TOKEN
GITHUB_REPO=YOUR_USERNAME/YOUR_MERGED_REPOSITORY
GITHUB_BRANCH=main
MAX_ITERATIONS=3

SECURITY_API_PORT=8101
BRIDGE_TOKEN=PASTE_THE_SAME_SHARED_TOKEN_HERE
SECURITY_TARGET_FILE=../sentinel_service/kali_lab/unsafe_demo.py
SECURITY_TARGET_REPO_PATH=sentinel_service/kali_lab/unsafe_demo.py
```

`SECURITY_TARGET_FILE` is the local source inspected by the SRE service.
`SECURITY_TARGET_REPO_PATH` is the path to the same file inside the GitHub repository.

## 8. Put the merged project in GitHub before testing PR creation

Create a new empty GitHub repository for the merged project. Then from the merged root:

```powershell
git init
git branch -M main
git add .
git status
```

Confirm neither `.env` file nor either `venv/` is staged.

Then:

```powershell
git commit -m "Initial merged Sentinel and SRE system"
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
git push -u origin main
```

Set `GITHUB_REPO=YOUR_USERNAME/YOUR_REPOSITORY` in `sre_service/.env`.

## 9. Start both systems

From the merged root:

```powershell
.\start-merged.ps1
```

Or start manually.

### Terminal 1: SRE remediation API

```powershell
cd sre_service
venv\Scripts\activate
python security_service.py
```

Expected:

```text
Uvicorn running on http://127.0.0.1:8101
```

Health check:

```text
http://127.0.0.1:8101/health
```

### Terminal 2: Sentinel

```powershell
cd sentinel_service
venv\Scripts\activate
python start.py
```

Expected:

```text
SRE remediation bridge enabled.
Dashboard: http://127.0.0.1:8000 | Protected gateway: http://127.0.0.1:8080
```

## 10. Dashboard

Open:

```text
http://127.0.0.1:8000
```

Enter:

- API address: `http://127.0.0.1:8000`
- Admin token: value of `ADMIN_TOKEN` from `sentinel_service/.env`

The dashboard will show the existing five Sentinel agents and incident evidence. The merge adds an **SRE remediation** details block to the incident view.

## 11. Test SQL detection and SRE handoff

Open Terminal 3:

```powershell
cd sentinel_service
venv\Scripts\activate
python demo_requests.py sql
```

Expected request output:

```text
SQL lab request: 403 ...
Normal product search: 200
```

The gateway blocks the suspicious request before it is forwarded to the intentionally vulnerable loopback lab. Normal traffic is still proxied to the lab.

Expected pipeline:

```text
SQL-like request
 -> Sentinel gateway detects SQL signature
 -> request blocked
 -> incident queued
 -> Boss Agent
 -> Detection Agent validates evidence
 -> SOC Analyst plans sql_guard
 -> Repair Agent validates/applies temporary gateway policy
 -> Monitor Agent verifies health/policy
 -> Sentinel calls SRE bridge
 -> SRE deterministic source inspection finds unsafe SQL in kali_lab/unsafe_demo.py
 -> SRE Investigator explains root cause
 -> Mechanic generates parameterized-query repair
 -> Validator rejects unsafe/broken candidates and accepts a safe candidate
 -> GitHub PR creator updates sentinel_service/kali_lab/unsafe_demo.py
 -> Sentinel incident stores SRE result
```

Expected dashboard SRE block resembles:

```json
{
  "status": "pr_created",
  "vulnerability_confirmed": true,
  "unsafe_findings": [
    "line 18: execute() uses dynamic SQL variable 'query' created near line 14"
  ],
  "fix_validated": true,
  "pr_status": "created",
  "pr_url": "[SUCCESS] Pull Request created successfully!...",
  "duration_ms": 9000.0
}
```

The exact timing and LLM wording will vary.

## 12. Test brute-force containment

Run:

```powershell
python demo_requests.py brute
```

Expected:

```text
Failed-login demonstration 1 : HTTP 401
...
Failed-login demonstration 5 : HTTP 401/429 depending on timing
Failed-login demonstration 6 : HTTP 429
Normal product search: 200
```

Sentinel creates a `login_cooldown` rule scoped to the attacking source. In v1 the SRE service returns:

```json
{
  "status": "no_code_change_required",
  "reason": "This incident type is handled by Sentinel containment/monitoring in v1."
}
```

This is intentional. A brute-force attempt is not automatically evidence that application source code must be rewritten.

## 13. What "self-healing" means in Windows-only v1

The first merged version performs:

```text
Detect -> Prevent/Contain -> Investigate source -> Generate repair -> Validate -> Create PR
```

It does **not** auto-merge or silently modify production code.

For SQL incidents, Sentinel immediately reduces impact with an expiring gateway guard. The SRE service creates a validated code repair PR for persistence.

This is safer than auto-merging LLM output.

## 14. Full live self-healing mode with Kali

The supplied Sentinel project already has a stronger live source-repair path for its onboarded SQL lab.

After Windows-only integration works:

1. Prepare the Kali lab using the original Sentinel instructions.
2. Set in `sentinel_service/.env`:

```env
START_LAB=false
AUTO_SQL_REPAIR=true
KALI_IP=YOUR_PRIVATE_KALI_IP
KALI_USER=kali
KALI_APP_PORT=9002
KALI_LAB_PATH=/home/kali/sentinel-five-agent-lab
KALI_HOST_FINGERPRINT=SHA256:YOUR_VERIFIED_FINGERPRINT
UPSTREAM_URL=http://YOUR_PRIVATE_KALI_IP:9002
```

3. Keep `SRE_BRIDGE_ENABLED=true`.

Then the SQL path becomes:

```text
Detect
 -> immediate gateway containment
 -> Sentinel Repair Agent connects to verified Kali SSH host
 -> source candidate generated on Windows
 -> candidate staged on Kali
 -> regression tests
 -> live apply
 -> health and security verification
 -> rollback on failed verification
 -> SRE bridge creates a GitHub PR so the repair is persisted in source control
```

This is the strongest mode of the combined architecture.

## 15. Output and timing metrics

Sentinel already records:

- `created`
- `sentinel_completed`
- `sentinel_duration_ms`
- `completed`
- `duration_ms`

After this merge:

- `sentinel_duration_ms` = detection/containment/verification workflow duration before SRE handoff.
- `duration_ms` = total incident processing including the SRE handoff.
- `sre_remediation.duration_ms` = SRE investigation -> validation -> PR duration.

Do **not** call PR-creation time "MTTR" unless the repaired code has actually been deployed and recovery verified. In Kali live-repair mode, Sentinel's verified `repaired` status is much closer to a real MTTR endpoint.

## 16. Files added by the merge

### Sentinel

- `sentinel/sre_bridge.py`: sends only structured incident evidence to SRE.

### SRE

- `security_state.py`: state contract for security remediation.
- `security_tools.py`: deterministic source scanning + security validation.
- `security_agents.py`: Security Investigator, Mechanic, Validator, PR nodes.
- `security_graph.py`: security remediation LangGraph.
- `security_service.py`: authenticated local FastAPI bridge endpoint.

### Root

- `integration/incident-contract.json`: example handoff contract.
- `setup-merged.ps1`: creates both virtual environments.
- `test-merged.ps1`: runs both original test suites.
- `start-merged.ps1`: starts SRE service and Sentinel in separate terminals.

## 17. Existing files changed by the merge

### `sentinel_service/sentinel/core.py`

Changes:

1. `Engine.__init__` now accepts `incident_sink=None`.
2. The final `finish()` node stores Sentinel-only timing, calls the SRE bridge, stores the result in `incident['sre_remediation']`, then records total duration.
3. `snapshot()` reports whether the SRE bridge is enabled.

No detection rule behavior is removed.

### `sentinel_service/start.py`

Creates `SREBridge` when `SRE_BRIDGE_ENABLED=true` and injects it into `Engine`.

### `sentinel_service/website/app.js`

Adds an expandable `SRE remediation` block to each incident.

### `.env.example` files

Add the shared bridge configuration and source target configuration.

## 18. Important architectural limits

1. Sentinel SQL signatures prove a suspicious request pattern, **not** a vulnerability by themselves.
2. The SRE service independently scans the configured source before allowing patch generation.
3. The supplied SRE validator originally performs only AST/static checks. The merged security workflow adds an SQL-specific deterministic check, but you should still add project-specific unit/integration tests for your real application.
4. `kali_lab/unsafe_demo.py` is an intentionally vulnerable learning fixture. It is not production code.
5. The merged system should not auto-merge Pull Requests in the first version.
6. Brute-force/flood events remain containment/monitoring events unless separate source evidence justifies a code repair.

## 19. Recommended next upgrades after this works

1. Replace complete-file LLM generation with minimal unified-diff patches.
2. Run the repaired repository in a disposable container/worktree.
3. Execute the repository's real test suite before PR creation.
4. Add SAST and dependency checks.
5. Add agent-based behavioral anomaly detection to the Sentinel Detection Agent.
6. Track incident onset, detection, containment, repair, deployment, and recovery separately for formal MTTD/MTTC/MTTR reporting.
7. Later, after both graphs are stable on a single LangGraph version, optionally collapse the two service graphs into one unified graph.
