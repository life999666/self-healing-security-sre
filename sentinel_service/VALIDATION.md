# Validation — 22 September 2026

Command: `python -m pytest tests -q`

Result: **41 passed in 18.41 seconds** on the development Linux/Python 3.12 environment.

Coverage:
- All 21 original gateway/detection tests still pass after the five-agent refactor.
- Exactly five LangGraph nodes and Boss dispatch/return order.
- SQL concatenation, f-string, %s and .format() candidates, direct and assigned queries.
- Normal input, apostrophes, injection regression and patch idempotence.
- Unsupported dynamic identifiers, wildcard construction and formatting conversions refused.
- Brute-force cooldown scope, other-source access and expiry.
- Continuous monitoring without an incident.
- Real HTTP source repair, rollback and concurrent-edit preservation.
- Actual loopback SSH using a generated Ed25519 test key and test-only password.
- SSH host key verification before password callback.
- Full gateway → five agents → SSH → SQL source repair → HTTP verification flow.
- Brute-force requests through the gateway while the real SSH-started lab runs.
- Disconnect during unverified deployment restores source.

Frontend JavaScript passed `node --check website/app.js`. A browser layout test was not completed because the environment had no installed browser binary.

The actual user's Windows/Kali machines were not accessed. Linux-only integration tests are skipped when this suite runs on Windows. Run the setup and demonstrations in START-HERE.md to verify that deployment. No detection-accuracy or universal SQL-repair claim is made.

The candidate test process runs on the disposable Kali VM, not in a hardened sandbox. The optional SOC LLM integration was not exercised with a live model; deterministic operation was tested.
