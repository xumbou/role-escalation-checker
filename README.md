# role-escalation-checker

Active checker for a **Broken Access Control / privilege-escalation** class of
vulnerability on REST APIs that expose a *"promote a user to an administrative
role on a resource"* endpoint, e.g.:

```
POST {base}/{resource}/administrators/{userId}      (often with no body)
```

If the backend does not re-verify that the caller is **already** a legitimate
administrator of *that specific resource*, an authenticated low-privilege user
may escalate:

- **Vertical** — promote themselves to admin of their own resource;
- **Horizontal (IDOR)** — promote themselves on *someone else's* resource by
  changing the resource id in the path.

Maps to **CWE-269** (Improper Privilege Management) + **CWE-639** (IDOR),
**OWASP WSTG-ATHZ-02 / ATHZ-04**, and OWASP Top 10 *Broken Access Control*.

> ⚠️ **Authorized use only.** This is an active testing tool. Run it **only**
> against systems you are explicitly authorized to test — your own lab, a CTF,
> or a signed penetration-testing engagement. Unauthorized use against
> third-party systems is illegal.

## Two complementary tools in this repo

1. **`bacscan/`** — a generic, reusable **access-control scanner** (cross-engagement):
   HAR ingestion → auth profiles (YAML) → differential engine → probes (IDOR/BOLA) →
   impact-confirmation plugins → JSON findings + Markdown report. See
   [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
2. **`tools/check_role_escalation.py`** — the standalone **single-vuln checker** for role
   promotion (sniper), also available as a confirmation **plugin** inside bacscan.

The scan *finds* candidates; the checker/plugin *proves* impact.

### bacscan in 30 seconds

```bash
pip install -r requirements.txt
python tests/test_e2e.py     # demo: detects 6 BAC classes on a vulnerable mock
python -m bacscan.cli --config examples/engagement.example.yaml --har traffic.har
# also accepts:  --openapi spec.yaml   --access-matrix access_matrix.json
```

**Probes**: `idor` (BOLA), `idor_dynamic` (id harvesting/chaining + sequential enum),
`bfla` (force-browse + verb-tampering/asymmetry), `bopla` (mass-assignment),
`leakage` (existence-leakage oracle), `graphql` (introspection + IDOR via variables).
**Confirmation**: the `role_escalation` plugin, or **declarative YAML plugins**
(`declarative_plugins:` — steps / validate / rollback, no code).

**Pluggable auth** (per profile): `bearer`, `cookie`, `oauth` (**token refresh on 401**),
and `csrf` (token pulled from a cookie/endpoint, injected on mutating verbs).

**Protocols**: REST/JSON (full); GraphQL (introspection + variable-IDOR + mutation BFLA);
SOAP/XML rides the generic differential engine (POST XML replayed per profile, no dedicated
probe); **gRPC and WebSocket are not supported** (binary/HTTP2/persistent — out of scope).

**Safe by default**: mutating requests run only with `safety.destructive: true` (auto rollback).

**False-positive triage**: every finding is re-checked for exploitability and tagged
`confirmed` / `false_positive` / `inconclusive`, each with a **logged reason** (`output.triage_log`).
It separates *benign* FPs (public/shared resources) from *tool-limitation* signals (e.g. empty
2xx, unverifiable effect) — so you understand each FP and spot when an oracle needs tightening.

## Install on Kali Linux / Debian

```bash
# Option A - pipx (recommended, isolated; the Kali-friendly way):
sudo apt install -y pipx
pipx install .            # provides the `bacscan` command in your PATH
bacscan --help

# Option B - one-liner (pipx if present, else a local .venv):
./install.sh

# Option C - distro packages, no build step:
sudo apt install -y python3-requests python3-yaml
python3 -m bacscan --config examples/engagement.example.yaml --har traffic.har
```

`bacscan`, `python3 -m bacscan` and `python3 -m bacscan.cli` are equivalent.
Run the full local validation suite with `python3 tests/run_checks.py`.
Real-target validation against VAmPI (found the real leak, triaged a real FP): see
[docs/FIELD-TEST-vampi.md](docs/FIELD-TEST-vampi.md).

## Why it is safe to use responsibly

- **Non-destructive by default.** The mutating promotion request is sent only
  with `--exploit`, and the tool **rolls the state back automatically**.
- **Scope guard.** `--allow-host` is **required**; any other host is refused
  before a single request leaves your machine.
- **IDOR observes the status code only.** On a third-party resource the tool
  reads/alters nothing — the HTTP response code is the proof.
- **Methodology, not just a 200.** It establishes a baseline, runs controls
  (no-auth → expect 401, bogus-resource → 404/403), tests the escalation, then
  **confirms the real effect** (did the role actually become admin?).

## Install

```bash
pip install requests
```

## Usage

Safe phases only (no mutation — baseline + controls):

```bash
python tools/check_role_escalation.py \
  --base-url https://api.lab.local --allow-host api.lab.local \
  --jwt eyJ... --user-id u-123 --resource-id r-456
```

Full vertical test (mutating, auto rollback) + IDOR (status code only):

```bash
python tools/check_role_escalation.py \
  --base-url https://api.lab.local --allow-host api.lab.local \
  --jwt eyJ... --user-id u-123 --resource-id r-456 \
  --exploit --idor-resource r-OTHER
```

### Adapting to your target API

Paths are templated with `{resource}` and `{user}`. Override the defaults to
match the API under test:

| Option | Default | Purpose |
|---|---|---|
| `--list-path` | `/{resource}/members` | GET: list members and their roles |
| `--promote-path` | `/{resource}/administrators/{user}` | the escalation endpoint |
| `--promote-method` | `POST` | promotion HTTP method |
| `--promote-body` | *(none)* | optional promotion body |
| `--role-field` | `role` | member field holding the role |
| `--admin-role` | `ADMINISTRATOR` | role value meaning "admin" |
| `--rollback-method` | `DELETE` | how to undo the promotion |
| `--rollback-path` | `/{resource}/members/{user}` | rollback endpoint |
| `--rollback-body` | *(none)* | optional rollback body (e.g. JSON-Patch) |

JSON-Patch style rollback example:

```bash
python tools/check_role_escalation.py ... --exploit \
  --rollback-method PATCH --rollback-path /{resource} \
  --rollback-body '[{"op":"remove","path":"/members/{user}"}]'
```

## Verdict matrix

| Vertical | Impact | IDOR | Verdict |
|---|---|---|---|
| 2xx | role = admin | 2xx | **CRITICAL** (escalation + IDOR) |
| 2xx | role = admin | 4xx | **HIGH** (vertical real, ownership OK) |
| 2xx | no effect | — | **INVESTIGATE** (200 no-op?) |
| 401/403 | — | — | **REFUTED** (server enforces) |

Exit code is `1` when a vulnerability is materialized (CRITICAL/HIGH), `0`
otherwise. Every run writes a timestamped JSON evidence log (`evidence_*.json`).

## License

MIT — see [LICENSE](LICENSE).
