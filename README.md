# Nagarkot Forwarders — Access Control Service

A locally runnable FastAPI service demonstrating scoped RBAC, workflow authorization,
separation of duties, immutable audit history, and an evidence-grounded LangChain/Groq
assistant. SQLite is used for a zero-dependency local setup; its indexes and query patterns
support the assessment's 500-user / 200,000-job test dataset. For a multi-instance production
deployment, move the same schema to PostgreSQL and use a managed identity provider.

## Security design

**The policy engine is authoritative. The LLM is not.** Every permission decision is made
by deterministic Python code. The chatbot may call read-only evidence functions and explain
their results; it cannot execute workflow actions, mutate grants, or invent policy.

### Scope dimensions

A grant has a role, action set, and optional scope for client, branch, direction
(`import`/`export`), mode (`air`/`fcl`/`lcl`), and job stage. A `null` scope dimension means
"all values" for that dimension. Grants are additive, except that separation-of-duty
constraints and explicit policy restrictions still apply.

### Built-in roles

- **maker** — create/prepare jobs within assigned scope.
- **checker** — check prepared jobs within assigned scope, subject to maker/checker conflict.
- **filer** — file checked jobs within assigned scope.
- **viewer** — read jobs within assigned scope.
- **client_viewer** — read jobs belonging to their own client; cannot change workflow state.
- **admin** — manage grants and perform documented break-glass recovery. Admin is not allowed
  to silently self-escalate; grant changes to the acting admin's own identity are rejected.
- **parser** — machine identity for idempotent automated ingestion/update operations.

Roles are shorthand. Actual access is represented by grant rows and action names. A user may
have multiple grants with different scopes, e.g. maker for every client and checker for two
clients only. The sample seed prints each user's effective grant description.

### Workflow

`confirmed -> prepared -> checked -> filed`

A job may also be cancelled from a non-filed state. A filed job can only be cancelled by an
admin break-glass action with a reason. A cancelled job can be reopened by an admin with a
reason, returning it to `confirmed`. The maker cannot check their own job. A checklist
preparer cannot approve/check the same job, even if they hold the checker grant.

An absent owner does not disable the job: another appropriately scoped maker/checker/filer
can act. Responsibility is represented by grants, not by a single named owner. Grant changes
are effective immediately for future decisions; past audit events retain the actor and
permission snapshot used at decision time.

### Audit model

Audit rows are append-only. SQLite triggers reject UPDATE and DELETE. Each row stores actor,
action, target, timestamp, decision, reason, request metadata, and a JSON snapshot of the
applicable grant evidence. Denied attempts are audited too. The `job_history` endpoint returns
the full ordered history. For stronger production tamper evidence, export audit events to
immutable object storage or a separately administered append-only log.

## Setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Set JWT_SECRET and optionally GROQ_API_KEY in .env
python seed_data.py --small
uvicorn main:app --reload
```

Open `http://127.0.0.1:8000/docs`.

### Demo authentication

Seed data creates a `demo_tokens.json` file containing signed JWTs for seeded users.
Use a token as `Authorization: Bearer <token>` in Swagger's Authorize dialog or curl.
These are development-only credentials. Do not use seeded tokens or the default secret
outside a local demonstration.

Example:

```bash
TOKEN=$(python -c "import json; print(json.load(open('demo_tokens.json'))['u_maker_all'])")
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/me
```

## Generate data

```bash
python seed_data.py --small
python seed_data.py --scale
```

`--small` creates 5 branches, 10 clients, 20 users and 300 jobs with edge-case users.
`--scale` creates 5 branches, 10 clients, 500 users and 200,000 jobs. It resets the local
database before seeding. Use `--jobs 10000` to override the scale job count.

The seed includes:
- a Maker across all clients;
- a Checker for only selected clients;
- a Checker restricted to one client, one branch, and imports only;
- a maker/checker conflict on the same job;
- an absent user (inactive identity);
- a client-side user restricted to their own client;
- an admin;
- an overnight parser service identity.

## API overview

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Health check |
| GET | `/me` | Current identity and grants |
| POST | `/authorize` | Explain whether an action is permitted |
| POST | `/jobs` | Create a job |
| GET | `/jobs/{job_id}` | Read a job |
| POST | `/jobs/{job_id}/actions` | Prepare/check/file/cancel/reopen |
| GET | `/jobs/{job_id}/history` | Immutable event history |
| GET | `/audit` | Filter audit events |
| POST | `/admin/grants` | Add scoped grant (admin only) |
| DELETE | `/admin/grants/{grant_id}` | Revoke scoped grant (admin only) |
| POST | `/chat` | Ask an evidence-grounded natural-language question |

For `POST /jobs/{id}/actions`, send `{"action":"prepare"}` or `check`, `file`,
`cancel`, `reopen`. Cancellation/reopening requires a non-empty `reason`. A filed-job
cancellation and reopening are admin break-glass operations.

## Chat examples

```json
{"question":"Why can user u_checker_limited check this job but u_maker_all cannot?"}
{"question":"Who could have changed job JOB-000012 on 2026-10-03?"}
{"question":"Show the history for JOB-000012"}
{"question":"Why was user u_client_01 denied access to a job for client_02?"}
{"question":"Who has checker access for client_01, branch_01, import, air?"}
```

The chat endpoint extracts likely identifiers, fetches authoritative policy/audit evidence,
and asks Groq to explain that evidence. Without `GROQ_API_KEY`, it returns a deterministic
evidence summary so the service remains usable locally.

## Production hardening / deliberate scope

Before production: replace demo JWT issuance with OIDC/JWKS validation; use PostgreSQL;
add migrations, rate limits, structured secrets management, TLS, request correlation IDs,
retention/legal-hold policy, monitoring, backup/restore drills, and integration tests.
Use database-level permissions and an external append-only audit sink for stronger
tamper resistance. The local bootstrap token file is intentionally a demo convenience.
