Nagarkot Forwarders — Access Control Service

A locally runnable FastAPI service demonstrating scoped RBAC, workflow authorization, separation of duties, immutable audit history, and an evidence-grounded LangChain/Groq assistant. SQLite is used for a zero-dependency local setup; its indexes and query patterns support the assessment's 500-user / 200,000-job test dataset. For a multi-instance production deployment, move the same schema to PostgreSQL and use a managed identity provider.

Security Design

The policy engine is authoritative. The LLM is not. Every permission decision is made by deterministic Python code. The chatbot may call read-only evidence functions and explain their results; it cannot execute workflow actions, mutate grants, or invent policy.

Scope Dimensions

A grant has a role, action set, and optional scope for client, branch, direction (import/export), mode (air/fcl/lcl), and job stage. A null scope dimension means "all values" for that dimension. Grants are additive, except that separation-of-duty constraints and explicit policy restrictions still apply.

Built-in Roles

maker — create/prepare jobs within assigned scope.

checker — check prepared jobs within assigned scope, subject to maker/checker conflict.

filer — file checked jobs within assigned scope.

viewer — read jobs within assigned scope.

client_viewer — read jobs belonging to their own client; cannot change workflow state.

admin — manage grants and perform documented break-glass recovery. Admin is not allowed to silently self-escalate; grant changes to the acting admin's own identity are rejected.

parser — machine identity for idempotent automated ingestion/update operations.

Roles are shorthand. Actual access is represented by grant rows and action names. A user may have multiple grants with different scopes, e.g. maker for every client and checker for two clients only. The sample seed prints each user's effective grant description.

Workflow

confirmed -> prepared -> checked -> filed

A job may also be cancelled from a non-filed state. A filed job can only be cancelled by an admin break-glass action with a reason. A cancelled job can be reopened by an admin with a reason, returning it to confirmed. The maker cannot check their own job. A checklist preparer cannot approve/check the same job, even if they hold the checker grant.

Audit Model

Audit rows are append-only. SQLite triggers reject UPDATE and DELETE. Each row stores actor, action, target, timestamp, decision, reason, request metadata, and a JSON snapshot of the applicable grant evidence. Denied attempts are audited too.

Verification & Test Screenshots

The following screenshots capture live verification results from Swagger UI (/docs) running against the local instance.

1. Unauthorized Token Response

How it works: Sending a request with an expired, malformed, or missing JWT Bearer token to a protected endpoint (POST /authorize).

Expected Output: HTTP 401 Unauthorized with the response body {"detail": "Invalid or expired token"}.

2. Token Regeneration & CLI Output

How it works: Running the token refresh script (refresh_tokens.py) after seeding data (python seed_data.py --small) to regenerate valid signed JWTs in demo_tokens.json.

Expected Output: CLI confirmation Tokens generated successfully! with active tokens mapped to user identifiers.

3. Current Identity & Grants (/me)

How it works: Authenticating as u_admin and calling GET /me to inspect the user profile and associated RBAC grants.

Expected Output: HTTP 200 OK returning user details and full administrative grants including admin_override.

4. Service Health Check (/health)

How it works: Calling GET /health to verify service availability and database connectivity.

Expected Output: HTTP 200 OK returning {"status": "ok", "service": "Nagarkot Access Control Service"}.

5. Policy Engine Enforcement & Separation of Duties

How it works: Testing POST /authorize where user u_maker_checker_conflict attempts to check JOB-000001 (a job they originally prepared).

Expected Output: HTTP 200 OK returning allowed: false due to the strict rule: "maker_cannot_check_own_job_separation_of_duties".

6. Evidence-Grounded Chatbot Response

How it works: Querying the LLM assistant via POST /chat with the question: "Who changed JOB-000001 and what is its current status?".

Expected Output: HTTP 200 OK returning an authoritative summary derived from immutable audit logs and job state tables, showing the exact maker, authorization attempts, and current stage.
