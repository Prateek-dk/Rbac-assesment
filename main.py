from __future__ import annotations

import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

load_dotenv()
DB_PATH = os.getenv("DATABASE_PATH", "./data/nagarkot.db")
JWT_SECRET = os.getenv("JWT_SECRET", "local-development-secret-change-me")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
APP_NAME = os.getenv("APP_NAME", "Nagarkot Access Control Service")
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

app = FastAPI(title=APP_NAME, version="1.0.0")
bearer = HTTPBearer(auto_error=False)

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
  user_type TEXT NOT NULL DEFAULT 'staff', active INTEGER NOT NULL DEFAULT 1,
  client_id TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS grants (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL REFERENCES users(id),
  role TEXT NOT NULL, actions_json TEXT NOT NULL,
  client_id TEXT, branch_id TEXT, direction TEXT, mode TEXT, stage TEXT,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_grants_user_active ON grants(user_id, revoked_at);
CREATE INDEX IF NOT EXISTS idx_grants_scope ON grants(client_id, branch_id, direction, mode, stage);
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY, client_id TEXT NOT NULL, branch_id TEXT NOT NULL,
  direction TEXT NOT NULL, mode TEXT NOT NULL, stage TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL,
  maker_id TEXT, checker_id TEXT, filer_id TEXT,
  updated_at TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_jobs_scope ON jobs(client_id, branch_id, direction, mode, stage);
CREATE INDEX IF NOT EXISTS idx_jobs_client_updated ON jobs(client_id, updated_at);
CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL,
  actor_id TEXT NOT NULL, action TEXT NOT NULL, target_type TEXT NOT NULL,
  target_id TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL,
  before_json TEXT, after_json TEXT, grant_evidence_json TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_target_time ON audit_events(target_type, target_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_actor_time ON audit_events(actor_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_action_time ON audit_events(action, occurred_at);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
"""

def now() -> str:
    return datetime.now(timezone.utc).isoformat()

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with db() as c:
        c.executescript(SCHEMA)

@app.on_event("startup")
def startup():
    init_db()

def rowdict(row):
    return dict(row) if row else None

def audit(c, actor, action, target_type, target_id, decision, reason,
          before=None, after=None, evidence=None, metadata=None):
    c.execute("""INSERT INTO audit_events
      (occurred_at,actor_id,action,target_type,target_id,decision,reason,
       before_json,after_json,grant_evidence_json,metadata_json)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
      (now(), actor, action, target_type, target_id, decision, reason,
       json.dumps(before, default=str) if before is not None else None,
       json.dumps(after, default=str) if after is not None else None,
       json.dumps(evidence or [], default=str), json.dumps(metadata or {})))

def issue_token(user_id: str) -> str:
    return jwt.encode({"sub": user_id, "exp": datetime.now(timezone.utc) +
                       timedelta(minutes=int(os.getenv("JWT_EXPIRE_MINUTES", "480")))},
                      JWT_SECRET, algorithm=JWT_ALGORITHM)

def current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    if not creds:
        raise HTTPException(401, "Bearer token required")
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")
    with db() as c:
        user = c.execute("SELECT * FROM users WHERE id=?", (payload.get("sub"),)).fetchone()
    if not user or not user["active"]:
        raise HTTPException(401, "Unknown or inactive user")
    return rowdict(user)

def get_grants(c, user_id):
    return [rowdict(x) for x in c.execute(
        "SELECT * FROM grants WHERE user_id=? AND revoked_at IS NULL", (user_id,)).fetchall()]

def scope_matches(g, job):
    for key in ("client_id", "branch_id", "direction", "mode", "stage"):
        if g.get(key) is not None and g.get(key) != job.get(key):
            return False
    return True

def matching_grants(c, user_id, action, job):
    if not user_id:
        return []
    grants = get_grants(c, user_id)
    found = []
    for g in grants:
        try:
            actions = json.loads(g["actions_json"])
        except Exception:
            actions = []
        if action in actions and scope_matches(g, job):
            found.append(g)
    return found

def decide(c, user, action, job):
    """Deterministic policy decision. The LLM is never consulted here."""
    uid = user["id"]
    if not user["active"]:
        return False, "identity_inactive", []
    # Client identities are always pinned to their own client, regardless of grants.
    if user["user_type"] == "client":
        if action != "read" or job["client_id"] != user.get("client_id"):
            return False, "client_identity_is_read_only_and_client_scoped", []
    evidence = matching_grants(c, uid, action, job)
    if not evidence:
        return False, "no_active_grant_matches_all_scope_dimensions", []
    roles = {g["role"] for g in evidence}
    if action == "check" and job.get("maker_id") == uid:
        return False, "maker_cannot_check_own_job_separation_of_duties", evidence
    if action == "check" and job.get("checklist_preparer_id") == uid:
        return False, "checklist_preparer_cannot_approve_same_job", evidence
    return True, "matching_scoped_grant", evidence

def require_decision(c, user, action, job):
    allowed, reason, evidence = decide(c, user, action, job)
    return allowed, reason, evidence

class Scope(BaseModel):
    client_id: Optional[str] = None
    branch_id: Optional[str] = None
    direction: Optional[str] = None
    mode: Optional[str] = None
    stage: Optional[str] = None

class AuthorizeRequest(BaseModel):
    user_id: Optional[str] = None
    job_id: str
    action: str

class JobCreate(BaseModel):
    id: Optional[str] = None
    client_id: str
    branch_id: str
    direction: str
    mode: str
    description: str = ""

class ActionRequest(BaseModel):
    action: str
    reason: str = ""

class GrantCreate(BaseModel):
    user_id: str
    role: str
    actions: list[str]
    scope: Scope = Field(default_factory=Scope)

class ChatRequest(BaseModel):
    question: str

def job_dict(row):
    return rowdict(row)

@app.get("/health")
def health():
    return {"status": "ok", "service": APP_NAME}

@app.get("/me")
def me(user=Depends(current_user)):
    with db() as c:
        grants = get_grants(c, user["id"])
    clean = [{k: g[k] for k in ("id","role","actions_json","client_id","branch_id",
                                 "direction","mode","stage","created_at")} for g in grants]
    return {"user": user, "grants": clean}

@app.post("/authorize")
def authorize(req: AuthorizeRequest, actor=Depends(current_user)):
    target_id = req.user_id or actor["id"]
    with db() as c:
        is_admin = "admin" in {g["role"] for g in get_grants(c, actor["id"])}
        if target_id != actor["id"] and not is_admin:
            raise HTTPException(403, "You may evaluate your own access; admin is required to evaluate another user")
        target = c.execute("SELECT * FROM users WHERE id=?", (target_id,)).fetchone()
        job = c.execute("SELECT * FROM jobs WHERE id=?", (req.job_id,)).fetchone()
        if not target or not job:
            raise HTTPException(404, "User or job not found")
        target, job = rowdict(target), job_dict(job)
        allowed, reason, evidence = decide(c, target, req.action, job)
        audit(c, actor["id"], "authorize:"+req.action, "job", req.job_id,
              "allowed" if allowed else "denied", reason,
              evidence=evidence, metadata={"evaluated_user": target_id})
    return {"allowed": allowed, "user_id": target_id, "job_id": req.job_id,
            "action": req.action, "reason": reason,
            "matching_grants": evidence}

@app.post("/jobs", status_code=201)
def create_job(req: JobCreate, user=Depends(current_user)):
    job_id = req.id or f"JOB-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
    job = {"id":job_id,"client_id":req.client_id,"branch_id":req.branch_id,
           "direction":req.direction,"mode":req.mode,"stage":"confirmed",
           "description":req.description,"created_by":user["id"],"maker_id":None,
           "checker_id":None,"filer_id":None,"updated_at":now(),"version":1}
    with db() as c:
        allowed, reason, evidence = decide(c, user, "create", job)
        if not allowed:
            audit(c,user["id"],"create_job","job",job_id,"denied",reason,evidence=evidence)
            raise HTTPException(403, reason)
        c.execute("""INSERT INTO jobs(id,client_id,branch_id,direction,mode,stage,description,
          created_by,updated_at,version) VALUES(?,?,?,?,?,?,?,?,?,?)""",
          (job_id,req.client_id,req.branch_id,req.direction,req.mode,"confirmed",
           req.description,user["id"],now(),1))
        audit(c,user["id"],"create_job","job",job_id,"allowed","job_created",
              after=job,evidence=evidence)
    return job

@app.get("/jobs/{job_id}")
def get_job(job_id: str, user=Depends(current_user)):
    with db() as c:
        r = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not r: raise HTTPException(404,"Job not found")
        job = rowdict(r)
        allowed, reason, evidence = decide(c,user,"read",job)
        audit(c,user["id"],"read_job","job",job_id,"allowed" if allowed else "denied",
              reason,evidence=evidence)
        if not allowed: raise HTTPException(403,reason)
        return job

@app.post("/jobs/{job_id}/actions")
def job_action(job_id: str, req: ActionRequest, user=Depends(current_user)):
    action = req.action.lower().strip()
    transitions = {
        "prepare": ("confirmed","prepared","prepare","maker_id"),
        "check": ("prepared","checked","check","checker_id"),
        "file": ("checked","filed","file","filer_id"),
        "cancel": (None,"cancelled","cancel",""),
        "reopen": ("cancelled","confirmed","reopen",""),
    }
    if action not in transitions: raise HTTPException(400,"Unsupported action")
    if action in ("cancel","reopen") and not req.reason.strip():
        raise HTTPException(400,"A reason is required for cancel/reopen")
    with db() as c:
        r = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not r: raise HTTPException(404,"Job not found")
        job = rowdict(r)
        expected, new_stage, permission, actor_field = transitions[action]
        admin_override = "admin" in {g["role"] for g in get_grants(c,user["id"])}
        if action in ("cancel","reopen"):
            if not admin_override:
                allowed, reason, evidence = decide(c,user,permission,job)
            else:
                allowed, reason, evidence = True, "admin_break_glass", matching_grants(c,user["id"],"admin_override",job)
        else:
            allowed, reason, evidence = decide(c,user,permission,job)
        if action == "cancel" and job["stage"] == "filed" and not admin_override:
            allowed, reason = False, "filed_job_requires_admin_break_glass"
        if action == "reopen" and not admin_override:
            allowed, reason = False, "reopening_requires_admin_break_glass"
        if expected and job["stage"] != expected:
            allowed, reason = False, f"invalid_transition_expected_{expected}_found_{job['stage']}"
        if action == "cancel" and job["stage"] == "cancelled":
            allowed, reason = False, "job_already_cancelled"
        if not allowed:
            audit(c,user["id"],action,"job",job_id,"denied",reason,before=job,evidence=evidence)
            raise HTTPException(403,reason)
        before = dict(job)
        changes = {"stage":new_stage,"updated_at":now(),"version":job["version"]+1}
        if actor_field: changes[actor_field] = user["id"]
        c.execute("UPDATE jobs SET stage=?,updated_at=?,version=version+1 WHERE id=?",
                  (new_stage,changes["updated_at"],job_id))
        if actor_field:
            c.execute(f"UPDATE jobs SET {actor_field}=? WHERE id=?", (user["id"],job_id))
        after = dict(before); after.update(changes)
        audit(c,user["id"],action,"job",job_id,"allowed",
              req.reason.strip() or reason,before=before,after=after,evidence=evidence,
              metadata={"break_glass": bool(admin_override and action in ("cancel","reopen"))})
    return {"job_id":job_id,"stage":new_stage,"version":after["version"]}

@app.get("/jobs/{job_id}/history")
def job_history(job_id: str, user=Depends(current_user)):
    with db() as c:
        job = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not job: raise HTTPException(404,"Job not found")
        allowed, reason, evidence = decide(c,user,"read",rowdict(job))
        if not allowed: raise HTTPException(403,reason)
        rows = c.execute("""SELECT * FROM audit_events WHERE target_type='job'
          AND target_id=? ORDER BY occurred_at,id""",(job_id,)).fetchall()
        return {"job_id":job_id,"events":[rowdict(x) for x in rows]}

@app.get("/audit")
def audit_search(actor_id: Optional[str]=None, target_id: Optional[str]=None,
                 action: Optional[str]=None, start: Optional[str]=None,
                 end: Optional[str]=None, limit: int=Query(100,ge=1,le=500),
                 user=Depends(current_user)):
    with db() as c:
        if "admin" not in {g["role"] for g in get_grants(c,user["id"])}:
            raise HTTPException(403,"admin role required")
        clauses, args = [], []
        for col,val in (("actor_id",actor_id),("target_id",target_id),("action",action)):
            if val: clauses.append(f"{col}=?"); args.append(val)
        if start: clauses.append("occurred_at>=?"); args.append(start)
        if end: clauses.append("occurred_at<=?"); args.append(end)
        sql = "SELECT * FROM audit_events" + (" WHERE "+" AND ".join(clauses) if clauses else "")
        sql += " ORDER BY occurred_at DESC,id DESC LIMIT ?"; args.append(limit)
        return {"events":[rowdict(x) for x in c.execute(sql,args).fetchall()]}

@app.post("/admin/grants", status_code=201)
def add_grant(req: GrantCreate, user=Depends(current_user)):
    allowed_actions = {"read","create","prepare","check","file","cancel","reopen","admin_override"}
    if not req.actions or not set(req.actions).issubset(allowed_actions):
        raise HTTPException(400,"Invalid or empty action list")
    if req.scope.direction not in (None,"import","export"): raise HTTPException(400,"Invalid direction")
    if req.scope.mode not in (None,"air","fcl","lcl"): raise HTTPException(400,"Invalid mode")
    with db() as c:
        is_admin = "admin" in {g["role"] for g in get_grants(c,user["id"])}
        if not is_admin: raise HTTPException(403,"admin role required")
        if req.user_id == user["id"]:
            audit(c,user["id"],"grant_create","user",req.user_id,"denied",
                  "admin_self_escalation_blocked")
            raise HTTPException(403,"Admins cannot grant permissions to themselves")
        if not c.execute("SELECT 1 FROM users WHERE id=?",(req.user_id,)).fetchone():
            raise HTTPException(404,"Target user not found")
        s=req.scope
        cur=c.execute("""INSERT INTO grants(user_id,role,actions_json,client_id,branch_id,
          direction,mode,stage,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
          (req.user_id,req.role,json.dumps(req.actions),s.client_id,s.branch_id,s.direction,
           s.mode,s.stage,user["id"],now()))
        grant={"id":cur.lastrowid,"user_id":req.user_id,"role":req.role,
               "actions":req.actions,"scope":s.model_dump()}
        audit(c,user["id"],"grant_create","grant",str(cur.lastrowid),"allowed",
              "grant_created",after=grant)
        return grant

@app.delete("/admin/grants/{grant_id}")
def revoke_grant(grant_id: int, user=Depends(current_user)):
    with db() as c:
        if "admin" not in {g["role"] for g in get_grants(c, user["id"])}:
            raise HTTPException(403, "admin role required")
        row = c.execute("SELECT * FROM grants WHERE id=? AND revoked_at IS NULL", (grant_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Active grant not found")
        grant_row = rowdict(row)
        if grant_row["user_id"] == user["id"]:
            raise HTTPException(403, "Admins cannot revoke their own grant")
        revoked = now()
        c.execute("UPDATE grants SET revoked_at=? WHERE id=?", (revoked, grant_id))
        audit(c, user["id"], "grant_revoke", "grant", str(grant_id), "allowed",
              "grant_revoked", before=grant_row, after={**grant_row, "revoked_at": revoked})
        return {"grant_id": grant_id, "revoked_at": revoked}

@app.post("/chat")
def chat(req: ChatRequest, user=Depends(current_user)):
    from agent import answer_question
    return answer_question(req.question, user, DB_PATH)

# Internal read-only helpers used by agent.py
def evidence_snapshot(question: str, user: dict, db_path: str):
    q=question.lower()
    ids=set(re.findall(r"\bJOB-[A-Za-z0-9_-]+\b",question,re.I))
    user_ids=set(re.findall(r"\bu_[A-Za-z0-9_-]+\b",question,re.I))
    date_match=re.search(r"\b(20\d{2}-\d{2}-\d{2})\b",question)
    with sqlite3.connect(db_path) as c:
        c.row_factory=sqlite3.Row
        result={"question":question,"requester":user["id"],"jobs":[],"audit_events":[],"users":[],"permission_principles":[
            "Permission checks are deterministic and scope across client, branch, direction, mode and stage.",
            "A maker cannot check their own job.",
            "Client identities are read-only and restricted to their own client.",
            "Grant changes do not rewrite historical audit events."
        ]}
        for jid in ids:
            jr=c.execute("SELECT * FROM jobs WHERE id=?",(jid,)).fetchone()
            if jr:
                j=dict(jr)
                # Only return job evidence if requester may read it, or requester is admin.
                gs=c.execute("SELECT * FROM grants WHERE user_id=? AND revoked_at IS NULL",(user["id"],)).fetchall()
                admin=any(x["role"]=="admin" for x in gs)
                allowed=admin or (user.get("user_type")=="client" and user.get("client_id")==j["client_id"])
                for g in gs:
                    acts=json.loads(g["actions_json"])
                    allowed |= ("read" in acts and all(g[k] is None or g[k]==j[k] for k in
                                  ("client_id","branch_id","direction","mode","stage")))
                if allowed:
                    result["jobs"].append(j)
                    ev=c.execute("SELECT * FROM audit_events WHERE target_type='job' AND target_id=? ORDER BY occurred_at,id",(jid,)).fetchall()
                    result["audit_events"] += [dict(x) for x in ev]
        for uid in user_ids:
            ur=c.execute("SELECT id,name,active,user_type FROM users WHERE id=?",(uid,)).fetchone()
            if ur: result["users"].append(dict(ur))
        if date_match:
            d=date_match.group(1)
            ev=c.execute("SELECT * FROM audit_events WHERE occurred_at LIKE ? ORDER BY occurred_at,id LIMIT 500",(d+"%",)).fetchall()
            # Date-wide actor list is only returned to admin.
            admin=c.execute("""SELECT 1 FROM grants WHERE user_id=? AND role='admin'
              AND revoked_at IS NULL LIMIT 1""",(user["id"],)).fetchone()
            if admin: result["audit_events"] += [dict(x) for x in ev]
        # For a named user, include grants only when requester is admin or asking about self.
        if user_ids and (user["id"] in user_ids or c.execute(
            "SELECT 1 FROM grants WHERE user_id=? AND role='admin' AND revoked_at IS NULL",
            (user["id"],)).fetchone()):
            for uid in user_ids:
                gs=c.execute("SELECT * FROM grants WHERE user_id=? AND revoked_at IS NULL",(uid,)).fetchall()
                result.setdefault("grants",{})[uid]=[dict(x) for x in gs]
    return result
