import argparse, json, os, random, sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
import jwt

load_dotenv()
from main import DB_PATH, db, init_db, issue_token, now, JWT_SECRET, JWT_ALGORITHM

BRANCHES=[f"branch_{i:02d}" for i in range(1,6)]
CLIENTS=[f"client_{i:02d}" for i in range(1,11)]
MODES=["air","fcl","lcl"]
DIRECTIONS=["import","export"]

def add_user(c, uid, name, user_type="staff", active=1, client_id=None):
    c.execute("INSERT INTO users(id,name,email,user_type,active,client_id,created_at) "
              "VALUES(?,?,?,?,?,?,?)",
              (uid,name,uid+"@example.test",user_type,active,client_id,now()))

def grant(c, uid, role, actions, **scope):
    c.execute("""INSERT INTO grants(user_id,role,actions_json,client_id,branch_id,direction,
      mode,stage,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
      (uid,role,json.dumps(actions),scope.get("client_id"),scope.get("branch_id"),
       scope.get("direction"),scope.get("mode"),scope.get("stage"),"seed",now()))

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--small",action="store_true")
    p.add_argument("--scale",action="store_true")
    p.add_argument("--jobs",type=int,default=None)
    args=p.parse_args()
    if not args.small and not args.scale: args.small=True
    nusers=500 if args.scale else 20
    njobs=args.jobs if args.jobs is not None else (200000 if args.scale else 300)
    # A seed run is a deliberate full reset. Recreate the DB so append-only audit
    # triggers remain effective during normal operation but do not block reseeding.
    db_file = Path(DB_PATH)
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(db_file) + suffix)
        if candidate.exists(): candidate.unlink()
    init_db()
    with db() as c:
        # Edge-case identities are stable across both data profiles.
        special=[
          ("u_admin","Operations Admin","staff",1),
          ("u_maker_all","Global Maker","staff",1),
          ("u_checker_limited","Limited Checker","staff",1),
          ("u_checker_import_branch","Import Branch Checker","staff",1),
          ("u_maker_checker_conflict","Maker Checker Conflict","staff",1),
          ("u_absent","Absent Staff Member","staff",0),
          ("u_client_01","Client One Portal User","client",1),
          ("svc_overnight_parser","Overnight Parser","service",1),
          ("u_filer","Global Filer","staff",1),
          ("u_viewer","Global Viewer","staff",1),
        ]
        for x in special:
            add_user(c,*x, client_id=("client_01" if x[0]=="u_client_01" else None))
        for i in range(1,max(0,nusers-len(special))+1):
            add_user(c,f"u_staff_{i:03d}",f"Staff {i:03d}")
        grant(c,"u_admin","admin",["read","create","prepare","check","file","admin_override"])
        grant(c,"u_maker_all","maker",["read","create","prepare"])
        grant(c,"u_checker_limited","checker",["read","check"],client_id="client_01")
        grant(c,"u_checker_limited","checker",["read","check"],client_id="client_03")
        grant(c,"u_checker_import_branch","checker",["read","check"],client_id="client_02",
              branch_id="branch_01",direction="import")
        grant(c,"u_maker_checker_conflict","maker",["read","create","prepare"])
        grant(c,"u_maker_checker_conflict","checker",["read","check"])
        grant(c,"u_client_01","client_viewer",["read"],client_id="client_01")
        grant(c,"svc_overnight_parser","parser",["read","create","prepare"])
        grant(c,"u_filer","filer",["read","file"])
        grant(c,"u_viewer","viewer",["read"])
        # Additional staff receive narrow random grants.
        for i in range(1,max(0,nusers-len(special))+1):
            uid=f"u_staff_{i:03d}"
            cl=random.choice(CLIENTS)
            grant(c,uid,random.choice(["maker","checker","viewer"]),
                  random.choice([["read"],["read","prepare"],["read","check"]]),
                  client_id=cl,branch_id=random.choice(BRANCHES))
        # Jobs in bulk using executemany.
        batch=[]
        for i in range(1,njobs+1):
            client=CLIENTS[(i-1)%len(CLIENTS)]
            branch=BRANCHES[(i-1)%len(BRANCHES)]
            direction=DIRECTIONS[(i-1)%2]
            mode=MODES[(i-1)%3]
            stage=["confirmed","prepared","checked","filed"][(i-1)%4]
            jid=f"JOB-{i:06d}"
            maker="u_maker_checker_conflict" if i==1 else ("u_maker_all" if i%3 else None)
            checker="u_checker_limited" if i%10==0 else None
            filer="u_filer" if stage=="filed" else None
            updated=(datetime.now(timezone.utc)-timedelta(days=i%45)).isoformat()
            batch.append((jid,client,branch,direction,mode,stage,f"Shipment {i}",
                          "seed",maker,checker,filer,updated,1))
            if len(batch)>=5000:
                c.executemany("""INSERT INTO jobs(id,client_id,branch_id,direction,mode,stage,
                  description,created_by,maker_id,checker_id,filer_id,updated_at,version)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",batch); batch=[]
        if batch:
            c.executemany("""INSERT INTO jobs(id,client_id,branch_id,direction,mode,stage,
              description,created_by,maker_id,checker_id,filer_id,updated_at,version)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",batch)
        # Seed a machine-originated overnight parser event for audit/chat demonstrations.
        parser_job = c.execute("SELECT * FROM jobs WHERE id='JOB-000020'").fetchone()
        if parser_job:
            parser_time = (datetime.now(timezone.utc)-timedelta(days=1)).replace(hour=2, minute=15, second=0, microsecond=0).isoformat()
            c.execute("""INSERT INTO audit_events(occurred_at,actor_id,action,target_type,target_id,
              decision,reason,before_json,after_json,grant_evidence_json,metadata_json)
              VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
              (parser_time,"svc_overnight_parser","parser_update","job","JOB-000020",
               "allowed","overnight parser synchronization",None,
               json.dumps({"job_id":"JOB-000020","source":"overnight_parser"}),
               "[]",json.dumps({"service_identity":True,"batch_id":"nightly-seed"})))
        # Ensure key example job and history demonstrate maker/checker separation.
        j=c.execute("SELECT * FROM jobs WHERE id='JOB-000001'").fetchone()
        if j:
            before=dict(j)
            c.execute("UPDATE jobs SET stage='prepared',maker_id='u_maker_checker_conflict' WHERE id='JOB-000001'")
            c.execute("""INSERT INTO audit_events(occurred_at,actor_id,action,target_type,target_id,
              decision,reason,before_json,after_json,grant_evidence_json,metadata_json)
              VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
              ((datetime.now(timezone.utc)-timedelta(days=3)).isoformat(),"u_maker_checker_conflict",
               "prepare","job","JOB-000001","allowed","seeded historical preparation",
               json.dumps(before),json.dumps({"stage":"prepared","maker_id":"u_maker_checker_conflict"}),
               "[]","{}"))
    # Demo tokens for all seeded identities (including inactive user to test rejection).
    with db() as c:
        ids=[r[0] for r in c.execute("SELECT id FROM users")]
    tokens={uid:issue_token(uid) for uid in ids}
    Path("demo_tokens.json").write_text(json.dumps(tokens,indent=2))
    print(f"Seeded {nusers} users, 5 branches, 10 clients and {njobs:,} jobs in {DB_PATH}")
    print("Demo tokens written to demo_tokens.json (development only).")
    print("Key users: u_admin, u_maker_all, u_checker_limited, "
          "u_checker_import_branch, u_maker_checker_conflict, u_absent, "
          "u_client_01, svc_overnight_parser, u_filer, u_viewer")
    print("Example job: JOB-000001")

if __name__=="__main__":
    main()
