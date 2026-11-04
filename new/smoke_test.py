"""Minimal API smoke-test; run after seed_data.py and uvicorn."""
import json, os, urllib.request, urllib.error
BASE=os.getenv("BASE_URL","http://127.0.0.1:8000")
tokens=json.load(open("demo_tokens.json"))
def call(path, token, method="GET", payload=None):
    data=json.dumps(payload).encode() if payload is not None else None
    req=urllib.request.Request(BASE+path,data=data,method=method,
        headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(req) as r: return r.status,json.loads(r.read())
    except urllib.error.HTTPError as e: return e.code,e.read().decode()
assert call("/health",tokens["u_viewer"])[0]==200
status,result=call("/authorize",tokens["u_maker_checker_conflict"],"POST",
                   {"job_id":"JOB-000001","action":"check"})
assert status==200 and result["allowed"] is False, result
status,result=call("/authorize",tokens["u_checker_limited"],"POST",
                   {"job_id":"JOB-000010","action":"check"})
assert status==200, result
print("Smoke tests passed.")
