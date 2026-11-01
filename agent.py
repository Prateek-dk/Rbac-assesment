"""Evidence-grounded natural-language explanation. Never performs authorization."""
import json
import os
from dotenv import load_dotenv
from main import evidence_snapshot

load_dotenv()

SYSTEM = """You are the audit explanation layer for Nagarkot Forwarders.
You are NOT an authorization engine. Use only the supplied JSON evidence.
Never infer a permission, actor, timestamp, or event that is not present.
If the evidence is insufficient, say exactly what is missing.
Explain scope dimensions (client, branch, direction, mode, stage), active grants,
workflow state, separation of duties, and audit chronology when relevant.
Distinguish 'could have acted' (current matching grant and policy) from
'actually acted' (a recorded audit event). A current grant does not prove a
historical grant existed at an earlier date. Do not disclose data absent from evidence.
Be concise, cite job IDs/event IDs/user IDs from the evidence, and state uncertainty.
"""

def answer_question(question: str, user: dict, db_path: str):
    evidence = evidence_snapshot(question, user, db_path)
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return {
            "answer": deterministic_fallback(question, evidence),
            "mode": "deterministic_fallback",
            "evidence": evidence
        }
    try:
        from langchain_groq import ChatGroq
        from langchain_core.messages import SystemMessage, HumanMessage
        llm = ChatGroq(model=os.getenv("GROQ_MODEL","llama-3.3-70b-versatile"),
                       temperature=0, api_key=api_key)
        response = llm.invoke([
            SystemMessage(content=SYSTEM),
            HumanMessage(content="Question:\n"+question+"\n\nVerified evidence JSON:\n"+
                         json.dumps(evidence, default=str))
        ])
        return {"answer": response.content, "mode":"groq_langchain",
                "evidence":evidence}
    except Exception as exc:
        return {"answer":deterministic_fallback(question,evidence),
                "mode":"deterministic_fallback",
                "warning":"Groq unavailable; returned deterministic evidence summary.",
                "evidence":evidence}

def deterministic_fallback(question, ev):
    if not ev["jobs"] and not ev["audit_events"] and not ev["users"]:
        return ("I cannot establish the answer from the records available to your identity. "
                "Provide an accessible job ID, a permitted audit date, or ask an administrator "
                "to review the relevant evidence.")
    parts=[]
    for job in ev["jobs"]:
        parts.append(f"Job {job['id']} is currently {job['stage']} for client "
                     f"{job['client_id']}, branch {job['branch_id']}, "
                     f"{job['direction']}/{job['mode']}. Maker: {job.get('maker_id') or 'not assigned'}; "
                     f"checker: {job.get('checker_id') or 'not assigned'}; "
                     f"filer: {job.get('filer_id') or 'not assigned'}.")
    if ev["audit_events"]:
        events=sorted(ev["audit_events"],key=lambda x:(x["occurred_at"],x["id"]))
        parts.append("Recorded audit events: "+ "; ".join(
            f"event {x['id']} at {x['occurred_at']}: actor {x['actor_id']} "
            f"{x['action']} on {x['target_id']} ({x['decision']}; {x['reason']})"
            for x in events))
    if ev["users"]:
        parts.append("User records: "+json.dumps(ev["users"]))
    parts.append("Important: recorded actions prove who acted; current grants alone do not prove "
                 "who was authorized on a past date. Historical grant snapshots are needed for that.")
    return "\n".join(parts)
