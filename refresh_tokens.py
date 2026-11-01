import json
from main import db, issue_token

with db() as conn:
    users = conn.execute(
        "SELECT id FROM users"
    ).fetchall()

tokens = {
    user["id"]: issue_token(user["id"])
    for user in users
}

with open("demo_tokens.json", "w") as f:
    json.dump(tokens, f, indent=2)

print("Tokens generated successfully!")