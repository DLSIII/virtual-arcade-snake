import os, json, base64, uuid
from datetime import datetime, timezone

from flask import Flask, render_template, request, jsonify, redirect, url_for
from azure.cosmos import CosmosClient

app = Flask(__name__)

# ---------- Auth helpers (Container Apps Authentication / Easy Auth) ----------
def get_user():
    # Sometimes name is directly present
    name = request.headers.get("X-MS-CLIENT-PRINCIPAL-NAME")
    if name:
        return {"name": name}

    # Otherwise decode the principal (Base64 JSON) 
    principal_b64 = request.headers.get("X-MS-CLIENT-PRINCIPAL")
    if not principal_b64:
        return None

    try:
        decoded = base64.b64decode(principal_b64).decode("utf-8")
        principal = json.loads(decoded)
        # "name" might be present depending on provider
        return {"name": principal.get("name") or principal.get("userDetails") or "user"}
    except Exception:
        return {"name": "user"}

def is_logged_in():
    return get_user() is not None

@app.before_request
def require_login_for_app_routes():
    p = request.path

    # Allow unauthenticated access to these routes
    if p.startswith("/static/") or p.startswith("/.auth/") or p in ("/login", "/health"):
        return None

    # Everything else requires login
    if not is_logged_in():
        return redirect(url_for("login"))

# ---------- Cosmos DB ----------
def get_container():
    conn = os.getenv("COSMOS_CONNECTION_STRING", "")
    if not conn:
        return None

    db_name = os.getenv("COSMOS_DB", "arcade")
    container_name = os.getenv("COSMOS_CONTAINER", "scores")

    client = CosmosClient.from_connection_string(conn)
    db = client.get_database_client(db_name)
    return db.get_container_client(container_name)

# ---------- Pages ----------
@app.get("/login")
def login():
    # Login page links to built-in /.auth endpoints 
    return render_template("login.html")

@app.get("/")
def snake():
    user = get_user()
    return render_template("snake.html", user=user["name"])

@app.get("/leaderboard")
def leaderboard_page():
    user = get_user()
    return render_template("leaderboard.html", user=user["name"])

@app.get("/health")
def health():
    return "ok", 200

# ---------- APIs ----------
@app.post("/api/score")
def save_score():
    user = get_user() or {"name": "guest"}
    data = request.get_json(force=True, silent=True) or {}
    score = int(data.get("score", 0))

    item = {
        "id": str(uuid.uuid4()),
        "game": "snake",  # partition key
        "user": user["name"],
        "score": score,
        "ts": datetime.now(timezone.utc).isoformat(),
    }

    container = get_container()
    if not container:
        return jsonify({"ok": False, "error": "Cosmos not configured"}), 500

    container.upsert_item(item)
    return jsonify({"ok": True})

@app.get("/api/leaderboard")
def leaderboard_api():
    limit = int(request.args.get("limit", 10))
    limit = max(1, min(limit, 50))

    container = get_container()
    if not container:
        return jsonify({"ok": False, "error": "Cosmos not configured"}), 500

    query = f"""
    SELECT TOP {limit} c.user, c.score, c.ts
    FROM c
    WHERE c.game = @game
    ORDER BY c.score DESC, c.ts ASC
    """
    items = list(container.query_items(
        query=query,
        parameters=[{"name": "@game", "value": "snake"}],
        enable_cross_partition_query=False
    ))

    return jsonify({"ok": True, "items": items})
