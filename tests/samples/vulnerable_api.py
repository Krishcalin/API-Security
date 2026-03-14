"""
Intentionally vulnerable Python API for API Security Scanner testing.
DO NOT use this code in production — every pattern here is insecure.
"""
import os
import json
import subprocess
import logging

from flask import Flask, request, jsonify, redirect, session
from flask_cors import CORS
import jwt
import requests
import sqlite3

app = Flask(__name__)

# ── API2-001: Flask route without auth ──
@app.route("/api/users", methods=["POST", "PUT", "DELETE"])
def manage_users():
    return jsonify({"status": "ok"})

# ── API2-002: JWT secret hardcoded ──
jwt_secret = "SuperSecretKeyThatShouldNotBeHere123"
token = jwt.encode({"user": "admin"}, jwt_secret, algorithm="HS256")

# ── API2-003: JWT weak algorithm ──
decoded = jwt.decode(token, jwt_secret, algorithms=["HS256"])

# ── API2-004: JWT verify disabled ──
unsafe_decode = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})

# ── API2-005: API key in query string ──
api_key = request.args.get("api_key")

# ── API2-006: Password compared without hashing ──
@app.route("/login", methods=["POST"])
def login():
    if request.json["password"] == request.json.get("stored"):
        return jsonify({"token": "abc"})
    password == request.json.get("pass")

# ── API2-007: Basic auth ──
from flask_httpauth import HTTPBasicAuth
basic_auth = HTTPBasicAuth()

# ── API2-008: CSRF disabled ──
from flask_wtf.csrf import csrf_exempt
@csrf_exempt
@app.route("/api/transfer", methods=["POST"])
def transfer():
    return jsonify({"ok": True})

# ── API2-009: Session fixation ──
@app.route("/auth", methods=["POST"])
def auth():
    session["user"] = request.json.get("username")
    return jsonify({"ok": True})

# ── API2-010: OAuth2 implicit flow ──
oauth_config = {"response_type": "token", "grant": "implicit flow"}

# ── API1-001: BOLA — direct ID from request ──
@app.route("/api/account")
def get_account():
    account_id = request.args.get("account_id")
    return jsonify(db.get(account_id))

# ── API1-002: Flask path param ID ──
@app.get("/api/users/<int:id>")
def get_user(id):
    return jsonify(db.find(id))

# ── API1-006: Sequential ID ──
# CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT);

# ── API3-001: Mass assignment ──
@app.route("/api/profile", methods=["PUT"])
def update_profile():
    user.update(**request.json)
    return jsonify(user.to_dict())

# ── API3-002: Excessive data exposure ──
@app.route("/api/user/<int:id>")
def user_detail(id):
    user = User.query.get(id)
    return jsonify(user.to_dict())

# ── API3-003: Internal fields in response ──
response_data = {
    "username": "admin",
    "password_hash": "bcrypt$abc123",
    "internal_id": 42,
    "ssn": "123-45-6789",
    "credit_card": "4111111111111111",
}

# ── API4-001: No rate limiting (Flask route) ──
@app.route("/api/search", methods=["GET"])
def search():
    return jsonify([])

# ── API4-002: No pagination ──
results = User.query.filter().all()

# ── API4-003: Unbounded file upload ──
app.config["MAX_CONTENT_LENGTH"] = None

# ── API4-004: No timeout ──
response = requests.get("https://external-api.com/data", timeout=None)

# ── API4-006: GraphQL without depth limit ──
from graphene import ObjectType, Schema
schema = Schema(query=Query)

# ── API5-001: Admin endpoint ──
@app.route("/admin/users/create", methods=["POST"])
def create_admin_user():
    return jsonify({"created": True})

# ── API5-002: Privilege escalation ──
@app.route("/api/user/role", methods=["PUT"])
def update_role():
    role = request.json.get("role")
    is_admin = request.json.get("is_admin")
    return jsonify({"ok": True})

# ── API5-004: DELETE without auth ──
@app.delete("/api/records/<int:id>")
def delete_record(id):
    return jsonify({"deleted": True})

# ── API6-001: Login without CAPTCHA ──
@app.route("/api/login", methods=["POST"])
def api_login():
    return jsonify({"token": "x"})

# ── API6-002: Payment without anti-automation ──
@app.route("/api/checkout", methods=["POST"])
def checkout():
    return jsonify({"order": "confirmed"})

# ── API6-003: Password reset ──
@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    return jsonify({"sent": True})

# ── API7-001: SSRF ──
@app.route("/api/fetch")
def fetch_url():
    url = request.args.get("url")
    resp = requests.get(request.args.get("target_url"))
    return jsonify(resp.json())

# ── API7-002: Open redirect ──
@app.route("/redirect")
def redir():
    redirect_to = request.args.get("redirect_to")
    return redirect(redirect_to)

# ── API7-003: Webhook SSRF ──
@app.route("/api/webhooks", methods=["POST"])
def register_webhook():
    webhook_url = request.json.get("callback_url")
    return jsonify({"registered": True})

# ── API8-001: CORS wildcard ──
CORS(app, origins="*")
app.config["Access-Control-Allow-Origin"] = "*"

# ── API8-002: Debug mode ──
app.config["DEBUG"] = True

# ── API8-003: Verbose errors ──
@app.errorhandler(500)
def handle_error(e):
    import traceback
    return jsonify({"error": traceback.format_exc()}), 500

# ── API8-005: HTTP serving ──
# http://0.0.0.0:5000/api

# ── API8-007: Bind to 0.0.0.0 ──
app.run(host="0.0.0.0", port=5000)

# ── API8-008: TLS verify disabled ──
resp = requests.post("https://api.example.com", verify=False)

# ── API8-009: CORS credentials ──
CORS(app, supports_credentials=True)

# ── API9-002: Swagger endpoint ──
@app.route("/api-docs")
def api_docs():
    return jsonify(spec)

# ── API9-003: Deprecated endpoint ──
@app.route("/api/v1/legacy")
def legacy():
    """deprecated endpoint"""
    return jsonify({})

# ── API9-004: Debug endpoint ──
@app.route("/debug/info")
def debug_info():
    return jsonify({"env": dict(os.environ)})

# ── API10-001: Third-party response unvalidated ──
external = requests.get("https://api.partner.com/data")
data = external.json()["results"]

# ── API10-004: Follow redirects ──
r = requests.get("https://untrusted.com", allow_redirects=True)

# ── API-INJ-001: SQL injection ──
@app.route("/api/query")
def query():
    q = request.args.get("q")
    cursor.execute(f"SELECT * FROM users WHERE name = '{q}'")

# ── API-INJ-002: NoSQL injection ──
from pymongo import MongoClient
db = MongoClient().mydb
result = db.users.find(request.json)
record = db.orders.findOne(request.args)

# ── API-INJ-003: Command injection ──
@app.route("/api/ping")
def ping():
    host = request.args.get("host")
    output = subprocess.run(request.args.get("cmd"), shell=True)

# ── API-INJ-006: XXE ──
import xml.etree.ElementTree as ET
tree = ET.parse(request.files["xml"])

# ── API-INJ-007: Path traversal ──
@app.route("/api/download")
def download():
    return open(request.args.get("file")).read()

# ── API-SEC-001: Hardcoded API key ──
api_key = "sk_live_abcdefghij1234567890"
api_secret = "secret_abcdefghijklmnop1234"

# ── API-SEC-002: Hardcoded password ──
database_password = "P@ssw0rd!SuperSecret123"

# ── API-SEC-003: Private key ──
key = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1234567890...
-----END RSA PRIVATE KEY-----"""

# ── API-SEC-004: AWS credentials ──
aws_key = "AKIAIOSFODNN7EXAMPLE01"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY01234567"

# ── API-SEC-005: Database connection string ──
db_url = "postgresql://admin:secret123@db.example.com:5432/mydb"
mongo_uri = "mongodb://root:password@mongo.example.com:27017/admin"

# ── API-SEC-006: Bearer token ──
headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123.def456"}

# ── API-TLS-001: HTTP endpoint ──
partner_api = "http://api.partner.com/v1/data"

# ── API-TLS-002: Weak TLS ──
import ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)

# ── API-LOG-001: Sensitive data in logs ──
logging.info(f"User login with password: {password} and token: {token}")

# ── API-LOG-003: Full request body logged ──
logging.debug(f"Request body: {request.body}")
