from flask import Flask, request, jsonify
import sqlite3
import subprocess
import os
import bcrypt

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me")

DB_PATH = "users.db"
SAFE_DIR = "./files"

# --------- Utils ----------
def get_db():
    return sqlite3.connect(DB_PATH)

# --------- Routes ----------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    )
    row = cursor.fetchone()

    if row and bcrypt.checkpw(password.encode(), row[0]):
        return jsonify({"status": "success", "user": username})

    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host")

    if not host or not host.replace(".", "").isalnum():
        return jsonify({"error": "Invalid host"}), 400

    output = subprocess.check_output(
        ["ping", "-c", "1", host],
        stderr=subprocess.STDOUT
    )

    return jsonify({"output": output.decode()})


@app.route("/compute", methods=["POST"])
def compute():
    expression = request.json.get("expression")

    try:
        # sandbox très limitée
        result = eval(expression, {"__builtins__": {}})
        return jsonify({"result": result})
    except Exception:
        return jsonify({"error": "Invalid expression"}), 400


@app.route("/hash", methods=["POST"])
def hash_password():
    pwd = request.json.get("password", "").encode()
    hashed = bcrypt.hashpw(pwd, bcrypt.gensalt())
    return jsonify({"hash": hashed.decode()})


@app.route("/readfile", methods=["POST"])
def readfile():
    filename = request.json.get("filename")

    if not filename or ".." in filename or filename.startswith("/"):
        return jsonify({"error": "Access denied"}), 403

    path = os.path.join(SAFE_DIR, filename)

    if not os.path.isfile(path):
        return jsonify({"error": "File not found"}), 404

    with open(path, "r") as f:
        return jsonify({"content": f.read()})


@app.route("/hello", methods=["GET"])
def hello():
    return jsonify({"message": "Secure DevSecOps API"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

