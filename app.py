from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "dev-key-2025"

# ---------- 预设用户（密码已哈希存储，不再明文）----------
# 实际项目中应从数据库加载，此处为演示用内存字典
_INITIAL_USERS = [
    {"username": "admin", "password": "Admin@2025#Secure", "role": "admin",
     "email": "admin@example.com", "phone": "13800138000", "balance": 99999},
    {"username": "alice", "password": "Alice@2025#Secure", "role": "user",
     "email": "alice@example.com", "phone": "13900139001", "balance": 100},
]

USERS = {}
for u in _INITIAL_USERS:
    user_data = dict(u)
    # 密码经过 werkzeug 哈希处理后存储，不保留明文
    user_data["password"] = generate_password_hash(user_data["password"])
    USERS[user_data["username"]] = user_data


@app.route("/")
def index():
    username = session.get("username")
    user = None
    if username and username in USERS:
        user = USERS[username]
    return render_template("index.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        user = USERS.get(username)
        if user and check_password_hash(user["password"], password):
            session["username"] = username
            return render_template("index.html", user=user)
        else:
            return render_template("login.html", error="用户名或密码错误")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
