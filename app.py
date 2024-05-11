import secrets
import sqlite3

from flask import Flask, request, render_template, redirect

from markupsafe import escape

from itsdangerous import URLSafeSerializer

app = Flask(__name__)

con = sqlite3.connect("app.db", check_same_thread=False)

serializer = URLSafeSerializer(secrets.token_hex(32))

# Route for login
@app.route("/login", methods=["GET", "POST"])
def login():
    cur = con.cursor()
    if request.method == "GET":
        session_token = request.cookies.get("session_token")
        if session_token:
            try:
                user_id = serializer.loads(session_token)
                res = cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
                user = res.fetchone()
                if user:
                    return redirect("/home")
            except Exception as e:
                print("Error:", e)
        return render_template("login.html")
    else:
        username = request.form["username"]
        password = request.form["password"]
        res = cur.execute("SELECT id FROM users WHERE username = ? AND password = ?", (username, password))
        user = res.fetchone()
        if user:
            user_id = user[0]
            token = serializer.dumps(user_id)
            cur.execute("INSERT INTO sessions (user, token) VALUES (?, ?)", (user_id, token))
            con.commit()
            response = redirect("/home")
            response.set_cookie("session_token", token)
            return response
        else:
            return render_template("login.html", error="Invalid username and/or password!")

@app.route("/home")
def home():
    cur = con.cursor()
    session_token = request.cookies.get("session_token")
    if session_token:
        try:
            user_id = serializer.loads(session_token)
            res = cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
            user = res.fetchone()
            if user:
                res = cur.execute("SELECT message FROM posts WHERE user = ?", (user_id,))
                posts = res.fetchall()
                return render_template("home.html", username=user[0], posts=posts)
        except Exception as e:
            print("Error:", e)
    return redirect("/login")

@app.route("/posts", methods=["POST"])
def posts():
    cur = con.cursor()
    session_token = request.cookies.get("session_token")
    if session_token:
        try:
            user_id = serializer.loads(session_token)
            message = escape(request.form["message"])
            cur.execute("INSERT INTO posts (message, user) VALUES (?, ?)", (message, user_id))
            con.commit()
            return redirect("/home")
        except Exception as e:
            print("Error:", e)
    return redirect("/login")

@app.route("/logout")
def logout():
    session_token = request.cookies.get("session_token")
    if session_token:
        try:
            user_id = serializer.loads(session_token)
            cur = con.cursor()
            cur.execute("DELETE FROM sessions WHERE user = ?", (user_id,))
            con.commit()
        except Exception as e:
            print("Error:", e)
    response = redirect("/login")
    response.set_cookie("session_token", "", expires=0)
    return response
