import uuid
import MySQLdb
import os
import base64
from flask import Flask, render_template, session, request, jsonify, redirect, send_file, flash, current_app, Response
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__, static_url_path='', static_folder='./web/static', template_folder='./web/templates')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SECRET_KEY'] = "your-secret-key"
app.debug = False

# Database connection
def get_db_connection():
    return MySQLdb.connect(host="localhost", user="root", passwd="password", db="VulnPracticeLabs")

@app.route("/")
def index():
    if not session.get('logged_in'):
        return render_template("index.html", login_error=True, reason=request.args.get('reason'))
    else:
        return redirect("/index")

@app.route("/logout")
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('api_key', None)
    return redirect('/')

@app.route("/index", methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        file_list = os.listdir('./web/uploads/') if os.path.exists('./web/uploads/') else []
        if session.get('logged_in'):
            return render_template("authenticated.html", api_key=session.get('api_key'), user_id=session.get('user_id'), username=session.get('username'), base64=base64, file_list=file_list)
        else:
            return redirect('/')

    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        db = get_db_connection()
        cur = db.cursor()
        try:
            cur.execute("SELECT id, api_key FROM users WHERE username = %s AND password = %s", (username, password))
            result = cur.fetchone()
            if result:
                session['logged_in'] = True
                session['username'] = username
                session['user_id'] = result[0]
                session['api_key'] = result[1]
                return redirect('/index')
            else:
                return redirect('/?error=true&reason=Invalid credentials')
        except Exception as e:
            return redirect('/?error=true&reason=Database Error!')
        finally:
            cur.close()
            db.close()

@app.route("/api/upload_file", methods=['POST'])
def upload_file():
    if not session.get('logged_in') or not session.get('api_key'):
        return jsonify({'error_msg': 'Unauthorized access'})
    
    if 'file' not in request.files:
        return jsonify({"error_msg": "FILE PARAMETER NOT SPECIFIED"})

    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({"error_msg": "FILE NAME NOT SPECIFIED"})

    original_filename = secure_filename(uploaded_file.filename)
    extension = original_filename.split('.')[-1] if '.' in original_filename else ''
    new_filename = uuid.uuid4().hex + ('.' + extension if extension else '')

    upload_path = os.path.join("./web/uploads/", new_filename)
    uploaded_file.save(upload_path)
    flash("Uploaded")
    return redirect("/")

@app.route("/message/")
def error_page():
    title = request.args.get('title')
    message = request.args.get('message')
    alert_type = request.args.get('alert_type')
    return render_template("error.html", title=title, message=message, alert_type=alert_type)

@app.route("/api/userinfo/", methods=['GET'])
def user_info():
    if not session.get('logged_in'):
        return jsonify({"error": "Not logged in"})
    return jsonify({
        "userid": session.get('user_id'),
        "username": session.get('username'),
        "api_key": session.get('api_key')
    })

if __name__ == "__main__":
    app.run()
