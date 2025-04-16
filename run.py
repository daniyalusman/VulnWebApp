import uuid
import MySQLdb
import os
import base64
from flask import Flask, render_template, session, request, jsonify, redirect, send_file, flash, current_app, Response
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__, static_url_path='', static_folder='./web/static', template_folder='./web/templates')

app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SECRET_KEY'] = "lollolol-lolol-lololol-lolol-lolololol"
app.debug = False

# DB connection - update as needed for deployment
db = MySQLdb.connect(host="localhost", user="root", passwd="password", db="VulnPracticeLabs")
cur = db.cursor()

@app.route("/")
def index():
    if not session.get('logged_in'):
        return render_template("index.html", login_error=True, reason=request.args.get('reason'))
    else:
        return redirect("/index")

@app.route("/logout", methods=['GET', 'POST'])
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('api_key', None)
    session.pop('user_id', None)
    return redirect('/')

@app.route("/api/upload_file", methods=['GET', 'POST'])
def upload_file():
    if session.get('logged_in'):
        if session.get('api_key'):
            if request.method == 'POST':
                if 'file' not in request.files:
                    return jsonify({"error_msg": "FILE PARAMETER NOT SPECIFIED"})
                uploaded_file = request.files['file']
                if uploaded_file.filename == '':
                    return jsonify({"error_msg": "FILE NAME NOT SPECIFIED"})

                original_filename = secure_filename(uploaded_file.filename)
                extension = original_filename.split('.')[-1] if '.' in original_filename else ''
                new_filename = uuid.uuid4().hex + ('.' + extension if extension else '')
                uploaded_file.save("./web/uploads/" + new_filename)
                flash("Uploaded")
                return redirect("/")
            return jsonify({'error_msg': 'INVALID HTTP METHOD'})
        return jsonify({"error_msg": "INVALID DOWNLOAD KEY"})
    return jsonify({'error_msg': 'NOT LOGGED IN'})

@app.route("/api/file/<api_key>/<original_filename>", methods=['GET'])
def download_user_file(api_key, original_filename):
    if session.get('logged_in'):
        if api_key == session.get('api_key'):
            path = f"./web/uploads/{original_filename}"
            if os.path.exists(path):
                return send_file(path)
            return jsonify({"error_msg": "file does not exist"})
        return jsonify({"error_msg": "invalid api_key"})
    return jsonify({'error_msg': 'NOT LOGGED IN'})

@app.route("/message/", methods=['GET'])
def error_page():
    return render_template("error.html", title=request.args.get('title'), message=request.args.get('message'), alert_type=request.args.get('alert_type'))

def support_jsonp(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        callback = request.args.get('callback', False)
        if callback:
            try:
                content = str(callback) + '(' + str(f().data) + ')'
            except:
                content = ''
            if session.get('logged_in'):
                return current_app.response_class(content, mimetype='text/html')
            return redirect('/')
        return f(*args, **kwargs)
    return decorated_function

@app.route("/index", methods=['GET', 'POST'])
def login():
    file_list = [f for f in os.listdir('./web/uploads/') if f != '.DS_Store']
    if request.method == 'GET':
        if session.get('logged_in'):
            return render_template("authenticated.html", api_key=session.get('api_key'), user_id=session.get('user_id'), username=session.get('username'), base64=base64, file_list=file_list)
        return redirect('/')

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        login_query = cur.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
        if login_query > 0:
            session['logged_in'] = True
            session['username'] = username
            cur.execute("SELECT api_key, id FROM users WHERE username = %s", (username,))
            api_key, user_id = cur.fetchone()
            session['api_key'] = api_key
            session['user_id'] = user_id
            return render_template("authenticated.html", user_id=user_id, username=username, file_list=file_list, api_key=api_key)
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cur.fetchone():
            return redirect('/?error=true&reason=Invalid Password!')
        return redirect('/?error=true&reason=User does not exist!')

# You can continue refactoring and securing the rest of the routes similarly

if __name__ == '__main__':
    app.run()
