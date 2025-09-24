from flask import Flask, render_template_string, request, redirect, url_for, session, send_from_directory
import sqlite3, os, hashlib, secrets, base64

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

DB_FILE = 'hchat.db'
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE,
                    password TEXT,
                    username TEXT UNIQUE,
                    profile_pic TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS friends (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    friend_id INTEGER,
                    status TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER,
                    receiver_id INTEGER,
                    group_id INTEGER,
                    content TEXT,
                    type TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS group_members (
                    group_id INTEGER,
                    user_id INTEGER
                )''')
    conn.commit()
    conn.close()

init_db()

# --- Helpers ---
def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def save_file(file):
    filename = secrets.token_hex(8) + "_" + file.filename
    path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(path)
    return filename

# --- Routes ---
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = hash_password(request.form['password'])
        username = request.form['username']
        pic = request.files.get('profile_pic')
        pic_filename = save_file(pic) if pic else ''
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute('INSERT INTO users (email,password,username,profile_pic) VALUES (?,?,?,?)',
                      (email,password,username,pic_filename))
            conn.commit()
            session['user_id'] = c.lastrowid
            return redirect(url_for('home'))
        except sqlite3.IntegrityError:
            return "Email or Username already exists!"
    return render_template_string('''
    <h2>Sign Up</h2>
    <form method="POST" enctype="multipart/form-data">
        Email: <input name="email"><br>
        Password: <input name="password" type="password"><br>
        Username: <input name="username"><br>
        Profile Pic: <input name="profile_pic" type="file"><br>
        <button>Sign Up</button>
    </form>
    <a href="/login">Login</a>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = hash_password(request.form['password'])
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email=? AND password=?', (email,password)).fetchone()
        if user:
            session['user_id'] = user['id']
            return redirect(url_for('home'))
        else:
            return "Invalid login"
    return render_template_string('''
    <h2>Login</h2>
    <form method="POST">
        Email: <input name="email"><br>
        Password: <input name="password" type="password"><br>
        <button>Login</button>
    </form>
    <a href="/signup">Sign Up</a>
    ''')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    uid = session['user_id']
    conn = get_db()
    # Friends
    friends = conn.execute('''SELECT u.id,u.username,u.profile_pic,f.status FROM users u
                              JOIN friends f ON (u.id=f.friend_id OR u.id=f.user_id)
                              WHERE (f.user_id=? OR f.friend_id=?) AND u.id!=?''',
                           (uid,uid,uid)).fetchall()
    # Friend requests
    requests = conn.execute('''SELECT u.id,u.username,u.profile_pic FROM users u
                               JOIN friends f ON u.id=f.user_id
                               WHERE f.friend_id=? AND f.status='pending' ''',(uid,)).fetchall()
    # Groups
    groups = conn.execute('''SELECT g.id,g.name FROM groups g
                             JOIN group_members gm ON g.id=gm.group_id
                             WHERE gm.user_id=?''',(uid,)).fetchall()
    return render_template_string('''
    <h2>H Chat Home</h2>
    <a href="/logout">Logout</a><br>
    <h3>Friend Requests</h3>
    {% for r in requests %}
        {{r['username']}} <a href="/accept/{{r['id']}}">Accept</a> <a href="/decline/{{r['id']}}">Decline</a><br>
    {% endfor %}
    <h3>Friends</h3>
    {% for f in friends %}
        {{f['username']}} ({{f['status']}}) <a href="/chat/{{f['id']}}">Chat</a>
        <a href="/unfriend/{{f['id']}}">Unfriend</a><br>
    {% endfor %}
    <h3>Groups</h3>
    {% for g in groups %}
        {{g['name']}} <a href="/group_chat/{{g['id']}}">Open</a><br>
    {% endfor %}
    <h3>Add Friend</h3>
    <form method="POST" action="/add_friend">
        Username: <input name="username">
        <button>Add Friend</button>
    </form>
    <h3>Create Group</h3>
    <form method="POST" action="/create_group">
        Group Name: <input name="name">
        Friend IDs (comma): <input name="friends">
        <button>Create Group</button>
    </form>
    ''', friends=friends, requests=requests, groups=groups)

# --- Friend routes ---
@app.route('/add_friend', methods=['POST'])
def add_friend():
    uid = session['user_id']
    username = request.form['username']
    conn = get_db()
    user = conn.execute('SELECT id FROM users WHERE username=?',(username,)).fetchone()
    if user:
        conn.execute('INSERT INTO friends (user_id,friend_id,status) VALUES (?,?,?)', (uid,user['id'],'pending'))
        conn.commit()
    return redirect(url_for('home'))

@app.route('/accept/<int:fid>')
def accept(fid):
    uid = session['user_id']
    conn = get_db()
    conn.execute("UPDATE friends SET status='accepted' WHERE user_id=? AND friend_id=?", (fid, uid))
    conn.commit()
    return redirect(url_for('home'))

@app.route('/decline/<int:fid>')
def decline(fid):
    uid = session['user_id']
    conn = get_db()
    conn.execute("DELETE FROM friends WHERE user_id=? AND friend_id=?", (fid, uid))
    conn.commit()
    return redirect(url_for('home'))

@app.route('/unfriend/<int:fid>')
def unfriend(fid):
    uid = session['user_id']
    conn = get_db()
    conn.execute("DELETE FROM friends WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)", (uid,fid,fid,uid))
    conn.commit()
    return redirect(url_for('home'))

# --- Chat routes ---
@app.route('/chat/<int:fid>', methods=['GET','POST'])
def chat(fid):
    uid = session['user_id']
    conn = get_db()
    if request.method=='POST':
        content = request.form['content']
        type_msg = request.form.get('type','text')
        if 'file' in request.files:
            f = request.files['file']
            if f.filename:
                content = save_file(f)
                type_msg = 'file'
        conn.execute('INSERT INTO messages (sender_id,receiver_id,group_id,content,type) VALUES (?,?,?,?,?)',
                     (uid,fid,None,content,type_msg))
        conn.commit()
    messages = conn.execute('''SELECT m.*,u.username,u.profile_pic FROM messages m
                               JOIN users u ON u.id=m.sender_id
                               WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)
                               ORDER BY m.id''',(uid,fid,fid,uid)).fetchall()
    friend = conn.execute('SELECT username FROM users WHERE id=?',(fid,)).fetchone()
    return render_template_string('''
    <h2>Chat with {{friend['username']}}</h2>
    <a href="/home">Home</a><br>
    <div style="height:300px;overflow:auto;border:1px solid black">
    {% for m in messages %}
        <b>{{m['username']}}:</b>
        {% if m['type']=='text' %}
            {{m['content']}}
        {% else %}
            <a href="/uploads/{{m['content']}}" target="_blank">{{m['content']}}</a>
        {% endif %}
        <br>
    {% endfor %}
    </div>
    <form method="POST" enctype="multipart/form-data">
        <input name="content">
        <input type="file" name="file">
        <button>Send</button>
    </form>
    ''', messages=messages, friend=friend)

# --- Groups ---
@app.route('/create_group', methods=['POST'])
def create_group():
    uid = session['user_id']
    name = request.form['name']
    friends = request.form['friends'].split(',')
    friends = [int(f.strip()) for f in friends if f.strip().isdigit()]
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT INTO groups (name) VALUES (?)',(name,))
    gid = c.lastrowid
    c.execute('INSERT INTO group_members (group_id,user_id) VALUES (?,?)',(gid,uid))
    for f in friends:
        c.execute('INSERT INTO group_members (group_id,user_id) VALUES (?,?)',(gid,f))
    conn.commit()
    return redirect(url_for('home'))

@app.route('/group_chat/<int:gid>', methods=['GET','POST'])
def group_chat(gid):
    uid = session['user_id']
    conn = get_db()
    if request.method=='POST':
        content = request.form['content']
        type_msg = request.form.get('type','text')
        if 'file' in request.files:
            f = request.files['file']
            if f.filename:
                content = save_file(f)
                type_msg = 'file'
        conn.execute('INSERT INTO messages (sender_id,receiver_id,group_id,content,type) VALUES (?,?,?,?,?)',
                     (uid,None,gid,content,type_msg))
        conn.commit()
    messages = conn.execute('''SELECT m.*,u.username,u.profile_pic FROM messages m
                               JOIN users u ON u.id=m.sender_id
                               WHERE m.group_id=? ORDER BY m.id''',(gid,)).fetchall()
    group = conn.execute('SELECT name FROM groups WHERE id=?',(gid,)).fetchone()
    return render_template_string('''
    <h2>Group: {{group['name']}}</h2>
    <a href="/home">Home</a><br>
    <div style="height:300px;overflow:auto;border:1px solid black">
    {% for m in messages %}
        <b>{{m['username']}}:</b>
        {% if m['type']=='text' %}
            {{m['content']}}
        {% else %}
            <a href="/uploads/{{m['content']}}" target="_blank">{{m['content']}}</a>
        {% endif %}
        <br>
    {% endfor %}
    </div>
    <form method="POST" enctype="multipart/form-data">
        <input name="content">
        <input type="file" name="file">
        <button>Send</button>
    </form>
    ''', messages=messages, group=group)

if __name__ == '__main__':
    app.run(debug=True)
