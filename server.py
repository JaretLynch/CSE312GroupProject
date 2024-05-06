from flask import Flask,send_file,render_template, request, jsonify, redirect, url_for, make_response
from flask_bcrypt import Bcrypt, check_password_hash
from flask_socketio import SocketIO, send, emit
from pymongo import MongoClient
import hashlib
import uuid
import html
import os
import ssl
import re
from datetime import datetime
from collections import defaultdict
import time
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from time import time

app = Flask(__name__, template_folder='.')
# context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
# context.load_cert_chain('/app/nginx/fullchain.pem', '/app/nginx/privkey.pem')
socketio = SocketIO(app, cors_allowed_origins="*", transport = ['websocket'])
active_users = {}
mongo_client = MongoClient("mongodb+srv://Jaretl123:Jaretl123@cluster0.dpg3dfq.mongodb.net/")

IMAGE_SIGNATURES = {
    b'\xFF\xD8\xFF': 'jpg',   # JPEG/JFIF
    b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': 'png',   # PNG
    b'\x47\x49\x46\x38\x37\x61': 'gif',   # GIF
}

VIDEO_SIGNATURES = {
    b'\x00\x00\x00\x18ftypmp4': 'mp4'    # MP4
}

filter = {"dingus"}
user_list = {'Bills': {}, 'General': {}, 'Sabres': {}}

def validate_image_signature(signature):
    for magic_number, image_type in IMAGE_SIGNATURES.items():
        if signature.startswith(magic_number):
            return image_type
    return None

def validate_video_signature(signature):
    for magic_number, image_type in VIDEO_SIGNATURES.items():
        if signature.startswith(magic_number):
            return image_type
    return None

db = mongo_client["CSE312Group"] 
if "Comments" not in db.list_collection_names():
    db.create_collection("Comments")
if "Tokens" not in db.list_collection_names():
    db.create_collection("Tokens")
if "Users" not in db.list_collection_names():
    db.create_collection("Users")
if "XSRF" not in db.list_collection_names():
    db.create_collection("XSRF")
if "id" not in db.list_collection_names():
    db.create_collection("id")
    db["id"].insert_one({"value": 0})
if "media_id" not in db.list_collection_names():
    db.create_collection("media_id")
    db["media_id"].insert_one({"value": 0})
if "BillsComments" not in db.list_collection_names():
    db.create_collection("BillsComments")
if "SabresComments" not in db.list_collection_names():
    db.create_collection("SabresComments")   
Comments = db["Comments"]
BillsComments=db["BillsComments"]
SabresComments=db["SabresComments"]
Tokens=db["Tokens"]
Users= db["Users"]
xsrf=db["XSRF"]
ID = db["id"]
media_id = db["media_id"]
bcrypt = Bcrypt()

request_counts = defaultdict(lambda: {'count': 0, 'blocked_until': 0})
blocked_ips = {}

# limiter = Limiter(
#     key_func=get_remote_address,
#     app=app,
#     default_limits=["50 per 10 seconds"]
# )

@app.before_request
def block_ip():
    ip = get_remote_address()
    if ip in blocked_ips:
        if time() - blocked_ips[ip] < 30:
            return jsonify({"error": "Too Many Requests. Try again later."}), 429
        else:
            del blocked_ips[ip]

    
@app.after_request
def add_header(response):
    ip = get_remote_address()
    # if limiter.hit or response.status_code == 429:
    #     blocked_ips[ip] = time()
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@socketio.on('connect')
def handle_connect():
    username = request.args.get('username')
    dest = request.args.get('dest')
    if username != 'Guest':
        active_users[request.sid] = username
        if dest == "Bills" or dest == "Sabres" or dest == "General":
            user_list[dest][username] = datetime.now()
            emit('user_joined', {'dest': dest}, broadcast=True)
    else:
        active_users[request.sid] = "Guest"

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in active_users:
        username = active_users.get(request.sid, "Guest")
        del active_users[request.sid]
        if username != "Guest":
            for room, users_in_room in user_list.items():
                users_in_room.pop(username, None)
                emit('user_left', {'room': room}, broadcast=True)

@app.route("/")
def HomePage():
    error_message = request.args.get('error')
    username = request.args.get('username', "Guest")
    regfailure = request.args.get('regfailure')
    regsuccess = request.args.get('regsuccess')
    app.logger.info("Accessing home page")
    comments = list(Comments.find())
    auth_token = request.cookies.get('auth_token')
    if auth_token and username:
        token_hash = hashlib.sha256(auth_token.encode()).hexdigest()
        user_token = Tokens.find_one({"token_hash": token_hash})
        if user_token and user_token['username'] == username:
            pass
        else:
            username = "Guest"
    if hasattr(request, 'sid'):
        sid=request.sid
        if sid in active_users:     
            active_users[request.sid]=""
    return render_template('index.html', username=username, error=error_message, regfailure=regfailure, regsuccess=regsuccess)

@app.route("/javascript.js")
def ServeJS():
    return send_file('./javascript.js')

@app.route("/style.css")
def ServeCSS():
    return send_file('./style.css')

@app.route("/Bills")
def ServeBillsChatroom():
    comments=list(BillsComments.find())
    username = request.args.get('username', "Guest")
    auth_token = request.cookies.get('auth_token')
    if auth_token and username:
        token_hash = hashlib.sha256(auth_token.encode()).hexdigest()
        user_token = Tokens.find_one({"token_hash": token_hash})
        if user_token and user_token['username'] == username:
            pass
        else:
            username = "Guest"
    else:
        username = "Guest"
    chatroom_data = {'Name': 'Bills',
                     'username':username,
                     'image': 'data:image/jpeg;base64,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',
                     'comments': comments}

    return render_template('chatroom.html', username=username, data=chatroom_data)

@app.route("/General")
def ServeGeneralChatroom():
    comments=list(Comments.find())
    username = request.args.get('username', "Guest")
    auth_token = request.cookies.get('auth_token')
    if auth_token and username:
        token_hash = hashlib.sha256(auth_token.encode()).hexdigest()
        user_token = Tokens.find_one({"token_hash": token_hash})
        if user_token and user_token['username'] == username:
            pass
        else:
            username = "Guest"
    else:
        username = "Guest"
    chatroom_data = {'Name': 'General',
                     'username':username,
                     'image': 'https://upload.wikimedia.org/wikipedia/commons/thumb/d/d5/Buffalo_Bisons_Mascot_At_Trenton_Thunder_Game.jpg/238px-Buffalo_Bisons_Mascot_At_Trenton_Thunder_Game.jpg', 'comments': comments}
    return render_template('chatroom.html', username=username, data=chatroom_data)

@app.route("/Sabres")
def ServeSabresChatroom():
    comments=list(SabresComments.find())
    username = request.args.get('username', "Guest")
    auth_token = request.cookies.get('auth_token')
    if auth_token and username != "Guest":
        token_hash = hashlib.sha256(auth_token.encode()).hexdigest()
        user_token = Tokens.find_one({"token_hash": token_hash})
        print(user_token)
        if user_token and user_token['username'] == username:
            pass
        else:
            username = "Guest"
    else:
        username = "Guest"
    chatroom_data = {'Name': 'Sabres',
                     'username':username,
                     'image': 'data:image/jpeg;base64,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',
                     'coments': comments}
    return render_template('chatroom.html', username=username, data=chatroom_data)

@app.route('/img/<path:filename>')
def serve_image(filename):
    extension = os.path.splitext(filename)[1]
    mime_type = None
    if extension == '.jpg' or extension == '.jpeg':
        mime_type = 'image/jpeg'
    elif extension == '.png':
        mime_type = 'image/png'
    elif extension == '.gif':
        mime_type = 'image/gif'
    elif extension == '.bmp':
        mime_type = 'image/bmp'
    elif extension == '.webp':
        mime_type = 'image/webp'
    if mime_type:
        image_path = os.path.join(app.root_path, 'img', filename)
        response = make_response(send_file(image_path, mimetype=mime_type))
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response
    else:
        return 'Invalid or unsupported file extension', 400

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    if any(re.search(re.escape(word), username, re.IGNORECASE) for word in filter):
        error_message = 'Username cannot be used due to containing a banned word.'
        return redirect(url_for('HomePage', username="Guest", error=error_message, regfailure = "Yes"))
    password1 = request.form.get('password1')
    password2 = request.form.get('password2')
    username_exists = get_username(username)
    if username_exists:
        error_message = 'Username already exists.'
        return redirect(url_for('HomePage', error=error_message, username="Guest", regfailure = "Yes"))
    if password1 != password2:
        error_message = 'Passwords do not match.'
        return redirect(url_for('HomePage', error=error_message, username="Guest"), regfailure = "Yes")
    hashed_password = bcrypt.generate_password_hash(password1)
    user_data = {"username": username, "password": hashed_password}
    Users.insert_one(user_data)
    return redirect(url_for('HomePage', username="Guest", regsuccess = "Yes"))

def get_username(username):
    user_document = Users.find_one({"username": username})
    if user_document:
        return user_document["username"]
    else:
        return None

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user_data = Users.find_one({"username": username})
    if not user_data:
        error_message = 'Username does not exist'
        return redirect(url_for('HomePage', error=error_message, username="Guest"))
    stored_password = user_data["password"]
    if check_password_hash(stored_password, password):
        token = generate_auth_token(username)
        response = redirect(url_for('HomePage', username=username)) 
        response.set_cookie('auth_token', token, httponly=True, max_age=3600, secure=True)
        return response, 302
    else:
        error_message = 'Invalid username and password combination'
        return redirect(url_for('HomePage', error=error_message, username="Guest"))

def generate_auth_token(username):
    token = str(uuid.uuid4())
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    Tokens.insert_one({"username": username, "token_hash": token_hash})
    return token

def remove_auth_token(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    Tokens.delete_one({"token_hash": token_hash})

@app.route('/logout')
def logout():
    auth_token = request.cookies.get('auth_token')
    if auth_token:
        token_hash = hashlib.sha256(auth_token.encode()).hexdigest()
        if Tokens.find_one({"token_hash": token_hash}):
            Tokens.delete_one({"token_hash": token_hash})
    response = redirect(url_for('HomePage', username="Guest"))
    response.set_cookie('auth_token', '', expires=0)
    return response

@socketio.on('create_comment')
def create_comment(data):
    destination = data.get('destination')
    content = html.escape(data.get('comment'))
    if any(re.search(re.escape(word), content, re.IGNORECASE) for word in filter):
        emit('filter_triggered')
        return
    author = "Guest"
    auth_token = request.cookies.get('auth_token')
    if auth_token:
        token_hash = hashlib.sha256(auth_token.encode()).hexdigest()
        token_data = Tokens.find_one({"token_hash": token_hash})
        if token_data:
            author = token_data.get('username', 'Guest')
    file = request.files.get('file')
    if file:
        signature = file.read(8)
        file_type = validate_image_signature(signature)
        if not file_type:
            file_type = validate_video_signature(signature)
        if file_type:
            id = get_next_media_id()
            media_filename = f'uploaded_media{id}.' + file_type
            file_path = os.path.join('/app/media/', f'uploaded_file{id}.' + file_type)
            file.save(file_path)
            content += f' <{ "img" if file_type in ["jpg", "png", "gif"] else "video" } src=\"/video/{media_filename}\" alt="Uploaded file">'
            new_comment = {
                "author": author,
                "content": content,
                "comment_id": get_next_id(),
                "likes": []
            }
        else:
            return "Invalid file format", 400
    else:
        new_comment = {
            "author": author,
            "content": content,
            "comment_id": get_next_id(),
            "likes": []
        }
    # Insert the comment into the appropriate collection based on the destination
    if destination == "General":
        Comments.insert_one(new_comment)
    elif destination == "Bills":
        BillsComments.insert_one(new_comment)
    elif destination == "Sabres":
        SabresComments.insert_one(new_comment)
    emit('Comment_Broadcasted', broadcast=True)

@socketio.on('like_comment')
def like_comment(data):
    dest = data.get('destination')
    if dest == "Bills":
        comment = BillsComments.find_one({"comment_id": data.get("id")})
        likes_list = comment.get("likes")
        username = active_users[request.sid]
        if username != "Guest" and username not in likes_list:
            BillsComments.update_one({"comment_id": data.get("id")}, {"$push": {"likes": username}})
    elif dest == "Sabres":
        comment = SabresComments.find_one({"comment_id": data.get("id")})
        likes_list = comment.get("likes")
        username = active_users[request.sid]
        if username != "Guest" and username not in likes_list:
            SabresComments.update_one({"comment_id": data.get("id")}, {"$push": {"likes": username}})
    else:
        comment = Comments.find_one({"comment_id": data.get("id")})
        likes_list = comment.get("likes")
        username = active_users[request.sid]
        if username != "Guest" and username not in likes_list:
            Comments.update_one({"comment_id": data.get("id")}, {"$push": {"likes": username}})
    emit('Comment_Liked')

def get_next_id():
    document = ID.find_one()
    current_value = document.get('value', 0)
    ID.update_one({}, {"$set": {"value": current_value + 1}})
    return current_value

def get_next_media_id():
    document = media_id.find_one()
    current_value = document.get('value', 0)
    media_id.update_one({}, {"$set": {"value": current_value + 1}})
    return current_value

@app.route('/get_comments')
def get_comments():
    destination = request.args.get('destination')
    if destination=="Bills":
        comments=BillsComments.find({})
    elif destination=="Sabres":
        comments=SabresComments.find({})
    else:
        comments = Comments.find({})
    comments_list = []
    for comment in comments:
        comment['_id'] = str(comment['_id'])
        user_data = Users.find_one({"username": comment['author']}, {"profile_file": 1})
        if user_data and 'profile_file' in user_data:
            profile_img_html = f'<img src="{user_data["profile_file"]}" width="50" height="50">'
            comment['profile_pic'] = profile_img_html
        comments_list.append(comment)
    return jsonify({'comments': comments_list})

#Adds profile data to user's database entry to use as img source
@app.route('/upload-profile', methods=['POST'])
def upload_profile_picture():
    auth_token = request.cookies.get('auth_token')
    if not auth_token:
        error_message = "Only authenticated users can upload profile pictures"
        return jsonify({'error': error_message}), 400
    token_hash = hashlib.sha256(auth_token.encode()).hexdigest()
    user_data = Tokens.find_one({"token_hash": token_hash})
    if not user_data:
        error_message = "Only authenticated users can upload profile pictures"
        return jsonify({'error': error_message}), 400
    if 'upload' not in request.files:
        return 'No image uploaded', 400
    image_file = request.files['upload']
    signature = image_file.read(8)
    image_file.seek(0)
    image_type = validate_image_signature(signature)
    if not image_type:
        return 'Invalid file format', 400
    id = get_next_media_id()
    image_filename = f'uploaded_media{id}.' + image_type
    image_path = os.path.join(os.path.dirname(__file__), 'img', image_filename)
    image_file.save(image_path)
    username = user_data.get('username')
    user_data = Users.update_one({"username": username}, {"$set": {"profile_file": f"/img/{image_filename}"}})
    response = redirect(url_for('HomePage', username=username))
    return response

def get_user_list(dest):
    now = datetime.now()
    return [(user, (now - entry_time).seconds) for user, entry_time in user_list[dest].items()]

@socketio.on('get_user_list')
def send_user_list(data):
    dest = data['dest']
    user_lists = get_user_list(dest)
    emit('user_list', {'user_list': user_lists, 'dest': dest})
    

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=8080)
