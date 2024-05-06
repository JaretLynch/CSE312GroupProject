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
from ImageSources import Sources 
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
    print(username)
    if username != 'Guest':
        active_users[request.sid] = username
        room = request.args.get('dest')
        print(room)
        if room == "Bills" or room == "Sabres" or room == "General":
            print("Adding User to list")
            user_list[room][username] = datetime.now()
            emit('user_joined', {'room': room}, broadcast=True)

    auth_token = request.cookies.get('auth_token')

    username = request.args.get('username')
    print(auth_token)
    dest=request.args.get('dest')
    print(dest)
    if auth_token:
        token_hash = hashlib.sha256(auth_token.encode()).hexdigest()
        user_data = Tokens.find_one({"token_hash": token_hash})
        if user_data:
            active_users[request.sid] = [user_data.get('username'),dest]
            print(active_users)
        else:
            active_users[request.sid] = ["Guest",dest]
            print(active_users)
            
    else:
        active_users[request.sid] = ["Guest",dest]
        print(active_users)

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in active_users:
        print("Request is in there")
        username = active_users.get(request.sid, "Guest")
        del active_users[request.sid]
        if username != "Guest":
            for room, users_in_room in user_list.items():
                print("****USERNAME IS ***** "+str(username))
                users_in_room.pop(username[0], None)
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
                     'image': Sources.BillsSource,
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
                     'image': Sources.SabresSource,
                     'comments': comments}
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
    if hasattr(request, 'sid'):
        print("Has Attribute")
        sid = request.sid
        print(active_users)
        if sid in active_users:
            message = data.get('message')
            for user_sid, (user_username, user_chatroom) in active_users.items():
                print("User is "+str(user_username)+"and they are in the "+str(user_chatroom)+" Chatroom")
                print("Destination is"+str(destination))
                if user_chatroom == destination:
                    emit('Comment_Broadcasted', {'author': author, 'content': content,'comment_id':new_comment.get('comment_id'),'likes':"0"}, room=user_sid)

@socketio.on('like_comment')
def like_comment(data):
    dest = data.get('destination')
    id=data.get("id")
    NumOfLikes = 120
    if dest == "Bills":
        comment = BillsComments.find_one({"comment_id": data.get("id")})
        likes_list = comment.get("likes")
        username = active_users[request.sid]
        if username in likes_list:
            emit('like_alert')
            return
        elif  username != "Guest":
            Result=BillsComments.update_one({"comment_id": data.get("id")}, {"$push": {"likes": username}})
            comment = BillsComments.find_one({"comment_id": data.get("id")})
            NumOfLikes=len(comment.get("likes"))
    elif dest == "Sabres":
        comment = SabresComments.find_one({"comment_id": data.get("id")})
        likes_list = comment.get("likes")
        username = active_users[request.sid]
        if username in likes_list:
            emit('like_alert')
            return
        elif  username != "Guest":
            Result=SabresComments.update_one({"comment_id": data.get("id")}, {"$push": {"likes": username}})
            comment = SabresComments.find_one({"comment_id": data.get("id")})

            NumOfLikes=len(comment.get("likes"))

    else:
        comment = Comments.find_one({"comment_id": data.get("id")})
        likes_list = comment.get("likes")
        username = active_users[request.sid]
        if username in likes_list:
            emit('like_alert')
            return
        elif  username != "Guest":
            Result=comment.update_one({"comment_id": data.get("id")}, {"$push": {"likes": username}})
            comment = Comments.find_one({"comment_id": data.get("id")})

            NumOfLikes=len(comment.get("likes"))


    if hasattr(request, 'sid'):
        print("Has Attribute")
        sid = request.sid
        print(active_users)
        if sid in active_users:
            message = data.get('message')
            for user_sid, (user_username, user_chatroom) in active_users.items():
                print("User is "+str(user_username)+"and they are in the "+str(user_chatroom)+" Chatroom")
                print("Destination is"+str(dest))
                if user_chatroom == dest:
                    emit('Comment_Liked', {'comment_id':id,"NumOfLikes":NumOfLikes}, room=user_sid)

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
    filtered_user_lists = [(user, time) for user, time in user_lists if user != "Guest"]
    emit('user_list', {'user_list': filtered_user_lists, 'dest': dest})

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=8080)
