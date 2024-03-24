from flask import Flask,send_file,render_template, request, jsonify, redirect, url_for, make_response
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
import hashlib
import uuid
import html
import os

app = Flask(__name__)

Method='local'

if Method=='local':
    mongo_client = MongoClient("mongodb+srv://Jaretl123:Jaretl123@cluster0.dpg3dfq.mongodb.net/")
else:
    mongo_client = MongoClient("mongo")

db = mongo_client["CSE312"] 
Comments = db["Comments"]
Tokens=db["Tokens"]
Users= db["Users"]
xsrf=db["XSRF"]
ID=db["ID"]

@app.route("/")
def HomePage():
    auth_token = request.cookies.get('auth_token')
    comments = Comments.find()
    if auth_token:
        token_hash = hashlib.sha256(auth_token.encode()).hexdigest()
        user_token = Tokens.find_one({"token_hash": token_hash})
        if user_token:
            username = user_token['username']
            return render_template('index.html', username=username, comments=comments)
    return render_template('index.html', username=None, comments=comments)

@app.route("/javascript.js")
def ServeJS():
    return(send_file('./javascript.js'))

@app.route("/style.css")
def ServeCSS():
    return(send_file('./style.css'))

@app.route('/img/<path:filename>')
def serve_image(filename):
    # Determine the MIME type based on the file extension
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
        # Serve the image file with the specified MIME type
        image_path = os.path.join(app.root_path, 'img', filename)
        response = make_response(send_file(image_path, mimetype=mime_type))
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response
    else:
        return 'Invalid or unsupported file extension', 400

bcrypt = Bcrypt()

# Registration route
@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password1 = request.json.get('password1')
    password2 = request.json.get('password2')

    username_exists = get_username(username)
    if username_exists:
        return jsonify({'error': 'Username already exists'}), 400

    if password1 != password2:
        return jsonify({'error': 'Passwords do not match'}), 400

    # Generate salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password1.encode('utf-8'), salt)

    user_data = {"username": username, "password": hashed_password.decode('utf-8')}
    Users.insert_one(user_data)
    return jsonify({'message': 'Registration successful'}), 200

def get_username(username):
    user_document = Users.find_one({"username": username})
    if user_document:
        return user_document["username"]
    else:
        return None

# Login route
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    user_data = Users.find_one({"username": username})
    if not user_data:
        return jsonify({'error': 'Invalid username or password'}), 401

    stored_password = user_data["password"]
    if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
        token = generate_auth_token(username)
        response = jsonify({'message': 'Login successful'})
        response.set_cookie('auth_token', token, httponly=True, max_age=3600)
        return response, 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

def generate_auth_token(username):
    token = str(uuid.uuid4())
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    Tokens.insert_one({"username": username, "token_hash": token_hash})
    return token

def remove_auth_token(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    Tokens.delete_one({"token_hash": token_hash})

# Logout route
@app.route('/logout')
def logout():
    auth_token = request.cookies.get('auth_token')
    if auth_token:
        token_hash = hashlib.sha256(auth_token.encode()).hexdigest()
        if Tokens.find_one({"token_hash": token_hash}):
            Tokens.delete_one({"token_hash": token_hash})
    response = redirect(url_for('index'))
    response.set_cookie('auth_token', '', expires=0)
    return response

@app.route('/create_comment', methods=['POST'])
def create_comment():
    # Get data from the request
    author = request.form.get('author')
    content = html.escape(request.form.get('content'))  # HTML escape to prevent XSS attacks
    ID = get_next_id()
    auth_token = request.cookies.get('auth_token')
    if auth_token:
        token_hash = hashlib.sha256(auth_token.encode()).hexdigest()
        if Tokens.find_one({"token_hash": token_hash}):
            new_comment = {"author": author, "content": content, "comment_id": ID, "likes": []}
        else:
            new_comment = {"author": "Guest", "content": content, "comment_id": ID, "likes": []}
    else:
        new_comment = {"author": "Guest", "content": content, "comment_id": ID, "likes": []}
    Comments.insert_one(new_comment)

    return jsonify({'message': 'Comment created successfully'})

@app.route('/like_comment', methods=['POST'])
def like_comment():
    # Get data from the request
    comment_id = request.form.get('comment_id')
    username = request.form.get('username')
    if not username:
        return jsonify({'error': 'Only authenticated users can like posts'}), 401
    post = Comments.find_one({"comment_id": comment_id})
    if username in post.get('likes', []):
        return jsonify({'error': 'User has already liked the post'}), 400
    Comments.update_one({"comment_id": comment_id}, {"$push": {"likes": username}})
    return jsonify({'message': 'Comment liked successfully'})

def get_next_id():
    document = ID.find_one()
    # Extract the current value
    current_value = document.get('value', 0)
    # Increment the value for the next document
    ID.update_one({}, {"$set": {"value": current_value + 1}})
    return current_value

if __name__ == "__main__":
    app.run(host="localhost", port=8080)