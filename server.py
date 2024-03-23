from flask import Flask,send_file
from pymongo import MongoClient

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

@app.route("/")
def HomePage():
    return send_file('./index.html')

@app.route("/javascript.js")
def ServeJS():
    return(send_file('./javascript.js'))

@app.route("/style.css")
def ServeCSS():
    return(send_file('./style.css'))

if __name__ == "__main__":
    app.run(host="localhost", port=8080)