from flask import Flask, render_template, request, jsonify, redirect, url_for
import hashlib
from flask.helpers import total_seconds
from pymongo import MongoClient
import jwt
import re
from bson.json_util import dumps
import datetime

app = Flask(__name__)

client = MongoClient(
    "mongodb+srv://test:sparta@cluster0.wkt0j.mongodb.net/Cluster0?retryWrites=true&w=majority"
)
db = client.bakbak2
SECRET_KEY = "SPARTA"

############## 적합 검사 함수 ################
# 이메일 적합 검사
def email_vaild(email):
    if (
        re.search("[a-zA-Z0-9+-_.]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", email) is None
    ):  # 이메일형식 적합성 검사
        return False
    else:
        print("아이디 적합")
        return True


# 디비에서 중복된 이메일이 있는지 확인
def email_check(email):
    # print(email)
    # print(db.user.find({"email": email}))
    return bool(db.user.find_one({"email": email}))
    # c = db.user.find({}, {"_id": False})
    # print(dumps(list(c)))
    # return True


# 비밀번호 적합 검사
def pw_vaild(passwords):
    special_char = ["!", "@", "#", "_", "*", "."]

    if len(passwords) < 8 or len(passwords) > 21:  # 비밀번호 8자 이상 20자 이하
        return False
    elif re.search("[0-9]+", passwords) is None:  # 최소 1개이상 숫자
        return False
    elif re.search("[a-z A-Z]+", passwords) is None:  # 최소 1개이상 영문자
        return False
    elif not any(password in special_char for password in passwords):  # 최소 1개이상 특수문자
        return False
    else:
        print("비밀번호 적합")
        return True


def token_valid():
    token_receive = request.cookies.get("token")
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return jsonify({"result": "fail", "msg": "로그인 시간이 만료되었습니다."})
    except jwt.exceptions.DecodeError:
        return jsonify({"result": "fail", "msg": "로그인 정보가 존재하지 않습니다."})


############## 라우팅 ################
@app.route("/")
def home():
    token = token_valid()
    if type(token) == dict:
        return render_template("main.html")
    else:
        return redirect(url_for("login"))


@app.route("/login")
def login():
    token = token_valid()
    if type(token) == dict:
        return redirect(url_for("home"))
    else:
        return render_template("login.html")


@app.route("/register")
def register():
    token = token_valid()
    if type(token) == dict:
        return redirect(url_for("home"))
    else:
        return render_template("register.html")


##############  api  ################
# 회원가입 api
@app.route("/api/register", methods=["POST"])
def api_register():
    email_receive = request.form["email_give"]
    if email_vaild(email_receive) == False:
        return jsonify({"msg": "이메일 주소를 확인하세요"})
    if email_check(email_receive) == True:
        return jsonify({"msg": "사용하고 있는 이메일 주소입니다"})
    print(email_receive)
    name_receive = request.form["name_give"]
    nick_receive = request.form["nick_give"]

    pw_receive = request.form["pw_give"]
    if pw_vaild(pw_receive) == False:
        return jsonify({"msg": "비밀번호가 적합하지 않습니다."})
    pw_hash = hashlib.sha256(pw_receive.encode("utf-8")).hexdigest()
    print(email_receive, name_receive, nick_receive, pw_hash)
    doc = {
        "email": email_receive,
        "name": name_receive,
        "nick": nick_receive,
        "pw": pw_hash,
    }
    db.user.insert_one(doc)
    return jsonify({"result": "success"})


# 로그인 api
@app.route("/api/login", methods=["POST"])
def api_login():
    email_receive = request.form["email_give"]
    pw_receive = request.form["pw_give"]
    print(email_receive, pw_receive)
    pw_hash = hashlib.sha256(pw_receive.encode("utf-8")).hexdigest()
    result = db.user.find_one({"email": email_receive, "pw": pw_hash})
    if result is not None:
        payload = {
            "email": email_receive,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=5000),
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        return jsonify({"result": "success", "token": token})
    else:
        return jsonify({"result": "fail", "msg": "아이디/비밀번호가 일치하지 않습니다."})


# @app.route('/api/upload', methods=['POST'])
# def upload():


if __name__ == "__main__":
    app.run("", port=8000, debug=True)
