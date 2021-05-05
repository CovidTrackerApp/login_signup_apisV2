from flask import Flask, request, jsonify, send_file
from flask_restful import Resource, Api
from functools import wraps
import jwt
import bcrypt
import datetime
from random import randint
from cryptography.fernet import Fernet
import hashlib

from multiprocessing import Process
import os
import csv
from werkzeug.utils import escape, secure_filename

from zipfile import ZipFile
from os.path import basename

import io

from flask_mail import Mail, Message
from pymongo import MongoClient

app = Flask(__name__)
api = Api(app)


app.config["SECRET_KEY"] = "t+isi-sth(esec4_OPof"

# mail thing here
app.config['MAIL_SERVER']='smtp.yandex.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'furqan4545@yandex.ru'
app.config['MAIL_PASSWORD'] = 'Yandex12345'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
# mail end here

# uploading file
UPLOAD_FOLDER = '/usr/src/app/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

UPLOAD_FOLDER_2 = '/usr/src/app/BTuploads'
app.config['UPLOAD_FOLDER_2'] = UPLOAD_FOLDER_2

FOLDER_3 = "/usr/src/app/zipfolder"
app.config['UPLOAD_FOLDER_3'] = FOLDER_3

FOLDER_4 = "/usr/src/app/btzipfolder"
app.config['UPLOAD_FOLDER_4'] = FOLDER_4

client = MongoClient("mongodb://db:27017")
mail = Mail(app)
# client = MongoClient('localhost', 27017)
# client = MongoClient('mongodb://localhost:27017/')

# app.config["MONGO_URI"] = "mongodb://localhost:27017/myDatabase"
# mongo = PyMongo(app)

db = client.Users
users = db["Users"]  # making collections

ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'csv', 'xlsx', 'docx'])

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get("token") # http://127.0.0.1:5000/route?token=sdasdasdaqwesadaw
        if not token:
            return jsonify({"msg" : "Token is missing!", "status": 402})

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"])

        except:
            return jsonify({"msg" : "Token is invalid!", "status": 403})

        return f(*args, **kwargs)

    return decorated

def UserExist(username):
    # if users.find({"username": username}).count() == 0:
    if users.count_documents({"username": username}) == 0:
        return False
    else: 
        return True

def EmailExist(email_hashed):
    if users.find({"email_hashed": email_hashed}).count() == 0:
        return False
    else: 
        return True

def ContactExist(contact_hashed):
    if users.find({"contact_hashed": contact_hashed}).count() == 0:
        return False
    else: 
        return True

def verifyPw(username, password):
    if not UserExist(username):
        return False

    hashed_pw = users.find({
        "username": username
    })[0]["password"]

    if bcrypt.hashpw(password.encode("utf8"), hashed_pw) == hashed_pw:
        return True
    else:
        return False

# def verifyPwWithEmail(email, password):
#     if not EmailhashedExist(email):
#         return False

#     hashed_pw = users.find({
#         "email": email
#     })[0]["password"]

#     if bcrypt.hashpw(password.encode("utf8"), hashed_pw) == hashed_pw:
#         return True
#     else:
#         return False

# modified
def verifyPwWithEmail(email, password):
    if not EmailExist(email):
        return False
    
    
    # hashed_email = users.find({
    #         "email": email
    #     })[0]["hashed_email"]

    hashed_pw = users.find({
        "email": email
    })[0]["password"]

    if bcrypt.hashpw(password.encode("utf8"), hashed_pw) == hashed_pw:
        return True
    else:
        return False


# def updateVerificationCode(email):
#     code = users.find({
#             "email": email
#         })[0]["verification_code"]

#     generated_code = randint(10000, 99999)
    
#     users.update({"verification_code" : code}, {"$set" : {"verification_code": generated_code}})

#     return generated_code

# remember you don't need an email to send user the email of reseting password. All you need is just a reference ID
# which is actually the username.
def updateVerificationCode(username):
    code = users.find({
            "username": username
        })[0]["verification_code"]

    generated_code = randint(10000, 99999)
    
    users.update({"verification_code" : code}, {"$set" : {"verification_code": generated_code}})

    return generated_code

def updateVerificationCodeViaEmail(hemail):
    code = users.find({
            "email_hashed": hemail
        })[0]["verification_code"]

    generated_code = randint(10000, 99999)
    
    users.update({"verification_code" : code}, {"$set" : {"verification_code": generated_code}})

    return generated_code

def updateOTPCode(username):
    code = users.find({
            "username": username
        })[0]["OTP"]

    encrypted_email = users.find({
                "username": username
            })[0]["email_encrypted"]

    stored_key = users.find({
                "username": username
            })[0]["u_key"]

    f = Fernet(stored_key)
    # Decrypt the email.
    decrypted_email = f.decrypt(encrypted_email)
    # Decode the bytes back into a string.
    decrypted_email = decrypted_email.decode()

    generated_code = randint(10000, 99999)
    
    users.update({"OTP" : code}, {"$set" : {"OTP": generated_code}})

    return generated_code, decrypted_email


# def GetCodeFromDb(email):
#     code = users.find({
#             "email": email
#         })[0]["verification_code"]
#     print("Code Here : ", code)
#     return code

def GetCodeFromDb(username):
    code = users.find({
            "username": username
        })[0]["verification_code"]
    print("Code Here : ", code)
    return code

# def setNewPassword(email, updated_password):
#     password = users.find({
#             "email": email
#         })[0]["password"]
    
#     users.update({"password" : password}, {"$set" : {"password": updated_password}})    

def setNewPassword(hemail, updated_password):
    # password = users.find({
    #         "username": username
    #     })[0]["password"]
    password = users.find({
            "email_hashed": hemail
        })[0]["password"]
    
    users.update({"password" : password}, {"$set" : {"password": updated_password}})    

def TokenExist(username):
    existing_token = users.find({
                    "username": username
                })[0]["Token"]

    return existing_token


def getOTP(username):
    old_otp = users.find({
        "username": username
    })[0]["OTP"]
    return old_otp

def verifyOtp(username, otpCode):
    stored_otp = users.find({
                    "username": username
                })[0]["OTP"]
    if stored_otp != otpCode:
        return False
    else:
        return True

def getEmailCode(hemail):
    code = users.find({
            "email_hashed": hemail
        })[0]["verification_code"]
    return code

def generate_key_for_credentials(username):
    key = Fernet.generate_key()
    c_path = os.getcwd()+ "/credential_keys"
    if os.path.exists(c_path):
        with open(f'{c_path}/{username}.key', 'wb') as new_key_file:
            new_key_file.write(key)
        return key
    else:
        os.mkdir(c_path)
        with open(f'{c_path}/{username}.key', 'wb') as new_key_file:
            new_key_file.write(key)
        return key


# create a msg to encode
def encode_credentials(username, email, name, contact_num, age, gender):
    # Instantiate the object with your key.
    # (Refer to Encoding types above).
    key = generate_key_for_credentials(username)
    # username = username.encode()
    email = email.encode()
    name = name.encode()
    contact_num = contact_num.encode()
    age = age.encode()
    gender = gender.encode()
    f = Fernet(key)
    # Pass your bytes type message into encrypt.
    # encrypted_username = f.encrypt(username)
    encrypted_email = f.encrypt(email)
    encrypted_name = f.encrypt(name)
    encrypted_number = f.encrypt(contact_num)
    encrypted_age = f.encrypt(age)
    encrypted_gender = f.encrypt(gender)
    
    print(encrypted_number)
    # return encrypted_username, encrypted_email, encrypted_number, encrypted_age, encrypted_gender
    return key, encrypted_email, encrypted_name, encrypted_number, encrypted_age, encrypted_gender

def decode_email(username):
    c_path = os.getcwd()+ "/credential_keys"
    if os.path.exists(f"{c_path}/{username}.key"):
        print("file exist")
        
        with open(f'{c_path}/{username}.key', 'rb') as my_private_key:
            key = my_private_key.read()
            # Instantiate Fernet on the recip system.
        
        encrypted_email = users.find({
                "username": username
            })[0]["email_encrypted"]
        f = Fernet(key)
        # Decrypt the message.
        decrypted_email = f.decrypt(encrypted_email)
        # Decode the bytes back into a string.
        decrypted_email = decrypted_email.decode()
        # if email == decrypted_email:
        #     return 
        return decrypted_email
    return False

def decrypt_email(h_email):
    key = users.find({
        "email_hashed": h_email
    })[0]["u_key"]

    encrypted_email = users.find({
        "email_hashed": h_email
    })[0]["email_encrypted"]

    f = Fernet(key)
    # Decrypt the message.
    decrypted_email = f.decrypt(encrypted_email)
    # Decode the bytes back into a string.
    decrypted_email = decrypted_email.decode()
    
    return decrypted_email


    
# full name daalna hai. 
# isky baad hme upload csv krni hai for bt and sensors data. 

class Register(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        fname = postedData["fname"]
        contact = postedData["contact_num"]
        email = postedData["email"]
        age = postedData["age"]
        gender = postedData["gender"]
        
        # email_hash = email.lower()
        email = email.lower()
        email_enc = email.encode("utf-8")
        contact_enc = contact.encode("utf-8")

        if username and password and email and contact:
            if UserExist(username):
                retJson = {
                    "status" : 301,
                    "msg" : "Username already exists"
                }
                return jsonify(retJson)

            email_hashed = hashlib.sha224(email_enc).hexdigest()
            
            if EmailExist(email_hashed):
                retJson = {
                        "status" : 302,
                        "msg" : "Email is already registered"
                    }
                return jsonify(retJson)
            
            contact_hashed = hashlib.sha224(contact_enc).hexdigest()
            if ContactExist(contact_hashed):
                retJson = {
                        "status" : 303,
                        "msg" : "Contact number is already registered"
                    }
                return jsonify(retJson)
                
            hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
            
        # store username and password in the database
        # if username and password:
            token = jwt.encode({"user" : username, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=365)}, app.config["SECRET_KEY"])
            # token = jwt.encode({"user" : username, "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=10)}, app.config["SECRET_KEY"])

            u_key, encrypted_email, encrypted_name, encrypted_number, encrypted_age, encrypted_gender = encode_credentials(username, email, fname, contact, age, gender)

            generated_OTP_code = randint(10000, 99999)

            # utc_timestamp = datetime.datetime.utcnow()

            # send email of OTP
            msg = Message('Covid Tracker: {}'.format(generated_OTP_code), sender = 'furqan4545@yandex.ru', recipients = [email])
            msg.body = "Here is your verification code: {}".format(generated_OTP_code)
            mail.send(msg)

            # users.create_index("date", expireAfterSeconds=20)
            users.insert({
                "username": username,
                "password": hashed_pw,
                "fname" : encrypted_name,
                "contact_num": encrypted_number,
                "contact_hashed" : contact_hashed,
                "email_hashed": email_hashed,
                "email_encrypted": encrypted_email,
                "age": encrypted_age,
                "gender": encrypted_gender,
                "Token" : token,
                # "date": utc_timestamp,
                "u_key" : u_key,
                "verification_code": 0,
                "OTP" : generated_OTP_code
            })
            retJson = {
                "Token": token.decode('UTF-8'),
                "OTP" : generated_OTP_code,
                "status" : 200
            }

            return jsonify(retJson)
        
        retJson = {
            "status" : 303,
            "msg" : "Please fill all the fields."
        }
        return jsonify(retJson)

class Login(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        # email = postedData["email"]
        password = postedData["password"]
        otp = postedData["otp"]
        
        if username and password:
            if not UserExist(username):
                retJson = {
                    "status" : 303,
                    "msg" : "No such user exist"
                }
                return jsonify(retJson)

            correct_pw = verifyPw(username, password)

            if not correct_pw:
                retJson = {
                    "status" : 301,
                    "msg" : "Invalid Password"
                    }
                return jsonify(retJson)
            
            Oldtoken = TokenExist(username)
            registeredOtp = getOTP(username)
            if registeredOtp != otp or otp == "":
                code, email = updateOTPCode(username)
                otp = code
                msg = Message('Covid Tracker: {}'.format(code), sender = 'furqan4545@yandex.ru', recipients = [email])
                msg.body = "Here is your verification code: {}".format(code)
                mail.send(msg)

                retJson = {
                    "status" : 200,
                    "msg" : "Old OTP code didn't match, here is the new one.",
                    "otpCode" : code
                }
                return jsonify(retJson)

            if not Oldtoken:
                new_token = jwt.encode({"user" : username, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=365)}, app.config["SECRET_KEY"])
                users.update({"username" : username}, {"$set" : {"Token": new_token}})
                retJson = {
                    "status" : 302,
                    "msg" : "Old token doesn't exist anymore, here is the new one.",
                    "Token" : new_token.decode('UTF-8')
                }
                return jsonify(retJson)

            # token = jwt.encode({"user" : username, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=365)}, app.config["SECRET_KEY"])
            
            
            # users.update({"Token" : code}, {"$set" : {"Token": generated_code}})

            retJson = {
                "Token" : Oldtoken.decode('UTF-8'),  # isky neechy vali line me code daalna hai edit kr k. 
                "otpCode": otp,
                "status" : 200
            }

            return jsonify(retJson)

        retJson = {
            "msg" : "Fields can not be empty. Login required!",
            "status" : 304
        }
        return jsonify(retJson)

class VerifyOTP(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        otp = postedData["otp"]

        if username and otp:
            if not UserExist(username):
                retJson = {
                    "status" : 302,
                    "msg" : "Username doesn't exists"
                }
                return jsonify(retJson)

            correct_otp = verifyOtp(username, otp)

            if not correct_otp:
                retJson = {
                    "status" : 301,
                    "msg" : "Invalid OTP"
                    }
                return jsonify(retJson)
            
            new_token = jwt.encode({"user" : username, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=365)}, app.config["SECRET_KEY"])
            retJson = {
                    "status" : 200,
                    "otp" : otp,
                    "token" : new_token.decode('UTF-8'),
                    }
            return jsonify(retJson)

        retJson = {
            "status" : 302,
            "msg" : "No OTP specified"
            }
        return jsonify(retJson)

class VerifyCodeViaEmail(Resource):
    def post(self):
        postedData = request.get_json()

        email = postedData["email"]
        code = postedData["code"]

        email = email.lower()
        email_enc = email.encode("utf-8")

        if email and code:
            email_hashed = hashlib.sha224(email_enc).hexdigest()
            
            obt_code = getEmailCode(email_hashed)

            if obt_code != code:
                retJson = {
                    "msg": "The code didn't match!",
                    "status" : 301
                }
                return jsonify(retJson)
            
            # new_token = jwt.encode({"user" : email, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=365)}, app.config["SECRET_KEY"])
            retJson = {
                    "status" : 200,
                    "msg" : "Code matched! Verification Done!"
                }
            return jsonify(retJson)

        retJson = {
            "status" : 302,
            "msg" : "No OTP specified"
            }
        return jsonify(retJson)

class ForgetPass(Resource):
    def post(self):
        postedData = request.get_json()

        #username = postedData["username"]
        email = postedData["email"]
        email = email.lower()
        email_enc = email.encode("utf-8")

        new_password = postedData["newPassword"]
        confirm_password = postedData["confirmPassword"]
        
        # if username and new_password and confirm_password:
        if email and new_password and confirm_password:

            if new_password != confirm_password:
                retJson = {
                    "msg": "Password doesn't match!",
                    "status" : 301 
                }
                return jsonify(retJson)

            email_hashed = hashlib.sha224(email_enc).hexdigest()
            hashed_password = bcrypt.hashpw(new_password.encode('utf8'), bcrypt.gensalt())
            # setNewPassword(username, hashed_password)
            setNewPassword(email_hashed, hashed_password)

            retJson = {
                "msg" : "Password updated successfully.",
                "status" : 200
            }
            return jsonify(retJson)

        retJson = {
            "msg" : "Please fill all the fields",
            "status" : 303
        }
            
        return retJson

# we have to take just email from user. Not username. 

class SendVerificationCode(Resource):
    def post(self):
        postedData = request.get_json()
        # username = postedData["username"]
        email = postedData["email"]
        
        email = email.lower()
        email_enc = email.encode("utf-8")
        
        if email:
           
            email_hashed = hashlib.sha224(email_enc).hexdigest()
            
            if not EmailExist(email_hashed):
                retJson = {
                        "status" : 302,
                        "msg" : "No such email is in records"
                    }
                return jsonify(retJson)

            decoded_email = decrypt_email(email_hashed)
            # decoded_email = decode_email(username)
            # if not EmailExist(decoded_email, email):
            #     retJson = {
            #         "msg" : "No such registered email",
            #         "status" : 303
            #     }
            #     return jsonify(retJson)
            if decoded_email != email:
                retJson = {
                    "msg" : "No such registered email",
                    "status" : 303
                }
                return jsonify(retJson)

            code = updateVerificationCodeViaEmail(email_hashed)
            msg = Message('Covid Tracker: {}'.format(code), sender = 'furqan4545@yandex.ru', recipients = [decoded_email])
            msg.body = "Here is your verification code: {}".format(code)
            mail.send(msg)

            retJson = {
                "msg": "Email has been sent to the registered email",
                "status" : 200
            }            
            return jsonify(retJson)

        retJson = {
            "msg": "Email field can't be empty!",
            "status": 302
        }
        return jsonify(retJson)

class WriteCsvFile(Resource):
    def get(self):
        c_path = os.getcwd()+ "/credential_keys"
        with open(f'{c_path}/furqaan.key', 'rb') as my_private_key:
            key = my_private_key.read()
            print("key is here : ", key)

        retJson = {
            "msg" : str(key),
            "status": 200
        }

        return jsonify(retJson)


def background_remove(path):
    task = Process(target=rm(path))
    task.start()

def rm(path):
    os.remove(path)

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/file-upload', methods=['POST'])
def upload_file():
	# check if the post request has the file part
	if 'file' not in request.files:
		resp = jsonify({'msg' : 'No file part in the request', 'file': request.files, "path": os.getcwd()})
		resp.status_code = 400
		return resp
	file = request.files['file']
	if file.filename == '':
		resp = jsonify({'msg' : 'No file selected for uploading'})
		resp.status_code = 400
		return resp
	if file and allowed_file(file.filename):
		filename = secure_filename(file.filename)
		file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
		resp = jsonify({'msg' : 'File successfully uploaded'})
		resp.status_code = 201
		return resp
	else:
		resp = jsonify({'msg' : 'Allowed file types are txt, pdf, csv, docx, xlsx'})
		resp.status_code = 400
		return resp

# Naming  convention for storing sensor file
# username+today's date
# for e.g. furqan4545_22-04-21

@app.route('/bt-file-upload', methods=['POST'])
def upload_BTfile():
	# check if the post request has the file part
	if 'file' not in request.files:
		resp = jsonify({'msg' : 'No file part in the request', 'file': request.files, "path": os.getcwd()})
		resp.status_code = 400
		return resp
	file = request.files['file']
	if file.filename == '':
		resp = jsonify({'msg' : 'No file selected for uploading'})
		resp.status_code = 400
		return resp
	if file and allowed_file(file.filename):
		filename = secure_filename(file.filename)
		file.save(os.path.join(app.config['UPLOAD_FOLDER_2'], filename))
		resp = jsonify({'msg' : 'File successfully uploaded'})
		resp.status_code = 201
		return resp
	else:
		resp = jsonify({'msg' : 'Allowed file types are txt, pdf, csv, docx, xlsx'})
		resp.status_code = 400
		return resp


class DownloadSensorCSV(Resource):
    def post(self):
        postedData = request.get_json()
        filename = postedData["filename"]
        file_path = os.getcwd()+"/uploads/"+filename
        # file_path = os.getcwd()+"/uploads/"+"ali.xlsx"
        # return send_file(file_path, as_attachment=True, attachment_filename="Random.xlsx")
        return send_file(file_path, as_attachment=True)


@app.route('/downloadsensorszip/<username>', methods=['GET'])
def download_csv_zip(username):
    
    folder_path = os.getcwd()+"/uploads"

    with ZipFile(f'{app.config["UPLOAD_FOLDER_3"]}/data.zip', 'w') as zipObj:
        # Iterate over all the files in directory
        for folderName, subfolders, filenames in os.walk(folder_path):
            for filename in filenames:
                if filename[:-13] == username:
                    print(filename)
                    print("Hello there is ")
                    #create complete filepath of file in directory
                    filePath = os.path.join(folderName, filename)
                    # Add file to zip
                    zipObj.write(filePath, basename(filePath))
                else:
                    return jsonify({"msg": "No such user files exist"})
    file_path = app.config['UPLOAD_FOLDER_3']+"/data.zip"

    ######
    return_data = io.BytesIO()
    with open(file_path, 'rb') as fo:
        return_data.write(fo.read())
        return_data.seek(0)   

    background_remove(file_path)
    #######

    return send_file(return_data, as_attachment=True, attachment_filename="data.zip")

@app.route('/downloadbtzip/<username>', methods=['GET'])
def download_bt_csv_zip(username):
    
    folder_path = os.getcwd()+"/BTuploads"

    with ZipFile(f'{app.config["UPLOAD_FOLDER_4"]}/btdata.zip', 'w') as zipObj:
        # Iterate over all the files in directory
        for folderName, subfolders, filenames in os.walk(folder_path):
            for filename in filenames:
                if filename[:-13] == username:
                    print("Hello there is file")
                    #create complete filepath of file in directory
                    filePath = os.path.join(folderName, filename)
                    # Add file to zip
                    zipObj.write(filePath, basename(filePath))
                else:
                    return jsonify({"msg": "No such user files exist"})
    file_path = app.config['UPLOAD_FOLDER_4']+"/btdata.zip"

    ######
    return_data = io.BytesIO()
    with open(file_path, 'rb') as fo:
        return_data.write(fo.read())
        return_data.seek(0)   

    background_remove(file_path)
    #######

    return send_file(return_data, as_attachment=True, attachment_filename="btdata.zip")


class WriteMongoFile(Resource):
    def get(self):
        mongo_docs = users.find()
        cursor = list(mongo_docs)
        # # json_export = cursor.to_json()
        if mongo_docs.count() == 0:
            return

        with open('credentials_file.csv', 'w') as outfile:   
            fields = ['_id', "username",
                "password",
                "contact_num",
                "contact_hashed",
                "email_hashed",
                "email_encrypted",
                "age",
                "gender",
                "Token",
                "verification_code",
                "OTP"]
            write = csv.DictWriter(outfile, fieldnames=fields)
            write.writeheader()
            for i in range(len(cursor)):
                f = Fernet(cursor[i]["u_key"])
                encrypted_email = cursor[i]["email_encrypted"]
                # Decrypt the message.
                decrypted_email = f.decrypt(encrypted_email)
                # Decode the bytes back into a string.
                decrypted_email = decrypted_email.decode()
                decrypted_cn = cursor[i]["contact_num"]
                decrypted_cn = f.decrypt(decrypted_cn)
                decrypted_cn = decrypted_cn.decode()
                decrypted_age = cursor[i]["age"]
                decrypted_age = f.decrypt(decrypted_age)
                decrypted_age = decrypted_age.decode()
                decrypted_gender = cursor[i]["gender"]
                decrypted_gender = f.decrypt(decrypted_gender)
                decrypted_gender = decrypted_gender.decode()
                
                
                write.writerow({
                    "username": cursor[i]["username"], "password" : cursor[i]["password"].decode("utf-8"),
                    "contact_num" : decrypted_cn, "email_encrypted" : decrypted_email,
                    "age" : decrypted_age, "gender" : decrypted_gender
                    })
            
        file_path = os.getcwd()+"/credentials_file.csv"
        # return jsonify(cursor[0]["email_encrypted"].decode("utf-8"))
        return send_file(file_path, as_attachment=True, attachment_filename="credentials_file.csv")
        


@app.route("/protected")
@token_required
def protected():
    return jsonify({"msg": "This is only available to people with valid token!"})


api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
api.add_resource(VerifyOTP, '/verifyotp')
api.add_resource(SendVerificationCode, '/sendcode')
api.add_resource(ForgetPass, '/resetpass')
api.add_resource(WriteCsvFile, '/writecsv')
api.add_resource(WriteMongoFile, '/writemongo')
api.add_resource(DownloadSensorCSV, '/downloadsensor')
api.add_resource(VerifyCodeViaEmail, '/verifycodeviaemail')


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, port=5000)




