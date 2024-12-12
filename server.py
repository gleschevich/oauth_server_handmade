from flask import Flask
from flask import make_response
from flask import request
from flask import abort, jsonify
from flask import redirect
from authlib.integrations.flask_client import OAuth
import psycopg2
import jwt
import secrets
import string
import random
import hashlib

####HASH AND SALT PASSWORD####
def hash_password(password:str):
    password_bytes = password.encode('utf-8')
    hashed_password = hashlib.sha256(password_bytes).hexdigest()
    return hashed_password

def generate_random_string(length=16):
    characters = string.ascii_letters + string.digits  # A-Z, a-z, 0-9
    return ''.join(secrets.choice(characters) for _ in range(length))

def generate_random_id(min_value=1, max_value=1000000):
    return random.randint(min_value, max_value)

def delete_expired_tokens():
    connection = psycopg2.connect(host="localhost", database="cct",port=5432, user="gleschevich", password="32220")
    cursor = connection.cursor()
    #Delete expired tokens
    query= """DELETE FROM tokens WHERE expires_at < NOW()"""
    cursor.execute(query,(None,))
    connection.commit()
    cursor.close()
    connection.close()



app = Flask(__name__)

def pass_validation(password:str):
    low,up,dig,sym=0,0,0,0
    if (len(password)>=12):
        for c in password:
            if (c.islower()):
                low+=1
            if (c.isupper()):
                up+=1
            if (c.isdigit()):
                dig+=1
            if (c in ['¬','!','£','$','%','^','&','*','(','_','+',')','@','.',':',';','#','"']):
                sym+=1
            print(sym,dig,up,low)
    if(low>=1 and up>=1 and dig>=1 and sym>=1 and low+up+dig+sym == len(password)):
        print("Valid password!")
        return True
    else:
        print("Invalid password!")
        return False


def user_validation(user:str):
    if (len(user)>8 and len(user)<=30):
        if (user.isalnum):
            print ("User name valid!")
            return True
        else:
            print("User name must be alphanumeric")
            return False
    else:
        print("User name must be between 8 and 30 character")
        return False




@app.post("/credentials")
def credentials():
    username = request.form.get("username")
    password = request.form.get("password")
    

    #validate that username and password have valids requirements
    if (user_validation(username) & pass_validation(password)):
       #connect to DB
       connection = psycopg2.connect(host="localhost", database="cct",port=5432, user="gleschevich", password="32220")
       cursor = connection.cursor()
       #see if username and password are in DB
       query= """select * from users where name=%s and password=%s"""
       t=(username,hash_password(password))
       print (t)
       cursor.execute(query,t)
       #if user is already registered in DB
       if (cursor.rowcount ==0):
            query= """INSERT INTO users (name,password) VALUES (%s,%s)"""
            t=(username,hash_password(password))
            cursor.execute(query,t)

       redirect_url = request.form.get("redirect_url")
       #see if user already have a short live token generated
       query= """select token from tokens where name=%s and password=%s"""
       t=(username,hash_password(password))
       cursor.execute(query,t)
       list = cursor.fetchall()
       
       #if user does not have token generate it and store
       if not list:
            print("Generate token")
            short_lived_token = generate_random_string(16)
            id = generate_random_id() 
            query= """INSERT INTO tokens (id,name, password, token, expires_at) VALUES (%s,%s,%s,%s,CURRENT_TIMESTAMP + INTERVAL '10 minutes')"""
            token = (id,username,password,short_lived_token)
            cursor.execute(query,token)
       #if user already have token and remains valid 
       else:
            print("user already have valid token")
            short_lived_token = list[0][0]
       redirect_url += "?short_lived_token="+ short_lived_token
       #close connection with DB
       connection.commit()
       cursor.close()
       connection.close()
       return redirect(redirect_url)

    #user or password incorrect
    else:
        return "Username or Password invalid"

@app.route("/access_token")
def get_access_token():
    
    short_lived_token = request.args.get("short_lived_token")
    connection = psycopg2.connect(host="localhost", database="cct",port=5432, user="gleschevich", password="32220")
    cursor = connection.cursor()

    #Get username 
    query= """SELECT name from tokens where token = %s"""
    print (query)
    print(short_lived_token)
    
    cursor.execute(query,(short_lived_token,))
   
    username = cursor.fetchall()
    #if user token does not exist
    if not username:
        print("Unexisting token")
    #if token exists in DB generate and store long lived token
    else:
        print(username[0])
        #check if user already have a long live token
        query= """select lltoken from lltokens where name=%s"""
        t=(username[0],)
        cursor.execute(query,t)
        list = cursor.fetchall()
        #if user does not have long lived token, generate it and store it in DB
        if not list:
            long_lived_token= jwt.encode({"aud": username},"secret",algorithm="HS256")
            query= """INSERT INTO lltokens (name,lltoken) VALUES (%s,%s)"""
            cursor.execute(query,(username[0],long_lived_token))
        else:
            #if user have long lived token just return it
            print("user already have lltoken")
            long_lived_token = list[0][0]
    
    connection.commit()
    cursor.close()
    connection.close()
    
    return long_lived_token

   

@app.route("/home")
def home():
    delete_expired_tokens()
    return '''
    <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Page</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f9;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-container {
            text-align: center;
            background: white;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            padding: 20px;
            width: 300px;
        }
        .login-container img {
            width: 100px;
            margin-bottom: 20px;
        }
        .login-container input {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        .login-container button {
            width: 100%;
            padding: 10px;
            background-color: blue;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
        }
        .login-container button:hover {
            background-color: darkblue;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <img src="https://static.vecteezy.com/system/resources/previews/003/559/570/non_2x/cartoon-kitten-icon-design-in-blue-color-cute-cat-illustration-for-a-template-free-vector.jpg" alt="Blue Login Icon">
        <h2>Login</h2>
        <form action="/credentials" method="POST">
            <input type="text" class="input-field" id="username" name="username" placeholder="Username must be inbetween 8 and 30 characters" required>
            <input type="password" class="input-field" id="password" name="password" placeholder="12 characters minimum, a number and a special character" required>
            <input type="hidden" name="redirect_url" value="|url|"/>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>

'''.replace("|url|", request.args.get("redirect_url"))

""" 
appConfig={
    "OAUTH2_CLIENT_ID": "0000",
    "OAUTH2_CLIENT_SECRET": "secret",
    "OAUTH2_ISSUER": "0000",
    "FLASK_SECRET": "fsecret",
    "FLASK_PORT": "5432"
    
    
}

app.secret_key = appConfig.get("FLASK_SECRET")

oauth = OAuth(app)
oauth.register(
    "myServer",
    client_id = appConf.get("OAUTH2_CLIENT_ID"),
    client_secret = appConfig.get("OAUTH2_CLIENT_SECRET"),
    client_kwargs={
        "scope": "open id profile"
    },
    server_metadata_url=f

)
 """








app.run(host="0.0.0.0",port=5000)