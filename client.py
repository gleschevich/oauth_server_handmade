from flask import Flask
from flask import make_response
from flask import request
from flask import abort, jsonify


app = Flask(__name__)


@app.route("/logged-in")
def hello_class():
    print("I am a client server and I am exchanging a short lived token by a long lived access_token")
    token = request.args.get('short_lived_token')
    import requests
    # Make a request to the authorization server with the short lived token.
    response = requests.get(f"http://localhost:5000/access_token?short_lived_token={token}")
    print(response.content)
    
    response = make_response(f"You access! your long lived token is: {response.content}")

    return response

@app.route("/login")
def login():
    print("I am the client server and received a request to login. Redirecting the user to the authorization server")
    
    from flask import redirect
    return redirect("http://localhost:5000/home?redirect_url=http://localhost:5001/logged-in")

app.run(host="0.0.0.0",port=5001)