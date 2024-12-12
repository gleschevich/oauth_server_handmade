from flask import Flask
from flask import make_response, request,render_template
import json


app = Flask(__name__)

####EXCHANGES SHORT LIVED TOKEN FOR A LONG LIVED TOKEN WITH AUTH####
@app.route("/logged-in")
def hello_class():
    token = request.args.get('short_lived_token')
    import requests
    # Make a request to the authorization server with the short lived token.
    response = requests.get(f"http://localhost:5000/access_token?short_lived_token={token}")
    print(response.content)
    
    response = response.content
    #make_response(f"You access! your long lived token is: {response.content}")
    parsed_content = json.loads(response)

    # Render it in a good-looking HTML page
    return render_template("access.html", json_data=parsed_content)

####RECIEVE REQUEST FROM USER TO LOGIN AND REDIRECT TO AUTH SERVER####
@app.route("/login")
def login():
   
    
    from flask import redirect
    return redirect("http://localhost:5000/home?redirect_url=http://localhost:5001/logged-in")

#run the client in the host and port given
app.run(host="0.0.0.0",port=5001)