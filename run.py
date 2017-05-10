
from flask import Flask, request ,redirect ,session, render_template
import requests
import requests.auth
import json
import urllib
import base64
import os

#Note the values set for these variables will allow you to run the application locally.
#Modify these values to point to your UAA Instance information.
CLIENT_ID = None #" Your Client ID"
UAA_URL = None #"Your UAA Url"
BASE64ENCODING = None #'MjEyNTg1NTM2LUhlbGxvV29ybGRDbGllbnRBcHA6SXNsYW5kVmlldw=='
port = int(os.getenv("PORT", 9099))
REDIRECT_URI = None #"http://localhost:"+str(port)+"/callback"

APP_URL = None
if 'VCAP_SERVICES' in os.environ:
    services = json.loads(os.getenv('VCAP_SERVICES'))
    uaa_env = services['predix-uaa'][0]['credentials']
    UAA_URL = uaa_env['uri']
    
if 'VCAP_APPLICATION' in os.environ:
    applications = json.loads(os.getenv('VCAP_APPLICATION'))
    app_details_uri = applications['application_uris'][0]
    APP_URL = 'https://'+app_details_uri
    REDIRECT_URI = APP_URL+'/callback'
else:
    APP_URL = "http://localhost:"+str(port)
    REDIRECT_URI = APP_URL+'/callback'
    
if(os.getenv('client_id')):
    print 'Client id: %s' % os.getenv('client_id')
    CLIENT_ID = os.getenv('client_id')
    
if(os.getenv('base64encodedClientDetails')):
    BASE64ENCODING = os.getenv('base64encodedClientDetails')
    
app = Flask(__name__)
app.secret_key = 'MjEyNTg1NTM2LUhlbGxvV29ybGQK' #not sure what to put here...

@app.route('/')
@app.route('/index')
def index():
    print 'Index / Root Resource'
    text = '<br> <a href="%s">Authenticate with Predix UAA </a>'
    return render_template('index.html') +text % getUAAAuthorizationUrl()

@app.route('/secure')
def securePage():
    print 'Secure Page '
    key = session.get('key', 'not set')
    if 'access_token' in session:
        #TODO: call to Check token is valid
        return 'This is a secure page controlled by UAA'
    else :
        text = '<br> <a href="%s">Authenticate with Predix UAA </a>'
        return 'Token not found, You are not logged in to UAA' +text % getUAAAuthorizationUrl()

@app.route('/callback')
def UAAcallback():
    print 'callback'
    error = request.args.get('error', '')
    if error:
        return "Error: " + error
    state = request.args.get('state', '')
    if not is_valid_state(state):
        print 'Request not initiated from this site!'
        #abort(403)
    code = request.args.get('code')
    access_token = get_token(code)
    # TODO: store the user token in sesson or redis cache , but for now use Flask session
    session['access_token'] = access_token
    print "You have logged in using UAA  with this access token %s" % access_token
    return redirect(APP_URL+"/secure", code=302)
   

# method to consttruct Oauth authorization request
def getUAAAuthorizationUrl():

    state = 'secure'
    params = {"client_id": CLIENT_ID,
              "response_type": "code",
              "state": state,
              "redirect_uri": REDIRECT_URI
              }
    url = UAA_URL+"/oauth/authorize?" + urllib.urlencode(params)
    return url

# Oauth Call to get access_token based on code from UAA
def get_token(code):
    post_data = {"grant_type": "authorization_code",
                 "code": code,
                 "redirect_uri": REDIRECT_URI,
                 "state":"secure"}
    headers = base_headers()
    response = requests.post(UAA_URL+"/oauth/token",
                             headers=headers,
                             data=post_data)
    token_json = response.json()
    return token_json["access_token"]

def base_headers():
    return {"Authorization": "Basic "+BASE64ENCODING }

def is_valid_state(state):
    if(state == 'secure' ) :
        return True
    else :
        return False
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port, debug=True)

    
