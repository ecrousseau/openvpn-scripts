import json
import requests
from urllib import quote, unquote
import argparse

clientID = "228546413242-mqmbbaca82g9ad1meehhqmplucjrftds.apps.googleusercontent.com"
clientSecret = FIXME

def userinfoCall(access_token):
    print "Making API call to UserInfo"
    userinfoRequestURI = "https://www.googleapis.com/oauth2/v3/userinfo"
    headers = {
        "Authorization": "Bearer {}".format(access_token)
    }
    response = requests.get(userinfoRequestURI, headers=headers)
    userinfoReponse = response.json()
    print json.dumps(userinfoReponse, indent=2)
    email = userinfoReponse['email']
    return email


def performCodeExchange(code, code_verifier, redirectURI):
    print "Exchanging code for tokens"
    tokenRequestURI = "https://www.googleapis.com/oauth2/v4/token?code={}&redirect_uri={}&client_id={}&code_verifier={}&client_secret={}&scope=email&grant_type=authorization_code".format(code, quote(redirectURI), clientID, code_verifier, clientSecret)
    response = requests.post(tokenRequestURI)
    tokenEndpointDecoded = response.json()
    print json.dumps(tokenEndpointDecoded, indent=2)
    access_token = tokenEndpointDecoded['access_token']
    return access_token
    

def main():
    parser = argparse.ArgumentParser(description='openvpn oauth')
    parser.add_argument('file')
    args = parser.parse_args()
    with open(args.file) as fd:
        l = fd.readlines()
    username = l[0].rstrip()
    password = unquote(l[1]).rstrip()
    print "username: {}".format(username)
    print "password: {}".format(password)
    code, code_verifier, redirectURI = password.split('::')
    access_token = performCodeExchange(code, code_verifier, redirectURI)
    email = userinfoCall(access_token)
    if email == username:
        print "match, returning 0"
        return 0
    else:
        print "no match, returning 1"
        return 1

if __name__ == '__main__':
    main()


