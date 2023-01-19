from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.decorators import api_view
from cryptography import x509
from cryptography.x509.oid import NameOID
import rsa
import json
from os import path
from .certif_authority import CA
from .db import Database
import bcrypt


ca = CA()
db = Database()

@api_view(['POST'])
def register(request):

    #get user object
    body_unicode = request.body.decode('utf-8')
    user = json.loads(body_unicode)
    
    #verify if user exists or not
    if(path.isfile(user["username"]+"_cert.pen") and path.exists(user["username"]+"_cert.pen")):
        return Response(False)


    #generate private key
    public_key, private_key = rsa.newkeys(2048)

    #save private key TO USER
    with open(user["username"]+".pem", "wb") as f:
        f.write(private_key.save_pkcs1("PEM"))

    #create csr
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"TN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Tunis"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"INSAT"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"INSAT"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"INSAT"),
    ]))

    #send csr to certificate authority
    ca.createCertificate(csr, user["username"])

    password = user["password"]
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    #save user
    db.execute("INSERT INTO users (name, email, username, password) VALUES (%s, %s, %s, %s)", (user["name"], user["email"],user["username"],hashed_password))

    return Response(True)
    

@api_view(["POST"])
def login(request):

    #get login user object
    body_unicode = request.body.decode('utf-8')
    user = json.loads(body_unicode)

    #verify if login data are valid
    username = user["username"]
    userFromDB = db.execute("SELECT * FROM users WHERE username like %s",(user["username"],))

    print(userFromDB)

    if(userFromDB!= None):
        if (bcrypt.checkpw(user["password"].encode(), userFromDB[3].encode())):
        #verify signature
            resp = ca.verifyCertificate(user["username"])
            return Response(resp)
        else:
            return Response(False)
    else:
        return Response(False)
    
