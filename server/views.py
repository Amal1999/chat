from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.decorators import api_view
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
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
    private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
            backend=default_backend()
        )

    #save private key TO USER
    with open(user["username"]+".pem", "wb") as f:
        f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

    #create csr
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"TN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Tunis"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"INSAT"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"INSAT"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"INSAT"),
    ])).sign(private_key, hashes.SHA256(), default_backend())
    with open(user["username"]+'_csr.pem', "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    #send csr to certificate authority
    ca.createCertificate(csr, user["username"])

    password = user["password"]
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    #save user
    db.execute1("INSERT INTO users (name, email, username, password) VALUES (%s, %s, %s, %s)", (user["name"], user["email"],user["username"],hashed_password))
    return Response(True)
    

@api_view(["POST"])
def login(request):

    #get login user object
    body_unicode = request.body.decode('utf-8')
    user = json.loads(body_unicode)

    #verify if login data are valid
    username = user["username"]
    userFromDB = db.execute2("SELECT * FROM users WHERE username like %s",(user["username"],))

    if(userFromDB!= None):
        if (bcrypt.checkpw(user["password"].encode(), userFromDB[4].encode())):
        #verify signature
            resp = ca.verifyCertificate(user["username"])
            return Response(resp)
        else:
            return Response(False)
    else:
        return Response(False)
    
