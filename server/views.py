from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.decorators import api_view
import rsa
import json



@api_view(['POST'])
def register(request):
    
    body_unicode = request.body.decode('utf-8')

    #get user object
    user = json.loads(body_unicode)
    
    #verify if user exists or not ???


    #generate private key
    public_key, private_key = rsa.newkeys(2048)

    #save private key TO USER DEVICE ????????? OR ENCRYPT
    with open(user.username+".pem", "wb") as f:
        f.write(private_key.save_pkcs1("PEM"))

    #create csr 

    return Response(True)

@api_view(["POST"])
def login(request):
    return Response("login")
