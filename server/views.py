from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.decorators import api_view
from cryptography import x509
from cryptography.x509.oid import NameOID
import rsa
import json




@api_view(['POST'])
def register(request):

    #get user object
    body_unicode = request.body.decode('utf-8')
    user = json.loads(body_unicode)
    
    #verify if user exists or not in LDAP ???

    #generate private key
    public_key, private_key = rsa.newkeys(2048)

    #save private key TO USER DEVICE ????????? OR ENCRYPT
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

    #send csr to certificate authority and get certificate ?????
    

    #Save certif in client device??????
    LDAPServer().add(user)
    LDAPServer().connect()

    #Save in LDAP user infos + certif + pub key??????


    return Response(True)
    

@api_view(["POST"])
def login(request):

    #get login user object
    body_unicode = request.body.decode('utf-8')
    user = json.loads(body_unicode)

    #verify if login data are valid

    #get certificate signature
    with open(user["username"]+"_cert.pem", "rb") as cert_file:
        cert_data = cert_file.read()
    cert = x509.load_pem_x509_certificate(cert_data)
    signature = cert.signature

    #verify signature
    

    return Response("login")


from ldap3 import Server, Connection, ALL

# Define server connection details
ldap_server = "ldap://192.168.0.102:389"
username = "cn=ines,dc=maxcrc,dc=com"
password = "ines"

class LDAPServer():

    def connect(self):
        server = Server(ldap_server)
        conn = Connection(server, user=username, password=password)
        conn.bind()
        

    # Search for an entry
        base_dn = "dc=maxcrc,dc=com"
        search_filter = "(cn=ines)"
        result = conn.search(search_base=base_dn, search_filter=search_filter)
    # Print the result
        print(result)


    def add(self,user):
        server = Server(ldap_server)
        
        conn = Connection(server, user=username, password=password)
        attributes = {
            'objectClass': ['person', 'organizationalPerson', 'inetOrgPerson'],
            'cn': user["username"],
            'sn': user["lastName"],
            'givenName': user["firstName"],
            'mail': user["email"],
        }
        
        conn.add("cn="+user["username"], attributes=attributes)
        
        if not conn.result['result'] == 0:
            print(conn.result)
        else:
            print('Successfully added entry')

