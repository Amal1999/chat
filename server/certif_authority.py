from os import path
import datetime
# verifying function doesn't exist in cryptography module
from OpenSSL.crypto import verify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


CA_CERT_PATH = 'ca_cert.pem'
CA_KEY_PATH = 'ca_key.pem'
cert = None
key = None

def caCertifKey():
        global cert
        global key
        if(path.isfile(CA_CERT_PATH) and path.exists(CA_CERT_PATH) and path.isfile(CA_KEY_PATH) and path.exists(CA_KEY_PATH)):
            cert = x509.load_pem_x509_certificate(
                open(CA_CERT_PATH, 'rb').read(), default_backend())
            key = serialization.load_pem_private_key(
                open(CA_KEY_PATH, 'rb').read(), password=None, backend=default_backend())
        else:
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=3072,
                backend=default_backend()
            )
            with open(CA_KEY_PATH, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"TN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Tunis"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Insat"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"INSAT"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"INSAT"),
            ])
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).sign(key, hashes.SHA256(), default_backend())
            with open(CA_CERT_PATH, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
        return (key, cert)

class CA():  

    _instances = {}
      
    def __init__(self):
        self.ca_key, self.ca_cert = caCertifKey()
        self.ca_pubkey = self.ca_key.public_key()

        
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]


    def createCertificate(self, csr, username):
        if(not(path.exists(username+"_cert.pem") and path.isfile(username+"_cert.pem"))):
            with open(CA_CERT_PATH, "rb") as cert_file:
                ca_certificate = x509.load_pem_x509_certificate(
                    cert_file.read(),
                    default_backend()
                )
            csr = x509.load_pem_x509_csr(
                open(username+'_csr.pem', 'rb').read(), default_backend())
            cert_client = x509.CertificateBuilder().subject_name(
                csr.subject
            ).issuer_name(
                ca_certificate.subject
            ).public_key(
                csr.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=30)
            )
            for ext in csr.extensions:
                cert_client.add_extension(ext.value, ext.critical)

            cert_client = cert_client.sign(key, hashes.SHA256(), default_backend())
            with open(username+'_cert.pem', 'wb') as f:
                f.write(cert_client.public_bytes(serialization.Encoding.PEM))




    def verifyCertificate(self, username):
    
        with open(username+"_cert.pem", "rb") as client_cert_file:
            client_certificate = x509.load_pem_x509_certificate(
            client_cert_file.read(),
            default_backend()
            )
        try:
            result = self.ca_pubkey.verify(
                client_certificate.signature,
                client_certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                client_certificate.signature_hash_algorithm,)
            return True
        except:
            return False
        