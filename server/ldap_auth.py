import ldap
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User

class LDAPBackend(BaseBackend):

    def authenticate(self, request, username=None, password=None, **kwargs):
        # Connect to the LDAP server
        l = ldap.initialize("ldap://ldap.example.com")
        l.protocol_version = ldap.VERSION3
        
        # Bind to the server using the provided username and password
        try:
            l.simple_bind_s(username, password)
        except ldap.INVALID_CREDENTIALS:
            return None
        
        # Search for the user's DN
        search_result = l.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, f'uid={username}')
        if len(search_result) != 1:
            return None
        user_dn = search_result[0][0]

        # Try to bind to the server using the user's DN and password
        try:
            l.simple_bind_s(user_dn, password)
        except ldap.INVALID_CREDENTIALS:
            return None
        
        # Retrieve the user's email
        email = search_result[0][1]['mail'][0].decode("utf-8")
        
        # Check if the user exists in the Django database
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            # Create a new user
            user = User(username=username, email=email)
            user.save()
        
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
