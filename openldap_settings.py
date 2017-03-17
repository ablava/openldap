"""
This config file contains constants describing
the specific environment where this script is used.
IMPORTANT: refer to the code on how they are used.
"""

# LDAP server address to connect to, e.g. ldaps://server.domain.edu:636/
LDAPSERVER = ''
# User to bind with, e.g. cn=admin,dc=university,dc=edu
USER = ''
# Credentials for the above user in base64, e.g. bmljZSB0cnkK
PASSWORD = ''
# BaseDN of the directory, e.g. dc=university,dc=edu
BASEDN = ''
# Email domain name for users, e.g. @university.edu
MAILDOMAIN = ''
# Pattern that identifies student user namess, e.g. _
STUPATTERN = ''
# Pattern that identifies guest users, e.g. starts with 'gst'
GSTPATTERN = ''
# OU where students are created, e.g. ,ou=people,dc=university,dc=edu
STUDENTOU = ''
# OU where guests are created, e.g. ,ou=people,dc=university,dc=edu
GUESTOU = ''
# OU where employees are created, e.g. ,ou=people,dc=university,dc=edu
EMPOU = ''
