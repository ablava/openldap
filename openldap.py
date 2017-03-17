#!/usr/bin/env python

"""
Simple script to manage entries in openldap. 

Usage: 
    python openldap.py -f input.json -o output.csv

Options:
    -h --help
    -f --file	Input file (required)
    -o --out	Output file (required)

Environment specific script constants are stored in this 
config file: openldap_settings.py
    
Input:

Input file is expected to be in JSON format (e.g. input.json).
with these 16 required data fields:
{
    "useractions": [
        {
            "action": "create",
            "username": "testuserj",
            "newusername": "testuserj",
            "loginDisabled": "False",
            "uidNumber": 15549,
            "gidNumber": 15549,
            "givenName": "John",
            "fullName": "John The Testuser",
            "sn": "Testuser",
            "employeeType": "ADM",
            "DNumber": "D01234567",
            "primO": "Biology",
            "businessCategory": "Aruba-User-Role = \"staff\"",
            "userPassword": "initial password",
            "description": "Create on this date or any note"
        }
    ] 
}
where action can be create/update/delete
where newusername is same as username or a new value if renaming the user

Output:

Output file (e.g. output.csv) will have these fields:

action, username, result (ERROR/SUCCESS: reason)

Logging:

Script creates a detailed openldap.log

All errors are also printed to stdout.

Author: C. Reitsma
With help from: A. Ablovatski
Based on the edir.py script by: A. Ablovatski
Email: ablovatskia@denison.edu
Date: 02/22/2016
"""

from __future__ import print_function
import time
import sys
import json
import csv
import argparse
import logging
import ldap
import ldap.modlist as modlist
import urllib
import textwrap
import smtplib
import base64
import hashlib

def main(argv):
    """This is the main body of the script"""
    
    # Setup the log file
    logging.basicConfig(
        filename='openldap.log',level=logging.DEBUG, 
        format='%(asctime)s, %(levelname)s: %(message)s', 
        datefmt='%Y-%m-%d %H:%M:%S')

    # Get LDAP creds and other constants from this settings file
    config_file = 'openldap_settings.py'
    
    if not readConfig(config_file):
        logging.error("unable to parse the settings file")
        sys.exit()
    
    # Parse script arguments
    parser = argparse.ArgumentParser()                                               

    parser.add_argument("--file", "-f", type=str, required=True, 
                        help="Input JSON file with user actions and params")
    parser.add_argument("--out", "-o", type=str, required=True, 
                        help="Output file with results of ldap user actions")

    try:
        args = parser.parse_args()
        
    except SystemExit:
        logging.error("required arguments missing - " \
                        "provide input and output file names")
        sys.exit()

    # Read input from json file
    in_file = args.file
    # Write output to csv file
    out_file = args.out
    
    try:
        f_in = open(in_file, 'rb')
        logging.info("opened file: {0}".format(in_file))
        f_out = open(out_file, 'wb')
        logging.info("opened file: {0}".format(out_file))
        reader = json.load(f_in)
        writer = csv.writer(f_out)
        writer.writerow( ['action','username','result'] )
        
        for row in reader["useractions"]:
            result = ''
            # Select what needs to be done
            if row["action"] == 'create':
                result = create(str(row["username"]), 
                                str(row["givenName"]), str(row["fullName"]), 
                                str(row["sn"]), str(row["employeeType"]), 
                                str(row["DNumber"]), 
                                str(row["primO"]), str(row["businessCategory"]), 
                                str(row["userPassword"]))
            elif row["action"] == 'update':
                result = update(str(row["username"]), str(row["newusername"]), 
                                str(row["uidNumber"]), 
                                str(row["gidNumber"]), str(row["givenName"]), 
                                str(row["fullName"]), str(row["sn"]), 
                                str(row["employeeType"]), str(row["DNumber"]), 
                                str(row["primO"]), str(row["businessCategory"]))
            elif row["action"] == 'delete':
                 result = delete(str(row["username"]))
            else:
                print("ERROR: unrecognized action")                
                logging.error("unrecognized action")
                result = "ERROR: Unrecognized action"
            
            # Write the result to the output csv file
            writer.writerow( [row["action"], row["username"], result] )
            
    except IOError:
        print("ERROR: Unable to open input/output file!")
        logging.critical("file not found: {0} or {1}".format(in_file, out_file))
        
    except Exception as e:
        print("ERROR: unknown error while attempting to read/write to file: " \
                "{0}".format(e))
        logging.critical("unknown error while attempting to read/write to " \
                "file".format(e))
        
    finally:
        f_in.close()
        logging.info("closed file: {0}".format(in_file))
        f_out.close()
        logging.info("closed file: {0}".format(out_file))
        
    return

def create(username, givenName, fullName, sn, employeeType, dNumber, ou, 
            businessCategory, userPassword):
    """This function adds users to openldap"""
    
    # Check if any of the parameters are missing
    params = locals()
    
    for _item in params:
        if str(params[_item]) == "":
            print("ERROR: unable to create user {0} because {1} is missing " \
                    "a value".format(username, _item))
            logging.error("unable to create user {0} because {1} is missing " \
                            "a value".format(username, _item))
            result = "ERROR: Missing an expected input value for " + _item \
                        + " in input file"
            return result

    # We have all we need, connect to LDAP
    l = ldapConnect()
    
    # Catch LDAP connection failure
    if not l:
        result = "ERROR: unable to connect to LDAP server"
        return result
        
    # Do a quick check if the user already exists
    if findUser(l, username):
        print("ERROR: cannot create user - user already exists: {0}" \
                .format(username))
        logging.error("cannot create user - user already exists: {0}" \
                .format(username))
        result = "ERROR: username already taken!"
        return result
        
    # Create new user if it does not exist
    try:
        
        # Build a dict for the "body" of the user object
        attrs = {}
        attrs['objectclass'] = ['top','person','organizationalPerson',
                                'inetOrgPerson','duPerson', 'qmailUser']
        attrs['uid'] = username
        h = hashlib.sha1()
        h.update(userPassword)
        attrs['userPassword'] =  '{SHA}' + base64.b64encode(h.digest())
        attrs['givenName'] = givenName
        attrs['cn'] = fullName
        attrs['sn'] = sn
        attrs['mail'] = username + MAILDOMAIN
        attrs['employeeType'] = employeeType
        attrs['employeeNumber'] = dNumber
        attrs['o'] = ou
        attrs['businessCategory'] = businessCategory
        attrs['pwdReset'] = 'TRUE'

        # Convert our dict to proper syntax using modlist module
        ldif = modlist.addModlist(attrs)

        # Do the actual synchronous add to the ldapserver
        dn = buildDN(username)
        l.add_s(dn,ldif)
        
        # Log user creation
        logging.info("user added to ldap: {0}" \
                        .format(username))
        print("SUCCESS: User {0} added to ldap" \
                        .format(username))
        
        # Its nice to the server to disconnect
        l.unbind_s()
        
    except ldap.LDAPError, e:
        print("ERROR: Could not add user to ldap: " \
                    "{0}".format(e))
        logging.error("ldap add failed for user: " \
                    "{0}".format(username))
        result = "ERROR: Could not create ldap user"
        return result
    
    result = "SUCCESS: User added to ldap"
    
    return result
    
def update(username, newusername, uidNumber, gidNumber, 
            givenName, fullName, sn, employeeType, dNumber, 
            ou, businessCategory):
    """This function updates user attributes 
    and renames users if needed"""  

    # Check if any of the arguments are missing
    params = locals()
    
    for _item in params:
        if str(params[_item]) == "":
            print("ERROR: unable to update user {0} because {1} is missing " \
                    "a value".format(username, _item))
            logging.error("unable to update user {0} because {1} is missing " \
                            "a value".format(username, _item))
            result = "ERROR: Missing an expected input value for " \
                        + _item + " in input file"
            return result

    # We have all we need, connect to LDAP
    l = ldapConnect()
    
    # Catch the condition when LDAP connection failed
    if not l:
        result = "ERROR: unable to connect to LDAP server"
        return result
    
    # Do a quick check if the user exists
    if not findUser(l, username):
        print("ERROR: user does not exist: {0}".format(username))
        logging.error("user does not exist: {0}".format(username))
        result = "ERROR: user could not be found!"
        return result
    
    # rename if new username is different
    if username != newusername:
        # First check if both usernames are of the same type
        userType = getUserType(username)
        
        if userType != getUserType(newusername):
            print("ERROR: unable to rename user {0} to {1} because " \
                    "they are of different type".format(username, newusername))
            logging.error("unable to rename user {0} to {1} because " \
                    "they are of different type".format(username, newusername))
            result = "ERROR: won't rename users across different types"
            return result

        # Rename the user
        try:
            # Check if the new user name already exists
            if findUser(l, newusername):
                print("ERROR: cannot rename user - user already exists: {0}" \
                        .format(newusername))
                logging.error("cannot rename user - user already exists: {0}" \
                                .format(newusername))
                result = "ERROR: newusername already taken!"
                return result
            
            # Get the dn of our user
            dn = buildDN(username)
            
            # you can safely ignore the results returned as an exception 
            # will be raised if the rename doesn't work.
            l.rename_s(dn, 'uid=' + newusername)
            
            logging.info("user {0} renamed to {1} in ldap" \
                            .format(username, newusername))
            
        except Exception as e:
            print("ERROR: unknown error while renaming user: {0}".format(e))
            logging.error("unknown error while attempting to rename user")
            result = "ERROR: Could not rename ldap user"
            
        findUser(l, newusername)
        print("INFO: user {0} renamed to {1} in ldap" \
                .format(username, newusername))
        logging.info("user {0} fully renamed to {1} in ldap" \
                        .format(username, newusername))
        
    # Rename or not, update attributes or disable
    try:
        # Build the list of modifications
        # We do not reset passwords here!
        mod_attrs = [
            ( ldap.MOD_REPLACE, 'givenName', givenName ),
            ( ldap.MOD_REPLACE, 'cn', fullName ),
            ( ldap.MOD_REPLACE, 'sn', sn ),
            ( ldap.MOD_REPLACE, 'uid', newusername ),
            ( ldap.MOD_REPLACE, 'mail', newusername + MAILDOMAIN ),
            ( ldap.MOD_REPLACE, 'employeeType', employeeType ),
            ( ldap.MOD_REPLACE, 'employeeNumber', dNumber ),
            ( ldap.MOD_REPLACE, 'o', ou ),
            ( ldap.MOD_REPLACE, 'businessCategory', businessCategory )
        ]
        if containsPosixAccount(l,username):
            mod_attrs = [
                ( ldap.MOD_REPLACE, 'uidNumber', uidNumber ),
                ( ldap.MOD_REPLACE, 'gidNumber', gidNumber ),
                ( ldap.MOD_REPLACE, 'homeDirectory', "/home/" + newusername )
            ]
        
        # Get the dn of our user
        dn = buildDN(newusername)
        
        # Do the actual modifications
        l.modify_s(dn, mod_attrs)

        # Its nice to the server to disconnect when done
        l.unbind_s()
        
    except ldap.LDAPError, e:
        print("ERROR: Could not update user in ldap: {0}".format(e))
        logging.error("ldap update failed for: {0}".format(username))
        result = "ERROR: Could not update ldap user"
        return result
    
    except Exception as e:
        print("ERROR: unknown error while updating user: {0}".format(e))
        logging.error("unknown error while updating user")
        result = "ERROR: Could not update ldap user"
            
    print("SUCCESS: user {0} updated in ldap".format(newusername))
    logging.info("User {0} updated ldap".format(dn))
    result = "SUCCESS: User updated in ldap"
    
    return result
    
    
def delete(username):
    """This function deletes a user from ldap"""
    
    # Check if the argument is missing
    if str(username) == "":
        print("ERROR: unable to delete user because username argument " \
                "is missing a value")
        logging.error("unable to delete user because username argument " \
                        "is missing a value")
        result = "ERROR: Missing an expected input value for username " \
                    "in input file"
        return result
            
    # We have all we need, connect to LDAP
    l = ldapConnect()
        
    # Catch the condition when LDAP connection failed
    if not l:
        result = "ERROR: unable to connect to LDAP server"
        return result
    
    # Do a quick check if the user exists
    if not findUser(l, username):
        print("ERROR: user does not exist: {0}".format(username))
        logging.error("user does not exist: {0}".format(username))
        result = "ERROR: user could not be found!"
        return result
    
    # Delete the user if all is OK
    try:
        # Get the dn of our user
        dn = buildDN(username)
        
        l.delete_s(dn)
        logging.info("user {0} deleted from ldap".format(dn))
        
        # Its nice to the server to disconnect when done
        l.unbind_s()
        
    except ldap.LDAPError, e:
        print("ERROR: Could not delete user in ldap: {0}".format(e))
        logging.error("ldap delete failed for {0}".format(dn))
        result = "ERROR: Could not delete ldap user"
        return result

    except Exception as e:
        print("ERROR: unknown error while deleting user: {0}".format(e))
        logging.error("unknown error while deleting user")
        result = "ERROR: Could not delete ldap user"
        
    print("SUCCESS: user {0} deleted from ldap".format(username))
    logging.info("user {0} fully deleted from ldap".format(dn))
    result = "SUCCESS: User deleted from ldap"
    
    return result

def readConfig(config_file):
    """Function to import the config file"""
    
    if config_file[-3:] == ".py":
        config_file = config_file[:-3]
    settings = __import__(config_file, globals(), locals(), [])
    
    # Read settings and set globals
    try: 
        global LDAPSERVER
        global USER
        global PASSWORD
        global baseDN
        global MAILDOMAIN
        global STUPATTERN
        global GSTPATTERN
        global STUDENTOU
        global GUESTOU
        global EMPOU
        
        LDAPSERVER = settings.LDAPSERVER
        USER = settings.USER
        PASSWORD = base64.b64decode(settings.PASSWORD)
        baseDN = settings.BASEDN
        MAILDOMAIN = settings.MAILDOMAIN
        STUPATTERN = settings.STUPATTERN
        GSTPATTERN = settings.GSTPATTERN
        STUDENTOU = settings.STUDENTOU
        GUESTOU = settings.GUESTOU
        EMPOU = settings.EMPOU

    except Exception as e:
        print("ERROR: unable to parse the settings file: {0}".format(e))
        return False
        
    return True

def getUserType(username):
    """ Function to determine the type of a user"""

    if STUPATTERN in username:
        userType = "STU"
    elif GSTPATTERN == username[0:-4]:
        userType = "GST"
    else:
        userType = "EMP"

    return userType
    

def ldapConnect():
    """Function to bind to LDAP server"""

    ldap_user = USER
    ldap_secret = PASSWORD
    ldap_server = LDAPSERVER
    
    try:
        # Open a connection to the LDAP server
        l = ldap.initialize(ldap_server)
        l.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        
        # Bind with a user that has rights to add/update objects
        l.simple_bind_s(ldap_user, ldap_secret)
    
    except ldap.LDAPError, e:
        print("ERROR: Could not establish LDAP connection: {0}".format(e))
        logging.error("problem binding to ldap LDAP server")
        return False
        
    return l

def findUser(l, username):
    """Do a quick check if the user already exists"""

    # Set the basic search parameters
    searchScope = ldap.SCOPE_SUBTREE
    retrieveAttributes = ['dn']
    searchFilter = "uid={}".format(username)
        
    try:
        ldap_result = l.search_s(baseDN, searchScope, searchFilter, 
                                    retrieveAttributes)		
    
    except ldap.LDAPError, e:
        print("ERROR: problems with LDAP search: {0}".format(e))
        logging.error("problem with LDAP search for: {0}".format(username))
    
    # Check the search results
    if len(ldap_result) == 0:
        logging.info("user {0} does not exist in ldap".format(username))
        return False
        
    if len(ldap_result) > 1:
        logging.info("user {0} has multiple entries in ldap".format(username))
        return False
        
    return True
    
def containsPosixAccount(l, username):
    """Check for presence of objectClass=posixAccount"""

    # Set the basic search parameters
    searchScope = ldap.SCOPE_SUBTREE
    retrieveAttributes = None
    searchFilter = "(&(uid={})(objectClass=posixAccount))".format(username)

    try:
        ldap_result = l.search_s(baseDN, searchScope, searchFilter, 
                                    retrieveAttributes)

    except ldap.LDAPError, e:
        print("ERROR: problems with LDAP search: {0}".format(e))
        logging.error("problem with LDAP search for: {0}".format(username))

    # Check the search results
    if len(ldap_result) == 0:
        logging.info("user {0} does not exist in ldap".format(username))
        return False

    if len(ldap_result) > 1:
        logging.info("user {0} has multiple entries in ldap".format(username))
        return False

    return True

def buildDN(username):
    """Function to construct FQN for a username"""

    # First check if emp or student or guest
    userType = getUserType(username)
    
    if userType == "STU":
        dn = "uid=" + username + STUDENTOU
        logging.info("looks like we have a student here: {0}".format(username))
    elif userType == "GST":
        dn = "uid=" + username + GUESTOU
        logging.info("looks like we have a guest here: {0}".format(username))
    else:
        dn="uid=" + username + EMPOU
        logging.info("looks like we have an employee here: {0}".format(username))

    return dn

if __name__ == "__main__":
    main(sys.argv)
