#!/usr/bin/env python3

import sys
from crawler import *
from parser import *

if __name__ == "__main__":
    #crawler.Run()
    ldap_manager = ORADLDAP(sys.argv[1])
    ldap_manager.get_naming_context()
    ldap_manager.get_config_context()
    ldap_manager.check_anonymous_auth()
    #ldap_manager.check_all_acls()
    
    acl_string = """
            olcAccess: {0}to attrs=userPassword
            by self write
            by anonymous auth
            by * none
            by users read
            by dn.exact="cn=admin,dc=example,dc=com" write
            by * search
            by dn.regex="uid=[a-z]+,ou=people,dc=example,dc=com" read
            by peername.regex=".*\.example\.com" read
            by * none

            {1}to attrs=shadowLastChange
                by self write
                by * read

             {2}to *
                by * none
    """
    parser = OpenLDAPACLParser(acl_string)
    parser.display_acls()