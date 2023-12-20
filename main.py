#!/usr/bin/env python3

import sys
from oradldap import *
from parser import *

if __name__ == "__main__":
    #crawler.Run()
    if len(sys.argv) > 1:
        ldap_manager = ORADLDAP(sys.argv[1])
    else:
        ldap_manager = ORADLDAP()
    ldap_manager.Run()