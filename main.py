#!/usr/bin/env python3

import sys
from crawler import *
from parser import *

if __name__ == "__main__":
    #crawler.Run()
    ldap_manager = ORADLDAP(sys.argv[1])
    ldap_manager.Run()