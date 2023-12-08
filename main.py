#!/usr/bin/env python3

import sys
from crawler import *
from ldap3 import Server, Connection, SAFE_SYNC

def ldap_query(config_file=None):
    config = configparser.ConfigParser()
    config.read(config_file)

    ldap_dn = config.get('auth', 'dn')
    ldap_password = config.get('auth', 'password')
    ldap_uri = config.get('auth', 'uri')
    ldap_base_dn = config.get('auth', 'base_dn')

    ldap_server = Server(ldap_uri, get_info=all)
    
    with Connection(ldap_server, user=ldap_dn, password=ldap_password, auto_bind=True) as conn:
        base_dn = ldap_base_dn
        filter_str = '(objectClass=*)'
        attributes = ['cn', 'sn', 'mail']

        conn.search(search_base=base_dn, search_filter=filter_str, attributes=attributes)
        for entry in conn.entries:
            print(entry.entry_dn)
            #for attr in attributes:
            #    print(f"{attr}: {entry[attr]}")
            print('-' * 30)

if __name__ == "__main__":
    if (len(sys.argv) != 1):
        Crawler(sys.argv[1])
    else:
        Crawler()
