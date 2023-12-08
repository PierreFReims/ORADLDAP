import configparser
from ldap3 import Server, Connection, SAFE_SYNC

class Crawler:
    dn = None
    password = None
    uri = None
    base_dn = None

    def __init__(self, config_path=None):
        if config_path:
            config = configparser.ConfigParser()
            config.read(config_path)

            self.dn = config.get('auth', 'dn')
            self.password = config.get('auth', 'password')
            self.uri = config.get('auth', 'uri')
            self.base_dn = config.get('auth', 'base_dn')

            # Initialize an LDAP Server object
            self.ldap_server = Server(self.uri)
            print("[Authenticated mode]")
        else:
            print("[Anonymous mode]")

        print("Crawler initialized...")
            

    def check_ppolicy()->bool:

        # LDAP server details
        ldap_server = Server('ldap://your-ldap-server:389', get_info=ALL)

        # Establish an LDAP connection
        with Connection(ldap_server, user=ldap_dn, password=ldap_password, auto_bind=True) as conn:
            # Search for password policy-related attributes
            base_dn = 'cn=subschema'
            filter_str = '(objectClass=*)'
            attributes = ['subschemaSubentry']

            conn.search(search_base=base_dn, search_filter=filter_str, search_scope=SUBTREE, attributes=attributes)

            # Check if password policy attributes are present
            entry = LDAPEntry(conn, base_dn)
            if 'subschemaSubentry' in entry:
                subschema_subentry = entry['subschemaSubentry'].value
                if 'pwdPolicySubentry' in conn.server.schema.get_entry(subschema_subentry):
                    return True
            else:
                print("Unable to determine password policy configuration.")
        return False
        
    def check_acl()->bool:
        return False