import configparser
from ldap3 import Server, Connection, SAFE_SYNC, SUBTREE, BASE

class Crawler:
    rootdn_user = None
    rootdn_password = None
    uri = None
    base_dn = None
    ldap_server = None
    suffix = None

    def __init__(self, config_path=None):
        if config_path:
            config = configparser.ConfigParser()
            config.read(config_path)

            self.rootdn_user = config.get('auth', 'rootdn_user')
            self.rootdn_password = config.get('auth', 'rootdn_password')
            self.uri = config.get('auth', 'uri')
            self.base_dn = config.get('auth', 'base_dn')
            self.suffix = config.get('auth', 'base_dn')
            self.ldap_server = Server(self.uri, get_info=all)

            print("[Authenticated mode]")
        else:
            print("[Anonymous mode]")

        print("Crawler initialized...")
            
    def check_ppolicy(self) -> bool:
        try:
            with Connection(self.uri, self.rootdn_user, self.rootdn_password, auto_bind=True) as conn:
                conn.search(search_base='', search_filter='(objectClass=*)', search_scope=BASE)
                supported_controls = conn.result.get('controls', [])
                if any(control['controlType'] == '1.3.6.1.4.1.42.2.27.8.5.1' for control in supported_controls):
                    print("[Password Policy] - Enabled")
                else:
                    print("[Password Policy] - Disabled or not supported")
        except Exception as e:
            print(f"Error checking password policy: {e}")
        
    def check_acl(self) -> bool:
        try:
            with Connection(self.uri, self.rootdn_user, self.rootdn_password, auto_bind=True) as conn:
                conn.search(search_base='cn=config', search_filter='(olcDatabase={1}mdb)', search_scope=SUBTREE, attributes=['olcAccess'])
                attrs = str(conn.entries[0]).split('\n')
                if conn.entries:
                    print("[ACLs] - Enabled")
                else:
                    print("[ACLs] - Disabled or not supported")

        except Exception as e:
            print(f"Error checking ACLs: {e}")
        return False

    def check_privileged_users_permissions(self) -> bool:
        attributes_check = ["pwdExpireWarning", "pwdMaxAge"]
        try:
            with Connection(self.uri, self.rootdn_user, self.rootdn_password, auto_bind=True) as conn:
                conn.search(search_base=self.suffix, search_filter='(|(objectClass=person)(objectClass=inetOrgPerson)(objectClass=organizationalPerson))',attributes=attributes_check)
            if conn.entries:
                print("[User Password Expiration Date] - Enabled")
            else:
                print("[User Password Expiration Date] - Disabled or not supported")
        except Exception as e:
            print(f"Error checking attribute: {e}")
            return False

    def check_asleep_accounts(self) -> bool:
        return False

    def Run(self):
      self.check_ppolicy()  
      self.check_acl()
      self.check_privileged_users_permissions()