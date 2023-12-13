import configparser
from ldap3 import Server, Connection, SAFE_SYNC, SUBTREE, BASE, ANONYMOUS,ALL


class ORADLDAP:
    def __init__(self, config_path=None):
        # Default configuration values
        default_config = {
            'rootdn_user': 'cn=admin,cn=config',
            'rootdn_password': 'secret',
            'uri': 'ldap://127.0.0.1:389',
            'base_dn': '',
            'suffix': '',
        }

        # Initialize with default values
        self.user = default_config['rootdn_user']
        self.password = default_config['rootdn_password']
        self.uri = default_config['uri']
        self.base_dn = default_config['base_dn']
        self.suffix = default_config['suffix']
        self.server = None
        self.connection = None

        if config_path:
            config = configparser.ConfigParser()
            try:
                config.read(config_path)

                # Update values from the configuration file
                self.user = config.get('auth', 'rootdn_user', fallback=default_config['rootdn_user'])
                self.password = config.get('auth', 'rootdn_password', fallback=default_config['rootdn_password'])
                self.uri = config.get('auth', 'uri', fallback=default_config['uri'])
                self.base_dn = config.get('auth', 'base_dn', fallback=default_config['base_dn'])
                self.suffix = config.get('auth', 'suffix', fallback=default_config['suffix'])

            except configparser.Error as e:
                raise ValueError(f"Error reading configuration: {e}")
        try:
            self.server = Server(self.uri, get_info=ALL)
            self.connection = Connection(self.server, user=self.user, password=self.password, auto_bind=True)
        except Exception as e:
            raise ValueError(f"Error establishing LDAP connection: {e}")

    def _connect(self, user=None):
        if not self.connection:
            self.server = Server(self.uri, get_info=ALL)
            if user==ANONYMOUS:
                self.connection = Connection(self.server, auto_bind=True)
            else:
                self.connection = Connection(self.server, user=self.user, password=self.password, auto_bind=True)
    def _disconnect(self):
        if self.connection:
            self.connection.unbind()
            self.server = None
            self.connection = None

    def get_naming_context(self):
        try:
            self._connect()
            self.connection.search(search_base='', search_filter='(objectclass=*)', attributes=['namingContexts'], search_scope=BASE)
            naming_context = self.connection.entries[0]
            naming_context = str(naming_context)
            naming_context = naming_context.split("namingContexts:")[1].strip()
        except Exception as e:
            raise ValueError(f"Error retrieving naming context: {e}")
        finally:
            self._disconnect()
        return naming_context

    def check_anonymous_access(self):
        try:
            self._connect(user=ANONYMOUS)

            # Si la connexion réussit, alors l'accès anonyme est autorisé
            return True
        except Exception as e:
            # Si la connexion échoue, alors l'accès anonyme n'est pas autorisé
            return False
        finally:
            self._disconnect()
    def get_config_context(self):
        try:
            self._connect()
            self.connection.search(search_base='', search_filter='(objectclass=*)', attributes=['*'],search_scope='BASE')
            config_context = str(self.server.info).split("configContext:")[1].lstrip().split("\n")[0]
        except Exception as e:
            raise ValueError(f"Error retrieving config context: {e}")
        finally:
            self._disconnect()
        return config_context

    def __del__(self):
        # Close the LDAP connection when the object is destroyed
        if self.connection:
            self.connection.unbind()


class Crawler:
    config = None
    server = None
    connection = None
    suffix = None

    user = None
    password = None
    uri = None
    base_dn = None

    def __init__(self, config_path=None):
        if config_path:
            config = configparser.ConfigParser()
            config.read(config_path)

            self.user = config.get('auth', 'rootdn_user')
            self.password = config.get('auth', 'rootdn_password')
            self.uri = config.get('auth', 'uri')
            self.base_dn = config.get('auth', 'base_dn')
            self.suffix = config.get('auth', 'base_dn')
            self.server = Server('127.0.0.1',  get_info=all)
            self.connection = Connection(self.server, auto_bind=True)
            
            print("Anonymous bind")
            print(self.server.info)
                
            
    def get_naming_context(self):

        return naming_context

    def check_ppolicy(self) -> bool:
        try:
            with Connection(self.uri, self.rootdn_user, self.rootdn_password, auto_bind=True) as conn:
                conn.search(search_base='cn=config', search_filter='(objectClass=*)', search_scope=SUBTREE)
                # Check if ppolicy module is loaded
                #for attribute in conn.entries:
                #print(attribute)
                if 'olcOverlay' in attribute:
                    if 'ppolicy' in attribute:
                        print("[PPOLICY] - Enabled")
                    else:
                        print("[PPOLICY] - Disabled or not supported")
                else:
                    print("The olcModuleLoad attribute is not present in the server configuration.")

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

    def check_users_password_expiration(self) -> bool:
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
      print("Initialization...")
      #self.check_ppolicy()  
      #self.check_acl()
      #self.check_users_password_expiration()