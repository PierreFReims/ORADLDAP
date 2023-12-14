import configparser
from parser import *
from ldap3 import Server, Connection, SAFE_SYNC, SUBTREE, BASE, ANONYMOUS,ALL
import re


class ORADLDAP:
    def __init__(self, config_path=None):

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

    def check_anonymous_auth(self):
        try:
            self._connect(user=ANONYMOUS)
            return True
        except Exception as e:
            return False
        finally:
            self._disconnect()
       
    def check_anonymous_acl(self):
        try:
            self._connect()
            self.connection.search(search_base='olcDatabase={1}mdb,cn=config', search_filter='(objectClass=*)', search_scope='BASE', attributes=['olcAccess'])
            acls = str(self.connection.entries[0]).split("olcAccess:")[1].split("\n")
            userPassword_attribute = re.compile(r'\bto\s+attrs=userPassword\s+', re.IGNORECASE)
            by_pattern = re.compile(r'by\s+([^\s]+)\s+(\w+)(?=\s+by|$)', re.IGNORECASE)
            for acl in acls:
                acl = acl.strip()
                match = re.search(userPassword_attribute, acl)
                if match:
                    matches = by_pattern.findall(acl)
                    # Check if 'anonymous' has permissions other than 'none'
                    anonymous_permissions = [permission for entity, permission in matches if entity == 'anonymous']
                    #if 'none' not in anonymous_permissions:
                    #    print("Anonymous has permissions other than 'none'")
                    return anonymous_permissions        
        except Exception as e:
            # Handle the exception as needed
            print(f"Error checking anonymous ACL: {e}")
        finally:
            self._disconnect()

    def check_all_acls(self):
        try:
            self._connect()
            self.connection.search(search_base='olcDatabase={1}mdb,cn=config', search_filter='(objectClass=*)', search_scope='BASE', attributes=['olcAccess'])
            acls_entry = str(self.connection.entries[0])
            result_string = re.sub(r'^\s+', '', acls_entry, flags=re.MULTILINE)
            
            if acls_entry:
                parser = OpenLDAPACLParser(acls_entry)
                parser.display_acls()
        except Exception as e:
            # Handle the exception as needed
            print(f"Error checking ACLs: {e}")
        finally:
            self._disconnect()

    def check_password_write_permission(self):
        try:
            self._connect()
            self.connection.search(search_base='olcDatabase={1}mdb,cn=config', search_filter='(objectClass=*)', search_scope='BASE', attributes=['olcAccess'])
            acls = str(self.connection.entries[0]).split("olcAccess:")[1].split("\n")
            userPassword_attribute = re.compile(r'\bto\s+attrs=userPassword\s+', re.IGNORECASE)
            by_pattern = re.compile(r'by\s+([^\s]+)\s+(\w+)(?=\s+by|$)', re.IGNORECASE)
            for acl in acls:
                acl = acl.strip()
                match = re.search(userPassword_attribute, acl)
                if match:
                    matches = by_pattern.findall(acl)
                    # Check if 'anonymous' has permissions other than 'none'
                    anonymous_permissions = [permission for entity, permission in matches if entity == 'anonymous']
                    #if 'none' not in anonymous_permissions:
                    #    print("Anonymous has permissions other than 'none'")
                    return anonymous_permissions        
        except Exception as e:
            # Handle the exception as needed
            print(f"Error checking anonymous ACL: {e}")
        finally:
            self._disconnect()

    def __del__(self):
        # Close the LDAP connection when the object is destroyed
        if self.connection:
            self.connection.unbind()
