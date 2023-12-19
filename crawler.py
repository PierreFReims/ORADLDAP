import configparser
import yaml
import time
import ssl
from parser import OpenLDAPACLParser
from report import VulnerabilityReport
from ldap3 import Server, Connection, SAFE_SYNC, SUBTREE, BASE, ANONYMOUS, ALL,Tls
import re
import logging

class ORADLDAP:
    def __init__(self, config_path='conf.yaml'):
        print('Init...')
        self.config = configparser.ConfigParser()
        self.config_path = config_path
        self.server_uri = None
        self.bind_dn = None
        self.bind_password = None
        self.use_ldaps = False
        self.server = None
        self.connection = None
        self.logging = None
        self.domain_admins = []
        self.report = VulnerabilityReport()
        
        self._read_config()

    def _connect(self):
        try:
            # Configure TLS if LDAPS is used
            tls_configuration = None
            if self.use_ldaps:
                tls_configuration = Tls(validate=ssl.CERT_REQUIRED)

            # Create a server object
            self.server = Server(f"{self.server_uri}:{self.port}", get_info=ALL, use_ssl=self.use_ldaps, tls=tls_configuration)

            # Create a connection object
            self.connection = Connection(self.server, user=self.bind_dn, password=self.bind_password, auto_bind=True)

        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            self.connection = Connection(self.server, auto_bind=True)
    
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
            self.report.add_vulnerability('1','vuln_allow_anon_auth','Binding anonyme autorisé','Permet à une personne non autorisée d\'intérrégir avec le service et collecter des informations.','Désactiver la possibilité d’établir une connexion anonyme.')
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
                acls = parser.get_acls()
                dangerous_permissions = []
                for acl_entry in acls:
                    target_attribute = acl_entry.get('to', '')
                    permissions = acl_entry.get('by', [])
                    for permission in permissions:
                        entity = permission.get('entity', '')
                        permission_type = permission.get('permission', '')
                        if permission_type == 'write' and entity != 'self':
                            # Check for dangerous write permissions on attributes other than userPassword
                            dangerous_permissions.append({
                                'target_attribute': target_attribute,
                                'entity': entity,
                                'permission_type': permission_type
                            })
                        elif permission_type == 'auth' and entity == 'anonymous':
                            # Check for dangerous auth permissions for anonymous users
                            dangerous_permissions.append({
                                'target_attribute': target_attribute,
                                'entity': entity,
                                'permission_type': permission_type
                            })
                # Print the results
                if dangerous_permissions:
                    self.report.add_vulnerability('1','vuln_dangerous_acls','Permissions dangereuse sur le serveur','Des Contrôles d’accès sont inéxistants sur le serveur LDAP, ou ne protègent pas suffisament les attributs critiques des entrées utilisateurs comme userPassword, uid.','Accorder des privilèges de lecture exclusivement aux propriétaires et octroyer les droits d\'écriture au compte administrateur.')
                    #print("Dangerous permissions found:")
                    for entry in dangerous_permissions:
                        var = 'ok'
                        #print(f"Target Attribute: {entry['target_attribute']}, Entity: {entry['entity']}, Permission Type: {entry['permission_type']}")
                else:
                    var = 'ok'
                    #print("No dangerous permissions found.")

        except Exception as e:
            print(f"Error checking ACLs: {e}")
        finally:
            self._disconnect()

    def check_default_acl_rule(self):
        try:
            self._connect()
            self.connection.search(search_base='olcDatabase={1}mdb,cn=config', search_filter='(objectClass=*)', search_scope='BASE', attributes=['olcAccess'])
            acls_entry = str(self.connection.entries[0])
            result_string = re.sub(r'^\s+', '', acls_entry, flags=re.MULTILINE)
            if acls_entry:
                parser = OpenLDAPACLParser(acls_entry)
                acls = parser.get_acls()
                if(
                    acls[-1]['to'] == '*'
                    and any(entry["entity"] == "*" and entry["permission"] == "none" for entry in acls[-1]['by'])
                ):
                    var = 'ok'
                    #print('No permissions')
                else:
                    self.report.add_vulnerability('1','vuln_dangerous_default_acl','ACL par default dangereux','Si aucune règle d\'ACL n\'a été déclenchée, la dernière règle s\'applique de manière globale, couvrant toutes les éventualités et autorisant potentiellement des actions risquées.',    
                    """dn: olcDatabase={1}mdb,cn=config\n changetype: modify\n replace: olcAccess\nolcAccess: {4}to * by * none""")
                    #print('Default ACL rule is dangerous')
        except Exception as e:
            print(f"Error checking ACLs: {e}")
        finally:
            self._disconnect()

    """
    Check users that have write permissions on the userPassword attribute
    You can define management users that are supposed to have those permissions in the conf.yaml file 
    """
    def check_password_write_permission(self):
        users_to_check = self.domain_admins
        users_to_check.append("self")
        users_with_write_permissions = []
        try:
            self._connect()
            self.connection.search(search_base='olcDatabase={1}mdb,cn=config', search_filter='(objectClass=*)', search_scope='BASE', attributes=['olcAccess'])
            acls_entry = str(self.connection.entries[0])
            parser = OpenLDAPACLParser(acls_entry)
            acls = parser.get_acls()
            for acl in acls:
                by_rules = acl.get('by', [])
                for rule in by_rules:
                    entity = rule.get('entity', '')
                    permission = rule.get('permission', '')
                    # Check for write permission first
                    if permission == 'write' and (entity == '*' or entity not in users_to_check):
                        # Check the 'to' attribute after write permission
                        to_attribute = acl.get('to', '')
                        if 'userPassword' in to_attribute or '*' in to_attribute:
                            self.report.add_vulnerability('1','vuln_userpassword_write_perm','Permissions en écriture sur un attribut userPassword','Les autorisations d\'écriture sur l\'attribut userPassword représentent un risque significatif pour la sécurité du système. Cela signifie que des entités non autorisées pourraient potentiellement modifier les mots de passe des utilisateurs, compromettant ainsi la confidentialité des informations sensibles.','Examiner et mettre à jour les contrôles d\'accès (ACL) pour l\'attribut userPassword')
                            # Additional checks or actions based on the 'to' attribute if needed

        except Exception as e:
            # Handle the exception as needed
            print(f"Error checking anonymous ACL: {e}")
        finally:
            self._disconnect()

    def _read_config(self):
        try:
            with open(self.config_path) as f:
                data = yaml.safe_load(f)
                self.server_uri = data['ldap']['server_uri']
                self.port = data['ldap']['port']
                self.bind_dn = data['ldap']['bind_dn']   
                self.bind_password = data['ldap']['bind_password'] 
                self.use_ldaps = data['ldap']['use_ldaps'] 
                for domain_admin in data['ldap']['admins_dn']:
                    self.domain_admins.append(domain_admin)
                print('Reading conf..')

        except (configparser.Error, ValueError) as e:
            raise ValueError(f"Error reading configuration: {e}")

    def Run(self):
        start_time = time.time()
        # Security Checks
        self.get_naming_context()
        self.get_config_context()
        self.check_anonymous_auth()
        self.check_all_acls()
        self.check_default_acl_rule()
        self.check_password_write_permission()
        self.report.generate_report()
        
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"Program execution time: {execution_time} seconds")

    def __del__(self):
        # Close the LDAP connection when the object is destroyed
        if self.connection:
            self.connection.unbind()
    