import configparser
import yaml
import time
import ssl
import sys
from parser import OpenLDAPACLParser
from report import VulnerabilityReport
from ldap3 import Server, Connection, SAFE_SYNC, SUBTREE, BASE, ANONYMOUS, ALL, Tls, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
from ldap3.core.exceptions import *
import re
import logging

class ORADLDAP:
    
    def __init__(self, config_path='conf.yaml'):
        print('Init...')
        self.config = configparser.ConfigParser()
        self.config_path = config_path
        self.naming_context = None
        self.server_uri = None
        self.bind_dn = None
        self.bind_password = None
        self.server = None
        self.connection = None
        self.logging = None
        self.critical_ous = []
        self._read_config()

        self.server = Server(self.server_uri,port=self.port, use_ssl=self.use_starttls)
        if self.admin_password == None:
            self.admin_password = input("Mot de passe administrateur: ")

        self.report = VulnerabilityReport()

    def _connect(self, anonymous=False):
        try:
            # Create a server object
            self.server = Server(self.server_uri, port=self.port, get_info=ALL)

            # Connect
            self.connection = Connection(self.server, user=self.bind_dn, password=self.bind_password, auto_bind=True)

            if self.use_starttls:
                # Start TLS if configured
                self.connection.start_tls()

            print('Connected successfully')

        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            sys.exit(-1)
            
    def _connect_anonymously(self):
        self._connect(anonymous=True)

    def _connect_authenticated(self):
        self._connect(anonymous=False)

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
            self.naming_context = naming_context
            self.report.suffix = naming_context
        
        except LDAPSocketOpenError as e:
            print("Socket is not opened. Abording...")
            sys.exit(-1)

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
        
        except LDAPSocketOpenError as e:
            print("Port {0} closed. Abording...".format(self.port))
            sys.exit(-1)

        except Exception as e:
            raise ValueError(f"Error retrieving config context: {e}")
        
        finally:
            self._disconnect()
        
        return config_context

    def check_anonymous_auth(self):
        try:
            self._connect(anonymous=True,fallback=False)
            self.report.add_vulnerability('1','vuln_allow_anon_auth','Binding anonyme autorisé','Permet à une personne non autorisée d\'intérrégir avec le service et collecter des informations.','Désactiver la possibilité d’établir une connexion anonyme.')
            return True
        
        except LDAPSocketOpenError as e:
            print("Port {0} closed. Abording...".format(self.port))
            sys.exit(-1)

        except Exception as e:
            return False
        finally:
            self._disconnect()
       
    def check_anonymous_acl(self):
        try:
            self._connect(anonymous=True,fallback=False)
            self.connection.search(search_base='olcDatabase={1}mdb,cn=config', search_filter='(objectClass=*)', search_scope='BASE', attributes=['olcAccess'])
            if not len(self.connection.entries) == 0:
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
                        if 'none' not in anonymous_permissions:
                            self.report.add_vulnerability('1','vuln_anonymous_dangerous_perms','Permissions dangereuses pour un utilisateur non authentifié','Un utilisateur non authentifié a des permissions autres que \'none\' sur certains attributs','Il est recommandé de donner des permissions \'none\' à utilisateurs anonymes, ou configurer une règle par défault qui englobe certains ce type d\'utilisateurs')
                        return anonymous_permissions        
        
        except LDAPSocketOpenError as e:
            print("Port {0} closed. Abording...".format(self.port))
            sys.exit(-1)

        except Exception as e:
            # Handle the exception as needed
            print(f"Error checking anonymous ACL: {e}")
        finally:
            self._disconnect()

    def check_all_acls(self):
        try:
            self._connect()
            self.connection.search(search_base='olcDatabase={1}mdb,cn=config', search_filter='(objectClass=*)', search_scope='BASE', attributes=['olcAccess'])
            if not len(self.connection.entries) == 0:
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
                        self.report.add_vulnerability('1','vuln_dangerous_acls','Permissions dangereuses sur le serveur','Des Contrôles d’accès sont inéxistants sur le serveur LDAP, ou ne protègent pas suffisament les attributs critiques des entrées utilisateurs comme userPassword, uid.','Accorder des privilèges de lecture exclusivement aux propriétaires et octroyer les droits d\'écriture au compte administrateur.')
                        #print("Dangerous permissions found:")
                        for entry in dangerous_permissions:
                            var = 'ok'
                            #print(f"Target Attribute: {entry['target_attribute']}, Entity: {entry['entity']}, Permission Type: {entry['permission_type']}")
                    else:
                        var = 'ok'
                        #print("No dangerous permissions found.")

        except LDAPSocketOpenError as e:
            print("Port {0} closed. Abording...".format(self.port))
            sys.exit(-1)

        except Exception as e:
            print(f"Error checking ACLs: {e}")
        finally:
            self._disconnect()

    def check_default_acl_rule(self):
        try:
            self._connect()
            self.connection.search(search_base='olcDatabase={1}mdb,cn=config', search_filter='(objectClass=*)', search_scope='BASE', attributes=['olcAccess'])
            if not len(self.connection.entries) == 0:
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
        
        except LDAPSocketOpenError as e:
            print("Port {0} closed. Abording...".format(self.port))
            sys.exit(-1)

        except Exception as e:
            print(f"Error checking ACLs: {e}")
        finally:
            self._disconnect()

    def check_password_write_permission(self):
        users_to_check = self.critical_ous
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
                            self.report.add_vulnerability('1','vuln_userpassword_write_perm','Permissions en écriture sur un attribut userPassword','Les autorisations d\'ecriture sur l\'attribut userPassword representent un risque significatif pour la securite du systeme. Cela signifie que des entites non autorisees pourraient potentiellement modifier les mots de passe des utilisateurs, compromettant ainsi la confidentialite des informations sensibles.','Examiner et mettre a jour les controles d\'acces (ACL) pour l\'attribut userPassword')
                            # Additional checks or actions based on the 'to' attribute if needed

        except LDAPSocketOpenError as e:
            print("Port {0} closed. Abording...".format(self.port))
            sys.exit(-1)

        except Exception as e:
            # Handle the exception as needed
            print(f"Error checking anonymous ACL: {e}")
        finally:
            self._disconnect()

    def check_ppolicy(self):
        try:
            # Search for ppolicy configuration
            self._connect()
            
            self.connection.search(
                search_base=self.get_config_context(),
                search_filter='(objectClass=olcPpolicyConfig)',
                search_scope=SUBTREE,
                attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]
            )
            if not self.connection.entries:
                self.report.add_vulnerability('1','vuln_missing_ppolicy','Absence de politique de mots de passe','En l’absence d’une politique de mot de passe, les utilisateurs peuvent être libres de choisir des mots de passe faibles, faciles à deviner, ou de ne pas suivre de bonnes pratiques de sécurité. Une politique de mot de passe efficace est cruciale pour renforcer la sécurité des systèmes, car les mots de passe sont souvent la première ligne de défense contre l’accès non autorisé.','Activer et configurer le module ppolicy')
        except LDAPSocketOpenError as e:
            print("Port {0} closed. Abording...".format(self.port))
            sys.exit(-1)

        except LDAPObjectClassError as e:
            self.report.add_vulnerability('1','vuln_missing_ppolicy','Absence de politique de mots de passe','En l’absence d’une politique de mot de passe, les utilisateurs peuvent être libres de choisir des mots de passe faibles, faciles à deviner, ou de ne pas suivre de bonnes pratiques de sécurité. Une politique de mot de passe efficace est cruciale pour renforcer la sécurité des systèmes, car les mots de passe sont souvent la première ligne de défense contre l’accès non autorisé.','Activer et configurer le module ppolicy')
        
        except Exception as e:
            self.report.add_vulnerability('1','vuln_missing_ppolicy','Absence de politique de mots de passe','En l’absence d’une politique de mot de passe, les utilisateurs peuvent être libres de choisir des mots de passe faibles, faciles à deviner, ou de ne pas suivre de bonnes pratiques de sécurité. Une politique de mot de passe efficace est cruciale pour renforcer la sécurité des systèmes, car les mots de passe sont souvent la première ligne de défense contre l’accès non autorisé.','Activer et configurer le module ppolicy')
        finally:
            self._disconnect()

    def check_user_password_encryption(self):
        try:
            # Configure TLS if LDAPS is used
            tls_configuration = None
            # Create a server object
            self.server = Server(f"{self.server_uri}:{self.port}", get_info=ALL, use_ssl=self.use_ldaps, tls=tls_configuration)

            
            # Create a connection object
            self.connection = Connection(self.server, user="cn=admin,dc=example,dc=com", password='secret', auto_bind=True)
            search_filter = '(objectClass=inetOrgPerson)'
            self.connection.search(
                search_base='dc=example,dc=com',
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['userPassword']
            )
            if self.connection.entries:
                for attribute in self.connection.entries:
                    user_password = attribute.userPassword.value.decode('utf-8')
                    if not re.match(r'{[^}]+}', user_password):
                        self.report.add_vulnerability('1','vuln_no_password_encryption','Mot de passe stocké en clair','Au moins un mots de passe utilisateurs est stocké sans chiffrement ni hachage, ce qui expose les données sensibles à un risque élevé en cas de violation de la sécurité.','Utilisation d\'un algorithme de hashage pour stocker les mots de passe')
                        break
        
        except LDAPSocketOpenError as e:
            print("Port {0} closed. Abording...".format(self.port))
            sys.exit(-1)

        except Exception as e:
            print(f"Error checking ACLs: {e}")
        finally:
            self._disconnect()

    def _read_config(self):
        try:
            with open(self.config_path) as f:
                data = yaml.safe_load(f)
                self.server_uri = data['ldap']['server_uri']
                self.port = data['ldap']['port']
                self.admin_user = data['ldap']['admin_user']   
                self.admin_password = data['ldap']['admin_password'] 
                self.use_starttls = data['ldap']['use_starttls'] 
                for critical_ou in data['ldap']['critical_ous']:
                    self.critical_ous.append(critical_ou)
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
        #self.check_default_acl_rule()
        #self.check_anonymous_acl()
        #self.check_password_write_permission()
        #self.check_ppolicy()
        #self.check_user_password_encryption()
        
        # Report Generation
        self.report.generate_report()
        end_time = time.time()
        execution_time = round(end_time - start_time,2)
        print(f"Program execution time: {execution_time} seconds")

    def __del__(self):
        # Close the LDAP connection when the object is destroyed
        if self.connection:
            self.connection.unbind()
    