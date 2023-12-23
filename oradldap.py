import configparser
import yaml
import time
import ssl
import sys
from parser import OpenLDAPACLParser
from report import VulnerabilityReport
from ldap3 import *
from ldap3.core.exceptions import *
import re
import logging

class ORADLDAP:
    
    def __init__(self, config_path='conf.yaml'):
        print('Init...')
        # Declarations
        self.config = configparser.ConfigParser()
        self.config_path = config_path
        self.naming_context = None
        self.server_uri = None
        
        self.simple_user = None
        self.simple_password = None
        self.critical_ous = []
        self.anonymous_connection = None
        self.simple_connection = None 
        self.admin_connection = None
        
        # Reading config file
        self._read_config()
        
        # Server
        self.server = Server(self.server_uri, port=self.port, get_info=ALL)
        
        # Connections
        self._connect()

        self.report = VulnerabilityReport()
    
    def _connect(self):
        # Anonymous
        try:
            self.anonymous_connection = Connection(self.server,auto_bind=True)
            if self.use_starttls:
                self.anonymous_connection.start_tls()
            print("Anonymous connection") 
            
        except Exception as e:
            print(f"An unexpected error occurred during anonymous connection: {e}")
        
        # Simple user
        try:
            self.simple_connection = Connection(self.server,user=self.simple_user,password=self.simple_password, auto_bind=True)
            if self.use_starttls:
                self.simple_connection.start_tls()
            print("Simple connection") 
        except Exception as e:
            print(f"An unexpected error occurred during simple user connection: {e}")

        # Admin user
        try:
            self.simple_connection = Connection(self.server,user=self.admin_user,password=self.admin_password, auto_bind=True)
            if self.use_starttls:
                self.admin_connection.start_tls()
            print("Admin connection") 
        except Exception as e:
            print(f"An unexpected error occurred during admin user connection: {e}")

    def _disconnect(self):
        if self.anonymous_connection:
            self.anonymous_connection.unbind()
        if self.simple_connection:
            self.simple_connection.unbind()
        if self.admin_connection:
            self.admin_connection.unbind()
    
    def _get_connection_by_strategy(self, strategy):
        if strategy == "ANONYMOUS":
            return self.anonymous_connection
        elif strategy == "SIMPLE":
            return self.simple_connection
        elif strategy == "ADMIN":
            return self.admin_connection
        else:
            raise ValueError(f"Invalid strategy: {strategy}")
            
    def get_config_context(self):
        if self.server:
            self.config_context = str(self.server.info).split("configContext:")[1].lstrip().split("\n")[0]
        return self.config_context

    def get_naming_context(self, strategy="ANONYMOUS"):
        
        connection = self._get_connection_by_strategy(strategy)
        if connection:
            print(f"{strategy} - Getting naming context")
            try:
                connection.search(search_base='', search_filter='(objectclass=*)', attributes=['namingContexts'], search_scope=BASE)
                self.naming_context = str(connection.entries[0]).split("namingContexts:")[1].strip()
                if strategy == "ANONYMOUS" and self.naming_context:
                    self.report.add_vulnerability('warning_naming_context')
            except LDAPSocketOpenError as e:
                print("Socket is not opened. Aborting...")
            except Exception as e:
                raise ValueError(f"Error retrieving naming context: {e}")
            return self.naming_context

    def get_subentries(self,strategy="ANONYMOUS"):
        print(f"{strategy} - Getting naming context")
        if strategy == "ANONYMOUS":
            var = ''
        elif strategy == "SIMPLE":
            var = ''
        elif strategy == "ADMIN":
            var = ''
        else:
            raise ValueError(f"Invalid strategy: {strategy}")

    def _get_subentries_anonymous(self):
        if self.anonymous_connection:
            try:
                # Search for subentries in the Root DSE
                result = connection.search(base=self.naming_context, scope=ldap.SCOPE_SUBTREE, filterstr="(objectClass=*)", attrlist=["subschemaSubentry"])
                
                # Extract subentries from the result
                subentries = [entry[1]["subschemaSubentry"][0].decode('utf-8') for entry in result if "subschemaSubentry" in entry[1]]
                return subentries
            except Exception as e:
                raise ValueError(f"Error retrieving naming context: {e}")
        else:
            return
    
    def check_anonymous_auth(self):
        print("ANONYMOUS - Check anonymous auths")
        if self.anonymous_connection:
            self.report.add_vulnerability('vuln_allow_anon_auth')
            return True
        else:
            return False
       
    def check_anonymous_acl(self):
        try:
            self._connect_anonymously()
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
                            self.report.add_vulnerability('vuln_anonymous_dangerous_perms')
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
            self.connect_authenticated()
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
                        self.report.add_vulnerability('vuln_dangerous_acls')
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
            self.connect_authenticated()
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
                        self.report.add_vulnerability('vuln_dangerous_default_acl')
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
            self.connect_authenticated()
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
                            self.report.add_vulnerability('vuln_userpassword_write_perm')
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
            self.connect_authenticated()
            
            self.connection.search(
                search_base=self.get_config_context(),
                search_filter='(objectClass=olcPpolicyConfig)',
                search_scope=SUBTREE,
                attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]
            )
            if not self.connection.entries:
                self.report.add_vulnerability('vuln_missing_ppolicy')
        except LDAPSocketOpenError as e:
            print("Port {0} closed. Abording...".format(self.port))
            sys.exit(-1)

        except LDAPObjectClassError as e:
            self.report.add_vulnerability('vuln_missing_ppolicy')
        
        except Exception as e:
            self.report.add_vulnerability('vuln_missing_ppolicy')
        finally:
            self._disconnect()

    def check_user_password_encryption(self):
        try:
            # Configure TLS if LDAPS is used
            tls_configuration = None
            
            # Create a connection object
            self.connect_authenticated()
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
                        self.report.add_vulnerability('vuln_no_password_encryption')
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
                self.simple_user = data['ldap']['simple_user']   
                self.simple_password = data['ldap']['simple_password'] 
                self.admin_user = data['ldap']['admin_user']   
                self.admin_password = data['ldap']['admin_password'] 
                self.use_starttls = data['ldap']['use_starttls'] 
                for critical_ou in data['ldap']['critical_ous']:
                    self.critical_ous.append(critical_ou)
                print('Reading conf..')

                if self.simple_password == None:
                    self.simple_password = input("Mot de passe utilisateur simple: ")
                if self.admin_password == None:
                    self.admin_password = input("Mot de passe utilisateur administrateur: ")

        except (configparser.Error, ValueError) as e:
            raise ValueError(f"Error reading configuration: {e}")

    def Run(self):
        start_time = time.time()

        # Security Checks
        
        #self.get_config_context()
        
        # ANONYMOUS
        self.get_naming_context(strategy="ANONYMOUS")
        self.check_anonymous_auth()
        #self.check_all_acls()
        #self.check_default_acl_rule()
        #self.check_anonymous_acl()
        #self.check_password_write_permission()
        #self.check_ppolicy()
        #self.check_user_password_encryption()
        
        # SIMPLE USER
        self.get_naming_context(strategy="SIMPLE")
        
        # ADMIN USER
        self.get_naming_context(strategy="ADMIN")
        
        # Close connections
        self._disconnect()

        # Report Generation
        self.report.generate_report()
        end_time = time.time()
        execution_time = round(end_time - start_time,2)
        print(f"Program execution time: {execution_time} seconds")

    def __del__(self):
        # Close the LDAP connection when the object is destroyed
        if self.anonymous_connection:
            self.anonymous_connection.unbind()
        if self.simple_connection:
            self.simple_connection.unbind()
        if self.admin_connection:
            self.admin_connection.unbind()

        self.server = None
        self.anonymous_connection = None
        self.simple_connection = None
        self.admin_connection = None