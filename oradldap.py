import configparser
import json
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
        self.critical_groups = []
        
        self.anonymous_connection = None
        self.simple_connection = None 
        self.admin_connection = None
        
        self.strategy = None
        
        # Reading config file
        self._read_config()
        
        # Server
        self.server = Server(self.server_uri, port=self.port, get_info=ALL) 
        
        # Connections
        self._connect()
        self.report = VulnerabilityReport(strategy=self.strategy)

    def _connect(self):
        # Anonymous
        try:
            self.anonymous_connection = Connection(self.server,auto_bind=True)
            self.strategy = "ANONYMOUS"
            if self.use_starttls:
                self.anonymous_connection.start_tls()
            print("Anonymous connection") 
            
        except Exception as e:
            print(f"An unexpected error occurred during anonymous connection: {e}")
        
        # Authenticated user
        try:
            self.simple_connection = Connection(self.server,user=self.simple_user,password=self.simple_password, auto_bind=True)
            self.strategy = "AUTHENTICATED"
            if self.use_starttls:
                self.simple_connection.start_tls()
            print("Simple connection") 
        except Exception as e:
            print(f"An unexpected error occurred during simple user connection: {e}")

        # Admin user
        try:
            self.admin_connection = Connection(self.server,user=self.admin_user,password=self.admin_password, auto_bind=True)
            self.strategy = "ADMIN"
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
        elif strategy == "AUTHENTICATED":
            return self.simple_connection
        elif strategy == "ADMIN":
            return self.admin_connection
        else:
            raise ValueError(f"Invalid strategy: {strategy}")
            
    def _get_parent_dn(self,dn):
        # If the DN has only one component, it means it's at the base level and has no parent
        if dn == self.naming_context:
            return None

        # Split the DN into its components
        dn_components = dn.split(',')

        # Construct the parent DN by excluding the first component
        parent_dn = ','.join(dn_components[1:])
        
        return parent_dn

    def _get_group_members(self, group_dn, strategy="ANONYMOUS"):
        # Connect to the LDAP server
        connection = self._get_connection_by_strategy(strategy)
        # Search for groups and their members
        if not connection:
            logging.warning('Invalid connection')
            return 
        connection.search(group_dn, "(objectClass=*)", SUBTREE, attributes=ALL_ATTRIBUTES)
        entries = connection.entries
        return entries[0].member

    def _check_membership(self, user_dn, strategy="ANONYMOUS"):
        membership = []
        # Connect to the LDAP server
        connection = self._get_connection_by_strategy(strategy)
        # Search for groups and their members
        if not connection:
            logging.warning('Invalid connection')
            return 
        connection.search(self.naming_context, "(member={0})".format(user_dn), SUBTREE, attributes=ALL_ATTRIBUTES)
        entries = connection.entries
        for entry in entries:
            membership.append(entry.entry_dn)
        if len(membership) > 0:
            return membership
        else:
            return None
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
                self.report.suffix = self.naming_context
                if strategy == "ANONYMOUS" and self.naming_context:
                    self.report.add_vulnerability('warning_naming_context')
            except LDAPSocketOpenError as e:
                print("Socket is not opened. Aborting...")
            except Exception as e:
                raise ValueError(f"Error retrieving naming context: {e}")
            return self.naming_context
    
    def check_anonymous_auth(self):
        print("ANONYMOUS - Check anonymous auths")
        if self.anonymous_connection:
            self.report.add_vulnerability('vuln_allow_anon_auth')
            return True
        else:
            return False
       
    def check_anonymous_acl(self,strategy="ANONYMOUS"):
        connection = self._get_connection_by_strategy(strategy)
        if connection:
            print(f"{strategy} - Checking anonymous ACLs")
            try:
                connection.search(search_base='olcDatabase={1}mdb,cn=config', search_filter='(objectClass=*)', search_scope='BASE', attributes=['olcAccess'])
                if not len(connection.entries) == 0:
                    print(connection.entries)
                    acls = str(connection.entries[0]).split("olcAccess:")[1].split("\n")
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

            except Exception as e:
                # Handle the exception as needed
                logging.error(f"Error checking anonymous ACL: {e}")

    def check_all_acls(self,strategy="ANONYMOUS"):
        connection = self._get_connection_by_strategy(strategy)
        if connection:
            print(f"{strategy} - Checking all ACLs")
            try:
                connection.search(search_base='olcDatabase={1}mdb,cn=config', search_filter='(objectClass=*)', search_scope='BASE', attributes=['olcAccess'])
                if not len(connection.entries) == 0:
                    print(connection.entries)
                    acls_entry = str(connection.entries[0])
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

            except Exception as e:
                logging.error(f"Error checking ACLs: {e}")

    def check_default_acl_rule(self,strategy="ANONYMOUS"):
        connection = self._get_connection_by_strategy(strategy)
        if connection:
            print(f"{strategy} - Check default ACL rule")
            try:
                connection.search(search_base='olcDatabase={1}mdb,cn=config', search_filter='(objectClass=*)', search_scope='BASE', attributes=['olcAccess'])
                if not len(connection.entries) == 0:
                    acls_entry = str(connection.entries[0])
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
            except Exception as e:
                logging.warning("Error checking ACLs: {e}")

    def check_password_write_permission(self,strategy="ANONYMOUS"):
        users_with_write_permissions = []

        connection = self._get_connection_by_strategy(strategy)
        if connection:
            print(f"{strategy} - Check password write permision")
            try:
                connection.search(search_base='olcDatabase={1}mdb,cn=config', search_filter='(objectClass=*)', search_scope='BASE', attributes=['olcAccess'])
                if connection.entries:
                    acls_entry = str(connection.entries[0])
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

    def check_ppolicy(self,strategy="ANONYMOUS"):
        connection = self._get_connection_by_strategy(strategy)
        if connection:
            print(f"{strategy} - Check ppolicy")
            try:
                connection.search(
                    search_base=self.get_config_context(),
                    search_filter='(objectClass=olcPpolicyConfig)',
                    search_scope=SUBTREE,
                    attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]
                )
                if not connection.entries:
                    self.report.add_vulnerability('vuln_missing_ppolicy')
            except LDAPObjectClassError as e:
                self.report.add_vulnerability('vuln_missing_ppolicy')
            
            except Exception as e:
                logging.warning(e)

    def check_user_password_encryption(self,strategy="ANONYMOUS"):
        connection = self._get_connection_by_strategy(strategy)
        if connection:
            print(f"{strategy} - Checking password encryption")
            try:
                search_filter = '(objectClass=inetOrgPerson)'
                connection.search(
                    search_base=self.naming_context,
                    search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=['userPassword']
                )
                if connection.entries:
                    for attribute in connection.entries:
                        attribute = json.loads(attribute.entry_to_json())
                        user_password = attribute['attributes']['userPassword']
                        if len(user_password) == 0:
                            return
                        if not re.match(r'{[^}]+}', user_password[0]):           
                            self.report.add_vulnerability('vuln_no_password_encryption')


            except Exception as e:
                print(f"Error checking password encryption: {e}")

    def data_collector(self, strategy="ANONYMOUS"):
        # Connect to the LDAP server
        connection = self._get_connection_by_strategy(strategy)
        # Search for groups and their members
        if not connection:
            logging.warning('Invalid connection')
            return [], []

        connection.search(self.naming_context, "(objectClass=*)", SUBTREE, attributes=ALL_ATTRIBUTES)
        entries = connection.entries
        
        nodes = []
        edges = []

        # Predefined styles for entry types
        style_mapping = {
            'organization': {'shape': 'square', 'color': '#FF5733', 'size': 30},
            'organizationalUnit':{'shape': 'diamond', 'color': '#5733FF', 'size': 25},
            'organizationalPerson': {'shape': 'ellipse', 'color': '#33FF57', 'size': 15},
            'groupOfNames': {'shape': 'box', 'color': {'border': '#2B7CE9', 'background': '#97C2FC', 'size': 15}}
            # Add more entry types and styles as needed
        }

        for entry in entries:
            dn = entry.entry_dn
            objectClass = entry.objectClass
            parent_dn = None
            #Organization    
            if "organization" in objectClass:
                label = entry.o.value
                style = style_mapping.get('organization', {})
            # OU
            elif "organizationalUnit" in objectClass:
                label = entry.ou.value
                style = style_mapping.get('organizationalUnit', {})
                parent_dn = self._get_parent_dn(dn)
            # User
            elif any(entry_class in ["person", "inetOrgPerson", "organizationalPerson"] for entry_class in objectClass):
                label = entry.cn.value[-1] if isinstance(entry.cn.value, list) else entry.cn.value
                style = style_mapping.get('organizationalPerson', {})
                membership = self._check_membership(dn)
                if membership:
                    parent_dn = membership[0]
                else:
                    parent_dn = self._get_parent_dn(dn)
            # Group
            elif any(entry_class in ["posixGroup","groupOfNames", "groupOfUniqueNames"] for entry_class in objectClass):
                label = entry.cn.value[-1] if isinstance(entry.cn.value, list) else entry.cn.value
                style = style_mapping.get('groupOfNames', {})
                membership = self._check_membership(dn)
                if membership:
                    parent_dn = membership[0]
                else:
                    parent_dn = self._get_parent_dn(dn)
            else:
                logging.warning(f"Unknown entry type: {objectClass}")
                continue

            # Add the current entry as a node
            nodes.append({"id": dn, "label": label,**style})
            
            # Check if the entry has a parent DN
            if parent_dn:
                # Add an edge from the current entry to its parent
                edges.append({"from": dn, "to": parent_dn, "label": "memberOf"})
        # Write the data to a JSON file
        data = {'nodes': nodes, 'edges': edges}
        with open('render/ldap_data.json', 'w') as json_file:
            json.dump(data, json_file)
        return nodes, edges
    
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
                for critical_group in data['ldap']['critical_groups']:
                    self.critical_groups.append(critical_group)
                print('Reading conf..')

                if self.simple_password == None:
                    self.simple_password = input("Mot de passe utilisateur simple: ")
                if self.admin_password == None:
                    self.admin_password = input("Mot de passe utilisateur administrateur: ")

        except (configparser.Error, ValueError) as e:
            raise ValueError(f"Error reading configuration: {e}")

    def Run(self):
        start_time = time.time()
        
        # ANONYMOUS
        self.check_anonymous_auth()
        self.get_naming_context(strategy="ANONYMOUS")
        self.check_user_password_encryption(strategy="ANONYMOUS")
        self.check_password_write_permission(strategy="ANONYMOUS")

        # AUTHENTICATED USER
        self.get_naming_context(strategy="AUTHENTICATED")
        self.check_user_password_encryption(strategy="AUTHENTICATED")
        self.check_password_write_permission(strategy="AUTHENTICATED")
        
        # ADMIN USER
        self.get_naming_context(strategy="ADMIN")
        self.check_user_password_encryption(strategy="ADMIN")
        self.check_ppolicy(strategy="ADMIN")
        self.check_all_acls(strategy="ADMIN")
        self.check_default_acl_rule(strategy="ADMIN")
        self.check_anonymous_acl(strategy="ADMIN")
        self.check_password_write_permission(strategy="ADMIN")
        self.data_collector(strategy="ADMIN")

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