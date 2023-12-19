import re
import json

class OpenLDAPACLParser:
    """
     --------------
    |BEFORE PARSING|
     --------------
    olcAccess: {0}to attrs=userPassword by self write by anonymous auth by * none
               {1}to attrs=shadowLastChange by self write by * read
               {2}to * by anonymous read
     -------------
    |AFTER PARSING|
     -------------
    [
        {
            "to": "attrs=userPassword",
            "by": [
                {"entity": "self", "permission": "write"},
                {"entity": "*", "permission": "none"}
            ]
        },
        {
            "to": "attrs=shadowLastChange",
            "by": [
                {"entity": "self", "permission": "write"},
                {"entity": "*", "permission": "read"}
            ]
        },
        {
            "to": "*",
            "by": [
                {"entity": "anonymous", "permission": "read"}
            ]
        }
    ]
    """

    def __init__(self, acl_string):
        self.acl_string = acl_string
        self.acls = self.parse_acls()

    def get_acls(self):
        return self.acls

    def get_acl_string(self):
        return self.acl_string
    
    """
    Parse the ACL table 
    """
    def parse_acls(self):
        acl_list = []
        self.acl_string = ' '.join(line.strip() for line in self.acl_string.split('\n'))
        acl_pattern = re.compile(r'(?<=olcAccess:\s)(.+?)(?=\s*olcAccess:|$)', re.DOTALL)
        acl_matches = re.finditer(acl_pattern, self.acl_string)
        for acl_match in acl_matches:
            acl_text = acl_match.group(1).strip()
            acl_text = result_string = re.sub(r'^\s+', '', acl_text, flags=re.MULTILINE)
            access_list = list(filter(None,re.split(r'\{\d+\}', acl_text)))
            for acl in access_list:
                acl = acl.strip()
                acl_list.append(self.parse_acl(acl))
        return acl_list
    
    """
    Parse a single ACL entry 
    """
    def parse_acl(self, acl_text):
        acl = {'to': None, 'by': []}
        to_clause = acl_text.split('to')[1].strip().split("by")[0].strip()
        if(to_clause[0:2] == 'dn'):
            acl['to'] = to_clause[4:-1]
        else:
            acl['to'] = to_clause
        by_pattern = re.compile(r'by\s+([^\s]+)\s+(\w+)(?=\s+by|$)', re.IGNORECASE)
        for match in by_pattern.finditer(acl_text):
            acl['by'].append({'entity': match.group(1), 'permission': match.group(2)})
        return acl

    def display(self):
        for acl in self.acls:
            print(f" + {acl['to']}")
            for by_clause in acl['by']:
                print(f"    - {by_clause['entity']} has '{by_clause['permission']}' permission")