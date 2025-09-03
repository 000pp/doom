from ldap3 import SUBTREE
from doom.protocols.ldap import safe_ldap_attr
from doom.parsers.attribute import parse_attribute

def enumerate_templates(ldap_connection, base_dn):
    search_filter = "(objectClass=pKICertificateTemplate)"
    attributes = ["*"]
    
    templates_base_dn = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{base_dn}"
    
    try:
        results = ldap_connection.search(
            search_base=templates_base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attributes,
        )
        
        if not results:
            return []
        
        entries = ldap_connection.entries
        if not entries:
            return []
        
        all_templates = []
        
        for entry in entries:
            template_name = safe_ldap_attr(entry, 'cn', 'Unknown Template')
            display_name = safe_ldap_attr(entry, 'displayName', template_name)
            
            raw_attributes = {}
            parsed_attributes = {}
            for attr in entry.entry_attributes:
                attr_value = safe_ldap_attr(entry, attr, 'N/A')
                raw_attributes[attr] = attr_value
                parsed_attributes[attr] = parse_attribute(attr, attr_value)
            
            template_properties = analyze_template_properties(raw_attributes)
            
            combined_attributes = {**parsed_attributes, **template_properties}

            all_templates.append({
                'name': template_name,
                'display_name': display_name,
                'dn': safe_ldap_attr(entry, 'distinguishedName', 'N/A'),
                'attributes': combined_attributes,
                'entry': entry
            })
        
        return all_templates
        
    except Exception as enumerate_templates_error:
        raise Exception(f"Failed to enumerate templates: {enumerate_templates_error}")

def analyze_template_properties(raw_attributes):
    properties = {}
    
    try:
        enrollment_flag = raw_attributes.get('msPKI-Enrollment-Flag', 0)
        certificate_name_flag = raw_attributes.get('msPKI-Certificate-Name-Flag', 0)
        private_key_flag = raw_attributes.get('msPKI-Private-Key-Flag', 0)
        template_flags = raw_attributes.get('flags', 0)
        
        enrollment_flag = enrollment_flag if isinstance(enrollment_flag, int) else 0
        certificate_name_flag = certificate_name_flag if isinstance(certificate_name_flag, int) else 0
        private_key_flag = private_key_flag if isinstance(private_key_flag, int) else 0
        template_flags = template_flags if isinstance(template_flags, int) else 0
        
        properties["Requires_Manager_Approval"] = bool(enrollment_flag & 0x00000002)
        properties["Auto_Enrollment"] = bool(enrollment_flag & 0x00000020)
        properties["User_Interaction_Required"] = bool(enrollment_flag & 0x00000100)
        properties["Publish_To_DS"] = bool(enrollment_flag & 0x00000008)
        properties["Domain_Auth_Not_Required"] = bool(enrollment_flag & 0x00000080)
        properties["Allow_Enroll_On_Behalf_Of"] = bool(enrollment_flag & 0x00000800)
        properties["Include_Symmetric_Algorithms"] = bool(enrollment_flag & 0x00000001)
        
        properties["Enrollee_Supplies_Subject"] = bool(certificate_name_flag & 0x00000001)
        properties["Enrollee_Supplies_Subject_Alt_Name"] = bool(certificate_name_flag & 0x00010000)
        properties["Add_Email"] = bool(certificate_name_flag & 0x00000002)
        
        properties["Exportable_Key"] = bool(private_key_flag & 0x00000010)
        properties["Require_Private_Key_Archival"] = bool(private_key_flag & 0x00000001)
        properties["Strong_Key_Protection_Required"] = bool(private_key_flag & 0x00000020)
        
        properties["Machine_Type"] = bool(template_flags & 0x00000040)
        properties["Is_CA"] = bool(template_flags & 0x00000080)
        properties["Add_Template_Name"] = bool(template_flags & 0x00000200)
        
    except Exception as e:
        properties["Analysis_Error"] = f"Analysis failed: {e}"
    
    return properties