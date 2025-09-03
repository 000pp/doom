from ldap3 import SUBTREE

from doom.protocols.ldap import safe_ldap_attr
from doom.parsers.filetime import parse_filetime

try:
    from certipy.lib.constants import (
        TemplateFlags, EnrollmentFlag, CertificateNameFlag, PrivateKeyFlag, OID_TO_STR_MAP
    )
    CERTIPY_AVAILABLE = True
except ImportError:
    CERTIPY_AVAILABLE = False

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
            for attr in entry.entry_attributes:
                attr_value = safe_ldap_attr(entry, attr, 'N/A')
                raw_attributes[attr] = attr_value
            
            template_properties = {}
            if CERTIPY_AVAILABLE:
                template_properties = analyze_template_properties(raw_attributes, entry)
            
            parsed_attributes = {}
            for attr in entry.entry_attributes:
                attr_value = safe_ldap_attr(entry, attr, 'N/A')
                if CERTIPY_AVAILABLE:
                    parsed_value = parse_attribute(attr, attr_value)
                    parsed_attributes[attr] = parsed_value
                else:
                    parsed_attributes[attr] = attr_value
            
            combined_attributes = {**parsed_attributes, **template_properties}

            all_templates.append({
                'name': template_name,
                'display_name': display_name,
                'dn': safe_ldap_attr(entry, 'distinguishedName', 'N/A'),
                'attributes': combined_attributes,
                'entry': entry
            })
        
        return all_templates
        
    except Exception as e:
        raise Exception(f"Failed to enumerate templates: {e}")

def parse_attribute(attr_name, attr_value):
    if not CERTIPY_AVAILABLE:
        return attr_value
    
    try:
        if attr_name == 'flags' and isinstance(attr_value, int):
            flag_meanings = []
            for flag in TemplateFlags:
                if attr_value & flag.value:
                    flag_meanings.append(flag.name)
            return f"{attr_value} ({', '.join(flag_meanings) if flag_meanings else 'None'})"
        
        elif attr_name == 'msPKI-Enrollment-Flag' and isinstance(attr_value, int):
            enrollment_flags = []
            for flag in EnrollmentFlag:
                if attr_value & flag.value:
                    enrollment_flags.append(flag.name)
            return f"{attr_value} ({', '.join(enrollment_flags) if enrollment_flags else 'None'})"
        
        elif attr_name == 'msPKI-Certificate-Name-Flag' and isinstance(attr_value, int):
            name_flags = []
            for flag in CertificateNameFlag:
                if attr_value & flag.value:
                    name_flags.append(flag.name)
            return f"{attr_value} ({', '.join(name_flags) if name_flags else 'None'})"
            
        elif attr_name == 'msPKI-Private-Key-Flag' and isinstance(attr_value, int):
            private_key_flags = []
            for flag in PrivateKeyFlag:
                if attr_value & flag.value:
                    private_key_flags.append(flag.name)
            return f"{attr_value} ({', '.join(private_key_flags) if private_key_flags else 'None'})"
        
        elif attr_name == 'pKIExtendedKeyUsage' and isinstance(attr_value, list):
            parsed_usage = []
            for oid in attr_value:
                oid_str = str(oid)
                if oid_str in OID_TO_STR_MAP:
                    parsed_usage.append(f"{oid_str} ({OID_TO_STR_MAP[oid_str]})")
                else:
                    parsed_usage.append(oid_str)
            return parsed_usage
        
        elif attr_name == 'instanceType' and isinstance(attr_value, int):
            instance_types = {
                1: "IT_WRITE", 
                2: "IT_NC_HEAD",
                4: "IT_NC_REPLICA",
                8: "IT_NC_COMING",
                16: "IT_NC_GOING"
            }
            types = []
            for bit_val, type_name in instance_types.items():
                if attr_value & bit_val:
                    types.append(type_name)
            return f"{attr_value} ({', '.join(types) if types else 'None'})"
        
        elif attr_name == 'pKIDefaultKeySpec' and isinstance(attr_value, int):
            key_spec_map = {
                1: "AT_KEYEXCHANGE (RSA key exchange)",
                2: "AT_SIGNATURE (RSA signature)", 
                3: "AT_KEYEXCHANGE | AT_SIGNATURE"
            }
            spec_name = key_spec_map.get(attr_value, "Unknown")
            return f"{attr_value} ({spec_name})"
        
        elif attr_name == 'pKIMaxIssuingDepth' and isinstance(attr_value, int):
            if attr_value == 0:
                return f"{attr_value} (End Entity Certificate)"
            elif attr_value == -1:
                return f"{attr_value} (Unlimited - Root CA)"
            else:
                return f"{attr_value} (Intermediate CA - {attr_value} levels deep)"
        
        elif attr_name == 'pKIKeyUsage' and isinstance(attr_value, bytes):
            try:
                if len(attr_value) >= 1:
                    usage_byte = attr_value[0]
                    usages = []
                    key_usage_map = {
                        0x80: "Digital Signature",
                        0x40: "Non Repudiation", 
                        0x20: "Key Encipherment",
                        0x10: "Data Encipherment",
                        0x08: "Key Agreement",
                        0x04: "Key Cert Sign",
                        0x02: "CRL Sign",
                        0x01: "Encipher Only"
                    }
                    for bit, usage in key_usage_map.items():
                        if usage_byte & bit:
                            usages.append(usage)
                    return f"{usage_byte:02x} ({', '.join(usages) if usages else 'None'})"
            except:
                pass
            return f"Binary: {attr_value.hex()}"
        
        elif attr_name in ['pKIExpirationPeriod', 'pKIOverlapPeriod'] and isinstance(attr_value, bytes):
            return parse_filetime(attr_value)
        
        elif attr_name == 'msPKI-Minimal-Key-Size' and isinstance(attr_value, int):
            return f"{attr_value} bits"
        
        elif attr_name == 'msPKI-Template-Schema-Version':
            return f"Schema Version: {attr_value}"
        
        elif attr_name == 'msPKI-Template-Minor-Revision':
            return f"Minor Revision: {attr_value}"
        
        elif attr_name == 'revision' and isinstance(attr_value, int):
            return f"Template Revision: {attr_value}"
        
        elif attr_name in ['uSNChanged', 'uSNCreated'] and isinstance(attr_value, int):
            return f"USN: {attr_value}"
        
        return attr_value
        
    except Exception:
        return attr_value

def analyze_template_properties(raw_attributes, entry):
    """Analyze template properties using raw numeric values"""

    if not CERTIPY_AVAILABLE:
        return {}
    
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
        
        # Source: https://raw.githubusercontent.com/ly4k/Certipy/refs/heads/main/certipy/lib/constants.py
        properties["Security_Analysis_Requires_Manager_Approval"] = bool(enrollment_flag & 0x00000002)
        properties["Security_Analysis_Auto_Enrollment"] = bool(enrollment_flag & 0x00000020)
        properties["Security_Analysis_User_Interaction_Required"] = bool(enrollment_flag & 0x00000100)
        properties["Security_Analysis_Publish_To_DS"] = bool(enrollment_flag & 0x00000008)
        properties["Security_Analysis_Domain_Auth_Not_Required"] = bool(enrollment_flag & 0x00000080)
        properties["Security_Analysis_Allow_Enroll_On_Behalf_Of"] = bool(enrollment_flag & 0x00000800)
        properties["Security_Analysis_Include_Symmetric_Algorithms"] = bool(enrollment_flag & 0x00000001)
        
        properties["Security_Analysis_Enrollee_Supplies_Subject"] = bool(certificate_name_flag & 0x00000001)
        properties["Security_Analysis_Enrollee_Supplies_Subject_Alt_Name"] = bool(certificate_name_flag & 0x00010000)
        properties["Security_Analysis_Add_Email"] = bool(certificate_name_flag & 0x00000002)
        
        properties["Security_Analysis_Exportable_Key"] = bool(private_key_flag & 0x00000010)
        properties["Security_Analysis_Require_Private_Key_Archival"] = bool(private_key_flag & 0x00000001)
        properties["Security_Analysis_Strong_Key_Protection_Required"] = bool(private_key_flag & 0x00000020)
        
        properties["Security_Analysis_Machine_Type"] = bool(template_flags & 0x00000040)
        properties["Security_Analysis_Is_CA"] = bool(template_flags & 0x00000080)
        properties["Security_Analysis_Add_Template_Name"] = bool(template_flags & 0x00000200)
        
        properties["Debug_Enrollment_Flag_Raw"] = f"Raw: {enrollment_flag}"
        properties["Debug_Certificate_Name_Flag_Raw"] = f"Raw: {certificate_name_flag}"
        properties["Debug_Private_Key_Flag_Raw"] = f"Raw: {private_key_flag}"
        properties["Debug_Template_Flags_Raw"] = f"Raw: {template_flags}"
        
    except Exception as e:
        properties["Analysis_Error"] = f"Analysis failed: {e}"
    
    return properties