from doom.parsers.filetime import parse_filetime
from doom.parsers.certipy.constants import TemplateFlags, EnrollmentFlag, CertificateNameFlag, PrivateKeyFlag, OID_TO_STR_MAP

def parse_attribute(attr_name, attr_value):
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
            remaining_value = attr_value
            
            for flag in PrivateKeyFlag:
                if attr_value & flag.value:
                    private_key_flags.append(flag.name)
                    remaining_value &= ~flag.value
            
            result_parts = []
            if private_key_flags:
                result_parts.append(', '.join(private_key_flags))
            
            if remaining_value > 0:
                result_parts.append(f"UNKNOWN_FLAGS(0x{remaining_value:x})")
            
            return f"{attr_value} ({', '.join(result_parts) if result_parts else 'None'})"
        
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
            except Exception:
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