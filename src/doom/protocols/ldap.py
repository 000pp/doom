# Source: https://raw.githubusercontent.com/000pp/hexodus/refs/heads/main/src/protocols/ldap.py

import ldap3
import ssl
from ldap3.core.exceptions import LDAPBindError, LDAPInvalidCredentialsResult, LDAPCursorAttributeError

def get_ldap_connection(host: str, username: str, password: str, domain: str):
    """ LDAP Connection Handler: tries signing on 389, then LDAPS on 636. """

    user = f"{domain}\\{username}"

    if len(password) == 32 and all(c in "0123456789abcdefABCDEF" for c in password):
        password = f"aad3b435b51404eeaad3b435b51404ee:{password}"

    tls = ldap3.Tls(validate=ssl.CERT_NONE,
          version=ssl.PROTOCOL_TLSv1_2,
          ciphers="ALL:@SECLEVEL=0")
    
    ldaps_server = ldap3.Server(f"ldaps://{host}", port=636,
                    use_ssl=True, get_info=ldap3.ALL, tls=tls)

    ldap_server = ldap3.Server(f"ldap://{host}", port=389,
                    use_ssl=False, get_info=ldap3.ALL)

    try:
        ldap_connection = ldap3.Connection(
            server=ldap_server,
            user=user,
            password=password,
            authentication=ldap3.NTLM,
            auto_bind=True,
            session_security="ENCRYPT",
            auto_referrals=False,
            raise_exceptions=True
        )

        base_dn = ldap_connection.server.info.naming_contexts[0]
        return ldap_connection, base_dn

    except LDAPBindError as e:
        if "strongerAuthRequired" not in str(e):
            raise Exception(f"LDAP bind error: {e}")

    except LDAPInvalidCredentialsResult:
        raise Exception("Invalid credentials provided")

    try:
        ldaps_connection = ldap3.Connection(
            server=ldaps_server,
            user=user,
            password=password,
            authentication=ldap3.NTLM,
            auto_bind=True,
            auto_referrals=False,
            raise_exceptions=True
        )

        base_dn = ldaps_connection.server.info.other.get("defaultNamingContext", ["<none>"])[0]
        return ldaps_connection, base_dn
    
    except LDAPInvalidCredentialsResult:
        raise Exception("Invalid credentials provided")

    except LDAPBindError as e:
        raise Exception(f"LDAPS bind failed: {e}")


def safe_ldap_attr(entry, attr_name, fallback=None) -> None:
    """ Safely get a LDAP attribute value or return a valid fallback to avoid exceptions """
    try:
        attr = getattr(entry, attr_name, None)
        return attr.value if attr else fallback
    except (AttributeError, LDAPCursorAttributeError):
        return fallback