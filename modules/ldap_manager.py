from ldap3 import Server, Connection, SAFE_SYNC, Tls
import ldap3.core.exceptions as Ldap3E
import ssl
import sys
from time import sleep

def ldap_conn_establish(config):
    while True:
        try:
            if config.LDAP_ENABLE_TLS:
                tls_configuration = Tls(
                    ca_certs_file = config.LDAP_CA_PATH,
                    validate=ssl.CERT_OPTIONAL,
                    version=ssl.PROTOCOL_TLSv1_2
                )

                server = Server(config.LDAP_SERVER,
                                use_ssl=False,
                                tls=tls_configuration)

                conn = Connection(server,
                                       config.LDAP_BINDER,
                                       config.LDAP_BINDER_CREDENTIAL,
                                       client_strategy=SAFE_SYNC,
                                       auto_bind=False)
                conn.start_tls()
                conn.bind()
            else:
                server = Server(config.LDAP_SERVER)
                conn = Connection(server,
                                       config.LDAP_BINDER,
                                       config.LDAP_BINDER_CREDENTIAL,
                                       client_strategy=SAFE_SYNC,
                                       auto_bind=True)
            if conn.extend.standard.who_am_i() != f"dn:{config.LDAP_BINDER}":
                print(f"Unable to authenticate {config.LDAP_BINDER}")
                exit(0)
            return conn
        except Ldap3E.LDAPSSLConfigurationError as e:
            print(f"Unable to initialize TLS configuration: {e}")
            print("Exiting.")
            sys.exit(0)
        except Ldap3E.LDAPBindError as e:
            print(f"Unable to bind: {e}")
            print("Exiting.")
            sys.exit(0)
        except Ldap3E.LDAPStartTLSError as e:
            print(f"Unable to verify the server: {e}")
            print("Exiting")
            sys.exit(0)
        except Ldap3E.LDAPSocketOpenError as e:
            print(f"Unable to connect to server: {e}")
            print("Waiting for trying.")
            sleep(3)
        except Ldap3E.LDAPSessionTerminatedByServerError as e:
            print(f"Session Terminated by server: {e}")
            print("Waiting for trying.")
            sleep(3)
