from modules import ldap_conn_establish
import config
from ldap3.utils.dn import safe_dn

conn = ldap_conn_establish(config)
search_dn = safe_dn(("ou=People", config.LDAP_BASE_DN))

group_id_to_name = {}

status, result, response, _ = conn.search(config.LDAP_BASE_DN, '(objectClass=PosixGroup)', attributes=['*'])
for entry in response:
    attributes = entry['attributes']
    group_id_to_name[attributes['gidNumber']] = (attributes['cn'][0], entry['dn'])

status, result, response, _ = conn.search(search_dn, '(objectClass=PosixAccount)', attributes=['*'])
for entry in response:
    attributes = entry['attributes']
    print(entry['dn'], attributes['uid'][0], group_id_to_name[attributes['gidNumber']], sep='\t')
