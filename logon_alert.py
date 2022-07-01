#!/usr/bin/env python3
from os import getenv, putenv, system
from requests import post
from sys import argv
from certifi import where
from subprocess import getoutput
from os.path import isfile

# add allowed clients here.
allowed_clients = [
        ]
splitter = "-" * 100
ah_shit = ''
de = ''
# add discord webhook here.
web_hook = ""
if getenv('SSH_CLIENT') is None:
    sh_client = 'Local, appears to be a local login, this can mean ' \
                'many things. but may need to encrypt special files.'
else:
    sh_client = getenv('SSH_CLIENT').split(" ")
    if str(sh_client[0]) in allowed_clients:
        ah_shit = ' An allowed host has connected, not blocking.'
    else:
        ah_shit = ' A non allowed client has connected, this is a serious issue. The server has been compromised ' \
                     'immediately rotate crypto and all passwords. ensure host system isnt infected, adding a drop ' \
                     'rule.'
        system(f'iptables -I INPUT -p tcp -s {sh_client[0]} -j DROP')
if getenv('LOGNAME') is None:
    login_name = "Appears that this is a userless login, might be a backdoor."
else:
    login_name = getenv("LOGNAME")
if getenv('USER') is None:
    user_name = "Appears that this is a userless login, might be a backdoor."
else:
    user_name = getenv('USER')
hostname = str(getoutput('hostname'))
if isinstance(sh_client, list):
    body = f"Logon check triggered on {hostname}!\n{splitter}\n" \
           f"Useraname used: {user_name}\n" \
           f"IP: {sh_client[0]}\nRemote port: {sh_client[1]}\nLocal Port: {sh_client[2]}\n" \
           f"Shodan URL: https://shodan.io/host/{sh_client[0]}\n" \
           f"Leakix URL: https://leakix.net/host/{sh_client[0]}\n" \
           f"In CloudGaze? (api being built)\n{splitter}\n"
else:
    body = f"Logon check triggered on {hostname}!\n{splitter}\n" \
           f"Useraname used: {user_name}\n" \
           f"Logged on locally: {sh_client}\n" \
           f"{ah_shit}\n" \
           f"\n{splitter}\n"

if argv[1] == '1':
    check = post(web_hook, json={"content": body, "Username": "logon_alerter"}, verify=where(), timeout=8,
                 allow_redirects=False,
                 headers={'Content-Type': "application/json"})
    if check.status_code:
        exit(0)
else:
    body = f"Logon check triggered on {hostname}!\n{splitter}\n" \
           f"Useraname: {user_name} has ended their session.\n" \
           f"\n{splitter}\n"
    check = post(
        web_hook, json={"content": body, "Username": "logon_alerter"}, verify=where(), timeout=8,
        allow_redirects=False,
        headers={'Content-Type': "application/json"}
        )
