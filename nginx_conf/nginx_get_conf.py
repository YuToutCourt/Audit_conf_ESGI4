#extract all the configuration files of nginx
import os
import re
import sys
import subprocess
import argparse

def get_nginx_conf():
    #get the path of the nginx.conf file
    p = subprocess.Popen(['nginx', '-V'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    if p.returncode != 0:
        print('Error: nginx not found')
        sys.exit(1)
    m = re.search(r'--conf-path=(\S+)', out)
    if m:
        conf_path = m.group(1)
    else:
        conf_path = '/etc/nginx/nginx.conf'
    return conf_path

def get_included_files(conf_path):
    #get the path of the included files
    included_files = []
    with open(conf_path) as f:
        for line in f:
            m = re.search(r'include\s+(\S+)', line)
            if m:
                included_files.append(m.group(1))
    return included_files

def get_all_files(conf_path):
    #get all the configuration files
    all_files = []
    all_files.append(conf_path)
    included_files = get_included_files(conf_path)
    for file in included_files:
        if not file.startswith('/'):
            file = os.path.join(os.path.dirname(conf_path), file)
        all_files.extend(get_all_files(file))
    return all_files

def save_files(all_files):
    #save all the configuration files
    folder = 'nginx_conf'
    if not os.path.exists(folder):
        os.makedirs(folder)
    for file in all_files:
        with open(file) as f:
            content = f.read()
        with open(os.path.join(folder, os.path.basename(file)), 'w') as f:
            f.write(content)
            
def main():
    conf_path = get_nginx_conf()
    all_files = get_all_files(conf_path)
    save_files(all_files)
    print('Configuration files saved in nginx_conf folder')