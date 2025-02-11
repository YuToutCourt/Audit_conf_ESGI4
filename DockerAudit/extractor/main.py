import subprocess
import shutil
import os
    
def extract_configuration(source_path, destination_path):
    try:
        if os.path.exists(source_path):
            print(f"fichier {source_path} trouvé !")
            shutil.copyfile(source_path, destination_path)
    except Exception as e:
        print(f"An error occurred: {e}")

def iptables_exist(destination_path):
    try:
        result = subprocess.run('iptables -L', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            with open(os.path.join(destination_path, "iptables_rules.txt"), "wb") as f:
                f.write(result.stdout)
            return True
        else:
            return False
    except Exception as e:
        print(f"An error occurred while checking iptables: {e}")
        return False

def find_files(root="/"):
    paths = []
    file_list = ["daemon.json", "config.toml"]
    for dirpath, dirnames, filenames in os.walk(root):
        for file in file_list:
            if file in filenames:
                paths.append(os.path.join(dirpath, file))
    return paths


if __name__ == '__main__':
    file_dst = "/tmp/audit"
    files_conf = find_files()
    os.mkdir(file_dst) if not os.path.exists(file_dst) else print(f"dossier {file_dst} déja créer")
    for current_file in files_conf:
        extract_configuration(current_file, f"{file_dst}/{current_file.split('/')[-2]}_{current_file.split('/')[-1]}")
    iptables_exist("/tmp/audit/iptables.conf")
    print("copie terminée !")
    
