import subprocess

def get_container_ids():
    try:
        result = subprocess.run("docker ps -aq", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return result.stdout.decode().strip().split('\n')
        else:
            return []
    except Exception as e:
        print(f"An error occurred while getting container IDs: {e}")
        return []

def does_root_have_containers():
    try:
        result = subprocess.run("docker inspect $(docker ps -q) --format '{{.Config.User}} {{.Name}}'", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            output = result.stdout.decode().strip().split('\n')
            return [line.split() for line in output]
        else:
            return []
    except Exception as e:
        print(f"An error occurred while running docker inspect: {e}")
        return []

def is_rootless():
    result = subprocess.run('docker info -f "{{println .SecurityOptions}}" | grep rootless', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return True if result.stdout else False

def is_tcp_socket():
    result = subprocess.check_output(["netstat", "-tunlp"], stderr=subprocess.STDOUT, text=True)
    return True if ":2375" in result else False

def does_containers_mount_socket():
    containers = get_container_ids()
    for container in containers:
        print(container)
        result = subprocess.check_output(["docker", "inspect", "-format='{{.HostConfig.Binds}}'", container], stderr=subprocess.STDOUT, text=True)
        if "/var/run/docker.sock" in result:
            return True
    return False
