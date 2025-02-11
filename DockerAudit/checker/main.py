from version_checker import *
from docker_checker import *
from package_checker import *
from prettytable import PrettyTable
from rich.console import Console
from rich.syntax import Syntax


    

if __name__ == '__main__':
    console = Console()

# Commande à afficher
    command = "sudo apt update && apt upgrade docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
    syntax = Syntax(command, "bash", theme="monokai", line_numbers=True)

# Vérification de la version Docker
    if get_latest_docker_version() != get_local_docker_version():
        # Affichage du message suivi de la commande en syntaxe colorée
        print("Docker n'est pas à jour, il est recommandé de le mettre à jour via :")
        console.print(syntax)
    
    results = {
        "Docker engine à jour? ":  "✓" if get_latest_docker_version() == get_local_docker_version() else "X",
        "Conteneurs exécutés sans augmentation de privilège ?":  "✓" if not does_root_have_containers() else "X",
        "Docker en mode rootless ?": "✓" if is_rootless() else "X",
        "Socket seulement en local ?": "✓" if not is_tcp_socket() else "X",
        "Auditd installé ?": "✓" if check_auditd_installed() else "X",
        "Socket monté dans un container ?": "✓" if does_containers_mount_socket() else "X",
    }

    # Display results in a clean table format

    table = PrettyTable()
    table.field_names = ["Check", "Result"]
    for key, value in results.items():
        table.add_row([key, value])

    print(table)

    
