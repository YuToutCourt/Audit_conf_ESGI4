import re, os
from rich.console import Console
from rich.text import Text
from rich.table import Table

console = Console()

SSH_CONFIG_PATH = "/etc/ssh/sshd_config"

RECOMMENDATIONS = {
    "PermitRootLogin": (r"^PermitRootLogin\s+(\w+)", lambda val: val.lower() == "no", "Désactiver le login root", "PermitRootLogin no"),
    "Protocol": (r"^Protocol\s+(\d+)", lambda proto: proto == "2", "Utiliser uniquement la version 2 du protocole SSH", "Protocol 2"),
    "PasswordAuthentication": (r"^PasswordAuthentication\s+(\w+)", lambda val: val.lower() == "no", "Désactiver l'authentification par mot de passe", "PasswordAuthentication no"),
    "PubkeyAuthentication": (r"^PubkeyAuthentication\s+(\w+)", lambda val: val.lower() == "yes", "Activer l'authentification par clé publique", "PubkeyAuthentication yes"),
    "AllowUsers": (r"^AllowUsers\s+(.+)", lambda val: val.strip() != "", "Limiter les users autorisés", "AllowUsers user1 user2"),
    "MaxAuthTries": (r"^MaxAuthTries\s+(\d+)", lambda val: int(val) <= 3, "Limiter les tentatives d'authentification", "MaxAuthTries 3"),
    "PermitEmptyPasswords": (r"^PermitEmptyPasswords\s+(\w+)", lambda val: val.lower() == "no", "Refuser les connexions pour les comptes sans pwd", "PermitEmptyPasswords no"),
    "AllowTcpForwarding": (r"^AllowTcpForwarding\s+(\w+)", lambda val: val.lower() == "no", "Désactiver le transfert TCP", "AllowTcpForwarding no"),
    "X11Forwarding": (r"^X11Forwarding\s+(\w+)", lambda val: val.lower() == "no", "Désactiver le transfert X11", "X11Forwarding no"),
    "LoginGraceTime": (r"^LoginGraceTime\s+(\d+[smhd]?)", lambda val: int(val[:-1]) <= 60 if val[-1].isdigit() else True, "Limiter le temps d'attente de connexion", "LoginGraceTime 60s"),
    "MaxSessions": (r"^MaxSessions\s+(\d+)", lambda val: int(val) <= 10, "Limiter le nombre de sessions simultanées", "MaxSessions 10"),
    "MaxStartups": (r"^MaxStartups\s+(.+)", lambda val: val == "10:30:60", "Limiter les connexions simultanées", "MaxStartups 10:30:60"),
    "Ciphers": (r"^Ciphers\s+(.+)", lambda val: "aes256-ctr,aes192-ctr,aes128-ctr" in val, "Utiliser des ciphers modernes et sécurisés pour SSH", "Ciphers aes256-ctr,aes192-ctr,aes128-ctr"),
    "HostKeyAlgorithms": (r"^HostKeyAlgorithms\s+(.+)", lambda val: "ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp256" in val, "Utiliser des algorithmes de clés modernes pour SSH", "HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp256"),

}

def check_ssh_config():
    if not os.path.exists(SSH_CONFIG_PATH):
        console.print(f"[bold red]Le fichier {SSH_CONFIG_PATH} n'existe pas.[/bold red]")
        return

    with open(SSH_CONFIG_PATH, 'r') as file:
        ssh_config = file.readlines()

    table = Table(title="État de la Configuration SSH", show_header=True, header_style="bold magenta")
    table.add_column("Nom de la règle", style="dim", width=22)
    table.add_column("Status")
    table.add_column("Message", width=55)
    table.add_column("Ligne à ajouter / modifier")

    secure_count = 0

    for directive, (pattern, condition, message, action) in RECOMMENDATIONS.items():
        found = False
        for line in ssh_config:
            match = re.match(pattern, line)
            if match:
                value = match.group(1)
                if condition(value):
                    table.add_row(directive, "[bold green]Correcte[/bold green]", "", "")
                else:
                    table.add_row(directive, "[bold yellow]Mal configurée[/bold yellow]", message, action)
                    secure_count += 0.5
                found = True
                break
        if not found:
            table.add_row(directive, "[bold red]Manquante[/bold red]", message, action)
            secure_count += 1

    console.print(table)

    # Afficher la note finale
    console.print(f"\n[bold blue]Note finale : {len(RECOMMENDATIONS) - secure_count}/{len(RECOMMENDATIONS)}[/bold blue]")

if __name__ == "__main__":
    check_ssh_config()
