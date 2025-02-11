import os
import re
from rich.console import Console
from rich.table import Table

console = Console()

APACHE_CONFIG_PATH = "/etc/apache2/apache2.conf"

RECOMMENDATIONS = {
    "TraceEnable": (r"^\s*TraceEnable\s+(\w+)", lambda val: val.lower() == "off", "Désactiver le traçage HTTP", "TraceEnable Off"),
    "User apache": (r"^\s*User\s+(\w+)", lambda val: val != "root", "Apache doit fonctionner sous un user non-root", "User apache"),
    "Group apache": (r"^\s*Group\s+(\w+)", lambda val: val != "root", "Apache doit fonctionner sous un G non-root", "Group apache"),
    "ServerSignature": (r"^\s*ServerSignature\s+(\w+)", lambda val: val.lower() == "off", "Désactiver la signature du serveur", "ServerSignature Off"),
    "ServerTokens": (r"^\s*ServerTokens\s+(\w+)", lambda val: val.lower() == "prod", "Désactiver la bannière du serveur", "ServerTokens Prod"),
    "SSLProtocol": (r"^\s*SSLProtocol\s+(.+)", lambda val: "+TLSv1.2" in val and "-ALL" in val, "Utilisez uniquement TLS 1.2 pour la sécurité", "SSLProtocol -ALL +TLSv1.2"),
    "Options": (r"^\s*Options\s+(.+)", lambda val: "-Indexes" in val, "Désactiver la liste des répertoires", "Options -Indexes"),
    "SSLCipherSuite": (r"^\s*SSLCipherSuite\s+(.+)", lambda val: "ALL:!aNULL:!ADH:!eNULL:!LOW:!EXP:RC4-RSA:HIGH:MEDIUM" in val, "Désactivez les chiffrages faibles", "SSLCipherSuite ALL:!aNULL:!ADH:!eNULL:!LOW:!EXP:RC4-RSA:HIGH:MEDIUM"),
    "RequestReadTimeout": (r"^\s*RequestReadTimeout\s+(.+)", lambda val: "header=10-20" in val, "Limitez le délai d'attente des requêtes HTTP", "RequestReadTimeout header=10-20,MinRate=500 body=20,MinRate=500"),
    "LimitRequestBody": (r"^\s*LimitRequestBody\s+(\d+)", lambda val: int(val) <= 1048576, "Limitez la taille des corps de requêtes HTTP", "LimitRequestBody 1048576"),
    "KeepAlive": (r"^\s*KeepAlive\s+(\w+)", lambda val: val.lower() == "on", "Activez 'KeepAlive' pour des connexions persistantes", "KeepAlive On"),
    "MaxKeepAliveRequests": (r"^\s*MaxKeepAliveRequests\s+(\d+)", lambda val: int(val) == 100, "Limitez le nombre de requêtes persistantes", "MaxKeepAliveRequests 100"),
    "KeepAliveTimeout": (r"^\s*KeepAliveTimeout\s+(\d+)", lambda val: int(val) == 5, "Limitez le délai KeepAlive", "KeepAliveTimeout 5")
}

def check_apache_config():
    if not os.path.exists(APACHE_CONFIG_PATH):
        console.print(f"[bold red]Le fichier {APACHE_CONFIG_PATH} n'existe pas.[/bold red]")
        return

    with open(APACHE_CONFIG_PATH, 'r') as file:
        apache_config = file.readlines()

    table = Table(title="État de la Configuration Apache", show_header=True, header_style="bold magenta")
    table.add_column("Nom de la règle", style="dim", width=20)
    table.add_column("Status")
    table.add_column("Message", width=45)
    table.add_column("Ligne à ajouter / modifier")

    secure_count = 0

    for directive, (pattern, condition, message, action) in RECOMMENDATIONS.items():
        found = False
        for line in apache_config:
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

    console.print(f"\n[bold blue]Note finale : {len(RECOMMENDATIONS) - secure_count}/{len(RECOMMENDATIONS)}[/bold blue]")

if __name__ == "__main__":
    check_apache_config()
